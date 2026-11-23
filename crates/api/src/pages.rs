//! Page payloads: one request assembles what a screen paints.
//!
//! These are not new domain reads. They compose the store's snapshot seam
//! ([`nodus_server_store::Store::batch`]) with the visibility predicates the neighbouring
//! endpoints already apply, so a profile or a thread cannot leak a post that the public
//! timeline or the account outbox would hide.

use std::collections::{BTreeMap, HashMap};

use axum::extract::{Path, Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use nodus_server_core::PageParams;
use nodus_server_store::hydrate::{BatchOutcome, ProfilePictures, RowMap};
use nodus_server_store::social::ViewerFlags;
use nodus_server_store::statuses::{ProfileFilters, ReactionCount, StatusRow};

use crate::accounts::RelationshipDto;
use crate::auth::MaybeAuth;
use crate::dto::{AccountDto, StatusDto};
use crate::error::{ApiError, ApiResult};
use crate::mastodon::PageQuery;
use crate::state::{AppState, InstanceConfig};

/// The thread's reply chain is bounded: twelve parents is more than a reader scrolls and
/// enough to show the shape of the conversation.
const ANCESTOR_LIMIT: i64 = 12;

/// A cursor pair. `next` moves to older posts; `prev` is present only when the request
/// itself was paging older, because the first page has nothing newer behind it.
#[derive(Debug, Serialize)]
pub struct PageCursors {
    pub next: Option<String>,
    pub prev: Option<String>,
}

/// `GET /api/v1/pages/profile/{acct}`
///
/// `{acct}` is either an account id or a handle. The handle form is `name@host` with a
/// literal `@` — the form the web client's URL builder sends, since it pushes path
/// segments and `@` is not in a path segment's percent-encode set; `%40` is accepted
/// too. A handle whose host is this instance's domain resolves to the local account, so
/// the SSR route can forward an `@name@host` the reader typed. Ids are ULIDs and never
/// contain `@`, which is what tells the two forms apart.
#[derive(Debug, Serialize)]
pub struct ProfilePageDto {
    pub account: AccountDto,
    pub statuses: Vec<StatusDto>,
    pub relationship: Option<RelationshipDto>,
    pub page: PageCursors,
}

/// `GET /api/v1/pages/status/{id}`
#[derive(Debug, Serialize)]
pub struct StatusPageDto {
    pub status: StatusDto,
    pub ancestors: Vec<StatusDto>,
    pub descendants: Vec<StatusDto>,
    pub context: ContextCursors,
}

/// The reply list is complete, so there is no next reply cursor yet. The key is present
/// because clients switch on the page shape, not on whether a thread happened to fill.
#[derive(Debug, Serialize)]
pub struct ContextCursors {
    pub next: Option<String>,
}

/// The account-status knobs, plus the flags the profile page honours.
#[derive(Debug, Deserialize)]
pub struct ProfileQuery {
    pub max_id: Option<String>,
    pub since_id: Option<String>,
    pub min_id: Option<String>,
    pub limit: Option<u32>,
    #[serde(default)]
    pub exclude_replies: bool,
    #[serde(default)]
    pub exclude_reblogs: bool,
    #[serde(default)]
    pub only_media: bool,
    /// Accepted so a client can ask, but refused: nodus stores no pinned statuses, and
    /// silently returning the ordinary page would answer a different question.
    #[serde(default)]
    pub pinned: bool,
}

impl ProfileQuery {
    fn params(&self) -> ApiResult<PageParams> {
        PageQuery {
            max_id: self.max_id.clone(),
            since_id: self.since_id.clone(),
            min_id: self.min_id.clone(),
            limit: self.limit,
            local: None,
        }
        .params()
    }
}

/// Whether a path segment names an account by id or by handle.
///
/// An id is a ULID, so `@` is the discriminator; there is no guessing a bare name
/// against an id. A leading `@` is accepted because that is how a handle is typed, and
/// a host equal to the instance's own domain means the local account.
enum ProfileTarget<'a> {
    Id(&'a str),
    Handle {
        username: &'a str,
        domain: Option<&'a str>,
    },
}

fn profile_target<'a>(segment: &'a str, local_domain: &str) -> ProfileTarget<'a> {
    let bare = segment.strip_prefix('@').unwrap_or(segment);
    let Some((username, host)) = bare.split_once('@') else {
        return ProfileTarget::Id(segment);
    };
    let domain = if host.eq_ignore_ascii_case(local_domain) {
        None
    } else {
        Some(host)
    };
    ProfileTarget::Handle { username, domain }
}

pub async fn profile(
    State(state): State<AppState>,
    MaybeAuth(auth): MaybeAuth,
    Path(segment): Path<String>,
    Query(query): Query<ProfileQuery>,
) -> ApiResult<Json<ProfilePageDto>> {
    if query.pinned {
        return Err(ApiError::unprocessable(
            "pinned statuses are not stored on this instance",
        ));
    }
    let params = query.params()?;
    let viewer = auth.as_ref().map(|auth| auth.0.account.id.as_str());
    let filters = ProfileFilters {
        exclude_replies: query.exclude_replies,
        exclude_reblogs: query.exclude_reblogs,
        only_media: query.only_media,
    };
    let (account, page) = match profile_target(&segment, &state.instance().domain) {
        ProfileTarget::Id(id) => {
            let account = state
                .store()
                .account(id)
                .await?
                .ok_or_else(|| ApiError::not_found("Record not found"))?;
            if account.deleted_at.is_some() {
                return Err(ApiError::not_found("Record not found"));
            }
            let page = nodus_server_store::statuses::profile_page(
                state.store().pool(),
                id,
                params,
                filters,
                viewer,
            )
            .await?;
            (account, page)
        }
        ProfileTarget::Handle { username, domain } => {
            let (account, page) = nodus_server_store::statuses::profile_page_by_handle(
                state.store().pool(),
                username,
                domain,
                params,
                filters,
                viewer,
            )
            .await?
            .ok_or_else(|| {
                ApiError::not_found(format!(
                    "the handle @{} is not known here",
                    segment.trim_start_matches('@')
                ))
            })?;
            (account, page)
        }
    };
    let id = account.id.clone();

    let next = page.next_max_id.clone();
    let prev = if query.max_id.is_some() {
        page.items.first().map(|row| row.id.clone())
    } else {
        None
    };
    let targets: Vec<String> = viewer.map(|_| id.clone()).into_iter().collect();
    let (statuses, relationships, pictures) =
        hydrate_statuses(&state, page.items, viewer, &targets, Some(&id)).await?;
    let relationship = viewer.and_then(|_| {
        relationships
            .get(&id)
            .map(|relationship| RelationshipDto::new(&id, relationship))
    });
    Ok(Json(ProfilePageDto {
        account: AccountDto::from_row(&account, state.instance()).with_pictures(pictures.get(&id)),
        statuses,
        relationship,
        page: PageCursors { next, prev },
    }))
}

pub async fn status(
    State(state): State<AppState>,
    MaybeAuth(auth): MaybeAuth,
    Path(id): Path<String>,
) -> ApiResult<Json<StatusPageDto>> {
    let focused = crate::statuses::visible_status(&state, auth.as_ref(), &id).await?;
    let viewer = auth.as_ref().map(|auth| auth.0.account.id.as_str());
    let ancestors =
        nodus_server_store::statuses::ancestor_chain(state.store().pool(), &id, ANCESTOR_LIMIT)
            .await?;
    let descendants = nodus_server_store::statuses::descendants(state.store().pool(), &id).await?;

    let ancestor_ids: Vec<String> = ancestors.iter().map(|row| row.id.clone()).collect();
    let descendant_ids: Vec<String> = descendants.iter().map(|row| row.id.clone()).collect();
    let mut rows = Vec::with_capacity(1 + ancestors.len() + descendants.len());
    rows.push(focused.clone());
    rows.extend(ancestors);
    rows.extend(descendants);
    let (statuses, _, _) = hydrate_statuses(&state, rows, viewer, &[], None).await?;
    let mut by_id: HashMap<String, StatusDto> = statuses
        .into_iter()
        .map(|dto| (dto.id.clone(), dto))
        .collect();
    let status = by_id
        .remove(&focused.id)
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    let ancestors = ancestor_ids
        .into_iter()
        .filter_map(|id| by_id.remove(&id))
        .collect();
    let descendants = descendant_ids
        .into_iter()
        .filter_map(|id| by_id.remove(&id))
        .collect();
    Ok(Json(StatusPageDto {
        status,
        ancestors,
        descendants,
        context: ContextCursors { next: None },
    }))
}

/// Builds the DTOs for a page in one pass: one moderation read, then one snapshot for
/// authors, attachments, decoration, polls and reactions, then one viewer-flag read.
///
/// `rows` is filtered here rather than by the caller so the two page handlers cannot
/// disagree about which row is safe to paint. The order of the input is preserved.
pub(crate) async fn hydrate_statuses(
    state: &AppState,
    rows: Vec<StatusRow>,
    viewer: Option<&str>,
    relationship_targets: &[String],
    profile_account: Option<&str>,
) -> ApiResult<(
    Vec<StatusDto>,
    RowMap<nodus_server_store::social::Relationship>,
    RowMap<ProfilePictures>,
)> {
    let mut all_ids: Vec<String> = rows.iter().map(|row| row.id.clone()).collect();
    let mut reblog_ids: Vec<String> = rows
        .iter()
        .filter_map(|row| row.reblog_of_id.clone())
        .collect();
    reblog_ids.sort_unstable();
    reblog_ids.dedup();
    all_ids.extend(reblog_ids.iter().cloned());
    all_ids.sort_unstable();
    all_ids.dedup();

    let hidden =
        nodus_server_store::statuses::hidden_status_ids(state.store().pool(), &all_ids, viewer)
            .await?;
    let rows: Vec<StatusRow> = rows
        .into_iter()
        .filter(|row| !hidden.contains(&row.id))
        .collect();

    // A reblog row paints its original, so the original needs the same moderation and
    // audience gate as a top-level row. It is fetched in one statement, not per boost.
    let mut originals =
        nodus_server_store::statuses::by_ids(state.store().pool(), &reblog_ids).await?;
    originals.retain(|row| !hidden.contains(&row.id));
    let visible_originals = visible_rows(state, originals, viewer).await?;
    let visible_rows = visible_rows(state, rows, viewer).await?;

    let mut status_ids: Vec<String> = visible_rows.iter().map(|row| row.id.clone()).collect();
    status_ids.extend(visible_originals.iter().map(|row| row.id.clone()));
    status_ids.sort_unstable();
    status_ids.dedup();
    let mut author_ids: Vec<String> = visible_rows
        .iter()
        .chain(visible_originals.iter())
        .map(|row| row.account_id.clone())
        .collect();
    author_ids.sort_unstable();
    author_ids.dedup();
    // The profile's own account may have no status on this page, but its pictures come
    // from the page's batch all the same: a profile with an empty outbox still has a face.
    let mut picture_ids = author_ids.clone();
    picture_ids.extend(profile_account.map(str::to_owned));
    picture_ids.sort_unstable();
    picture_ids.dedup();

    let outcome = if relationship_targets.is_empty() {
        state
            .store()
            .batch()
            .accounts(&author_ids)
            .profile_pictures(&picture_ids)
            .media_by_status(&status_ids)
            .decorations(&status_ids)
            .polls(&status_ids, viewer)
            .reactions(&status_ids)
            .run()
            .await?
    } else {
        state
            .store()
            .batch()
            .accounts(&author_ids)
            .profile_pictures(&picture_ids)
            .media_by_status(&status_ids)
            .decorations(&status_ids)
            .polls(&status_ids, viewer)
            .reactions(&status_ids)
            .relationships(viewer.unwrap_or_default(), relationship_targets)
            .run()
            .await?
    };
    let reactions: RowMap<Vec<ReactionCount>> = match &outcome.reactions {
        Ok(reactions) => reactions.clone(),
        Err(_) => RowMap::new(),
    };
    let flags = match viewer {
        Some(viewer) => {
            nodus_server_store::social::viewer_flags(state.store().pool(), viewer, &status_ids)
                .await?
        }
        None => HashMap::new(),
    };
    let now = Utc::now();

    let mut built_originals = BTreeMap::new();
    for row in &visible_originals {
        if let Some(dto) = build_dto(row, &outcome, &flags, &reactions, now, state.instance()) {
            built_originals.insert(row.id.clone(), dto);
        }
    }
    let mut statuses = Vec::with_capacity(visible_rows.len());
    for row in &visible_rows {
        let Some(mut dto) = build_dto(row, &outcome, &flags, &reactions, now, state.instance())
        else {
            continue;
        };
        if let Some(original_id) = &row.reblog_of_id {
            dto.reblog = built_originals.remove(original_id).map(Box::new);
        }
        statuses.push(dto);
    }
    Ok((statuses, outcome.relationships, outcome.profile_pictures))
}

/// Keeps the rows a reader may see, in the order they arrived.
async fn visible_rows(
    state: &AppState,
    rows: Vec<StatusRow>,
    viewer: Option<&str>,
) -> ApiResult<Vec<StatusRow>> {
    let mut visible = Vec::with_capacity(rows.len());
    for row in rows {
        if row_visible(state, viewer, &row).await? {
            visible.push(row);
        }
    }
    Ok(visible)
}

/// The public rows are safe once moderation has spoken; only private and direct rows
/// need the audience check, and paying its two reads for a public thread would make the
/// page's cost grow with its length.
async fn row_visible(state: &AppState, viewer: Option<&str>, row: &StatusRow) -> ApiResult<bool> {
    if row.visibility == "public" || row.visibility == "unlisted" {
        return Ok(true);
    }
    crate::statuses::can_view_for_viewer(state, viewer, row).await
}

fn build_dto(
    row: &StatusRow,
    outcome: &BatchOutcome,
    flags: &HashMap<String, ViewerFlags>,
    reactions: &RowMap<Vec<ReactionCount>>,
    now: DateTime<Utc>,
    instance: &InstanceConfig,
) -> Option<StatusDto> {
    let account = outcome.accounts.get(&row.account_id)?;
    let attachments = outcome
        .media_by_status
        .get(&row.id)
        .map_or(&[][..], Vec::as_slice);
    let mut dto = StatusDto::from_row_with_media(row, account, instance, attachments);
    dto.apply_account_pictures(&outcome.profile_pictures);
    if let Some(decorations) = outcome.decorations.get(&row.id) {
        crate::statuses::apply_decorations(&mut dto, decorations, instance);
    }
    if let Some(poll) = outcome.polls.get(&row.id) {
        let document = crate::polls::page_document(poll, now);
        dto.poll = serde_json::to_value(document).ok();
    }
    dto.reactions = reactions.get(&row.id).cloned().unwrap_or_default();
    if let Some(flag) = flags.get(&row.id) {
        crate::statuses::apply_flags(&mut dto, *flag);
    }
    Some(dto)
}
