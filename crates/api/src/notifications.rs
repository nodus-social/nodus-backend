//! Mastodon notification endpoints.
//!
//! Notifications are written by the follow, favourite, reblog and mention paths through
//! `social::notify`, and by every account-level moderation decision through
//! `moderation::apply_action_noted` / `moderation::warn_in`; this module only reads and
//! acknowledges them, so a notification can never be produced by a read.
//!
//! `moderation` is the one kind the reader may see while restricted: a silenced or
//! suspended person still has to learn what was decided, so the list resolves its token
//! through [`AppealAuth`] rather than [`Auth`].

use axum::extract::{Path, Query, RawQuery, State};
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;

use nodus_server_core::limits::PAGE_MAX;
use nodus_server_core::pagination::PageSize;
use nodus_server_store::accounts::AccountRow;
use nodus_server_store::hydrate::{PollFacts, ProfilePictures};
use nodus_server_store::media::MediaRow;
use nodus_server_store::social::{NotificationRow, ViewerFlags};
use nodus_server_store::statuses::StatusRow;
use nodus_server_store::{RowMap, StatusDecorations};

use crate::appeals::AppealDto;
use crate::auth::{AppealAuth, Auth};
use crate::dto::{AccountDto, StatusDto};
use crate::error::{ApiError, ApiResult};
use crate::mastodon::PageQuery;
use crate::state::AppState;
use crate::statuses;

use nodus_server_store::appeals;

/// Every kind this server can produce. Mastodon also has `update` (an edited status) and
/// `admin.sign_up`; both are accepted as filters and simply match nothing. `appeal` is
/// this instance's own: a decided appeal has no status to point at, only a sentence.
/// `moderation` is the same shape for a decision *about* the reader, which is why it is
/// the only kind that also carries structured fields beside the sentence.
const KINDS: [&str; 8] = [
    "follow",
    "favourite",
    "reblog",
    "mention",
    "status",
    "poll",
    "appeal",
    "moderation",
];

/// One notification, in Mastodon's shape.
#[derive(Debug, Serialize)]
pub struct NotificationDto {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub created_at: DateTime<Utc>,
    pub account: AccountDto,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusDto>,
    /// A sentence that carries the event itself, when there is no status to point at.
    /// `appeal` and `moderation` use it: the outcome, the reason, and whatever the
    /// moderator wrote.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Present on `moderation` only: the decision, its reason, the rule if a rule
    /// decided, the expiry if there is one, and whether the reader may answer it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub moderation: Option<ModerationNoticeDto>,
    /// Clients group duplicates by this; we notify once per event, so it is per row.
    pub group_key: String,
    /// How many events this line covers. A poll with twenty voters is one line with the
    /// latest voter in `account` and 20 here; every other kind reports 1.
    pub group_count: i32,
}

/// The structured half of a `moderation` notification.
///
/// `note` says it in one sentence for a client that knows nothing about moderation;
/// these fields let a client say "you were silenced for X until Y, you may appeal"
/// without parsing prose.
#[derive(Debug, Serialize)]
pub struct ModerationNoticeDto {
    /// `warn`, `silence`, `suspend`, `reject`, `approve`, `unsilence`, `unsuspend` —
    /// spelled as the audit log spells it, so the two records can be read side by side.
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// True when the decision is a restriction still in force and nothing is waiting on a
    /// moderator already: the reader has something to answer and no answer pending.
    pub can_appeal: bool,
    /// The appeal already waiting, so a person who filed one sees it is not lost.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appeal: Option<AppealDto>,
}
///
/// `serde_urlencoded` cannot express an array, so these are read from the raw query
/// string rather than through a `Query<T>` extractor.
#[derive(Debug, Default)]
struct NotificationFilter {
    types: Vec<String>,
    exclude_types: Vec<String>,
    /// `?filtered=true` asks for the rows a `filter` policy kept out of the ordinary list.
    filtered: bool,
}

impl NotificationFilter {
    fn parse(raw: Option<&str>) -> Self {
        let mut filter = Self::default();
        for (key, value) in url::form_urlencoded::parse(raw.unwrap_or_default().as_bytes()) {
            match key.as_ref() {
                "types[]" | "types" => filter.types.extend(split_list(&value)),
                "exclude_types[]" | "exclude_types" => {
                    filter.exclude_types.extend(split_list(&value));
                }
                "filtered" => filter.filtered = matches!(value.as_ref(), "true" | "1"),
                _ => {}
            }
        }
        filter
    }

    /// The kinds to ask the store for.
    ///
    /// An unknown `types[]` value is ignored rather than rejected: Mastodon returns only
    /// the kinds it knows, and a client that asks for `admin.sign_up` should get an empty
    /// page, not a `422`.
    fn kinds(&self) -> Vec<String> {
        let wanted: Vec<String> = if self.types.is_empty() {
            KINDS.iter().map(ToString::to_string).collect()
        } else {
            KINDS
                .iter()
                .filter(|kind| self.types.iter().any(|asked| asked == *kind))
                .map(ToString::to_string)
                .collect()
        };
        wanted
            .into_iter()
            .filter(|kind| !self.exclude_types.iter().any(|skip| skip == kind))
            .collect()
    }
}

/// Accepts both `types[]=a&types[]=b` and the comma-separated form some clients send.
fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// `GET /api/v1/notifications`
///
/// Authentication is [`AppealAuth`], not [`Auth`]: a suspended account must be able to
/// read the sentence that suspended it and find the appeal form (migration 39) from it.
pub async fn list(
    State(state): State<AppState>,
    auth: AppealAuth,
    Query(query): Query<PageQuery>,
    RawQuery(raw): RawQuery,
) -> ApiResult<Response> {
    auth.0.require_scope("read:notifications")?;
    let params = query.params()?;
    let size = PageSize::clamp(params.limit, PAGE_MAX);
    let filter = NotificationFilter::parse(raw.as_deref());
    let kinds = filter.kinds();
    if kinds.is_empty() {
        // Every kind was excluded, so the page is empty by construction. Novel kinds are
        // not an error, which is why this is checked here and not in the filter parser.
        return Ok((
            axum::http::StatusCode::OK,
            Json(Vec::<NotificationDto>::new()),
        )
            .into_response());
    }
    let cursor = params.max_id.map(|id| id.to_string());
    let rows = nodus_server_store::social::notifications(
        state.store().pool(),
        &auth.0 .0.account.id,
        cursor.as_deref(),
        i64::from(size.get()),
        &kinds,
        Some(filter.filtered),
    )
    .await?;

    // Two status reads and one batch for the whole page, then shaping with no statement
    // of its own: a page of twenty notifications costs what a page of one costs.
    let parts = page_parts(&state, &auth.0 .0.account.id, &rows).await?;
    let now = Utc::now();
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        let mut item = dto_from_page(&state, row, &parts, now)?;
        if item.kind == "moderation" {
            item.moderation = Some(moderation_dto(&state, row).await?);
        }
        items.push(item);
    }

    let next = rows.last().map(|row| row.id.clone());
    let mut response = Json(items).into_response();
    if let Some(link) = next.and_then(|id| {
        params
            .next_link("/api/v1/notifications", id.parse().ok(), size)
            .and_then(|link| HeaderValue::from_str(&link).ok())
    }) {
        response
            .headers_mut()
            .insert(axum::http::header::LINK, link);
    }
    Ok(response)
}

/// `GET /api/v1/notifications/{id}`
pub async fn show(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<NotificationDto>> {
    auth.require_scope("read:notifications")?;
    let row = notification(&state, &auth, &id).await?;
    Ok(Json(dto(&state, &row, Some(&auth)).await?))
}

/// `POST /api/v1/notifications/{id}` — marks one notification seen.
pub async fn mark_seen(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<NotificationDto>> {
    auth.require_scope("write:notifications")?;
    let row = notification(&state, &auth, &id).await?;
    nodus_server_store::social::mark_seen(state.store().pool(), &auth.0.account.id, &id).await?;
    Ok(Json(dto(&state, &row, Some(&auth)).await?))
}

/// `POST /api/v1/notifications/{id}/dismiss`
pub async fn dismiss(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<NotificationDto>> {
    auth.require_scope("write:notifications")?;
    let row = notification(&state, &auth, &id).await?;
    nodus_server_store::social::dismiss_notification(state.store().pool(), &auth.0.account.id, &id)
        .await?;
    Ok(Json(dto(&state, &row, Some(&auth)).await?))
}

/// `POST /api/v1/notifications/clear`
pub async fn clear(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_scope("write:notifications")?;
    nodus_server_store::social::clear_notifications(state.store().pool(), &auth.0.account.id)
        .await?;
    Ok(Json(serde_json::json!({})))
}

/// One of the reader's own notifications, or a `404` that says nothing about others'.
async fn notification(state: &AppState, auth: &Auth, id: &str) -> ApiResult<NotificationRow> {
    nodus_server_store::social::notification_by_id(state.store().pool(), &auth.0.account.id, id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))
}

/// Everything a page of notifications points at, read once.
struct PageParts {
    statuses: HashMap<String, StatusRow>,
    accounts: RowMap<AccountRow>,
    media: RowMap<Vec<MediaRow>>,
    decorations: RowMap<StatusDecorations>,
    polls: RowMap<PollFacts>,
    pictures: RowMap<ProfilePictures>,
    flags: HashMap<String, ViewerFlags>,
}

/// Reads the senders, the statuses they point at and what those boost in one snapshot.
///
/// A line used to be built on its own: sender, status, author, attachments, decorations
/// and the poll's tallies, twenty times for twenty lines. The page is the unit here, so a
/// longer page costs no more than a short one. A status or author that is gone stays
/// absent rather than being padded.
async fn page_parts(
    state: &AppState,
    viewer: &str,
    rows: &[NotificationRow],
) -> ApiResult<PageParts> {
    let pool = state.store().pool();
    let mut page_ids: Vec<String> = rows
        .iter()
        .filter_map(|row| row.status_id.clone())
        .collect();
    page_ids.sort_unstable();
    page_ids.dedup();
    let mut statuses: HashMap<String, StatusRow> =
        nodus_server_store::statuses::by_ids(pool, &page_ids)
            .await?
            .into_iter()
            .map(|row| (row.id.clone(), row))
            .collect();
    // A boost renders the status it boosted, so the originals belong to the page too.
    let mut originals: Vec<String> = statuses
        .values()
        .filter_map(|row| row.reblog_of_id.clone())
        .collect();
    originals.sort_unstable();
    originals.dedup();
    for row in nodus_server_store::statuses::by_ids(pool, &originals).await? {
        statuses.insert(row.id.clone(), row);
    }
    page_ids.extend(originals);

    let mut account_ids: Vec<String> = rows.iter().map(|row| row.from_account_id.clone()).collect();
    account_ids.extend(statuses.values().map(|row| row.account_id.clone()));
    account_ids.sort_unstable();
    account_ids.dedup();

    let hydrated = state
        .store()
        .batch()
        .accounts(&account_ids)
        .profile_pictures(&account_ids)
        .media_by_status(&page_ids)
        .decorations(&page_ids)
        .polls(&page_ids, Some(viewer))
        .run()
        .await?;
    let flags = nodus_server_store::social::viewer_flags(pool, viewer, &page_ids).await?;
    Ok(PageParts {
        statuses,
        accounts: hydrated.accounts,
        media: hydrated.media_by_status,
        decorations: hydrated.decorations,
        polls: hydrated.polls,
        pictures: hydrated.profile_pictures,
        flags,
    })
}

/// A status payload from the page's reads; `None` when its author is gone.
fn status_from_page(
    state: &AppState,
    row: &StatusRow,
    parts: &PageParts,
    now: DateTime<Utc>,
) -> ApiResult<Option<StatusDto>> {
    let Some(account) = parts.accounts.get(&row.account_id) else {
        return Ok(None);
    };
    let media = parts.media.get(&row.id).map_or(&[][..], Vec::as_slice);
    let mut dto = StatusDto::from_row_with_media(row, account, state.instance(), media);
    dto.apply_account_pictures(&parts.pictures);
    if let Some(decorations) = parts.decorations.get(&row.id) {
        statuses::apply_decorations(&mut dto, decorations, state.instance());
    }
    if let Some(poll) = parts.polls.get(&row.id) {
        dto.poll = Some(
            serde_json::to_value(crate::polls::page_document(poll, now)).map_err(|error| {
                ApiError::new(
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    error.to_string(),
                )
            })?,
        );
    }
    if let Some(flags) = parts.flags.get(&row.id) {
        statuses::apply_flags(&mut dto, *flags);
    }
    if let Some(original_id) = &row.reblog_of_id {
        if let Some(original) = parts.statuses.get(original_id) {
            dto.reblog = status_from_page(state, original, parts, now)?.map(Box::new);
        }
    }
    Ok(Some(dto))
}

/// The payload for one row of a page whose reads are already in hand.
fn dto_from_page(
    state: &AppState,
    row: &NotificationRow,
    parts: &PageParts,
    now: DateTime<Utc>,
) -> ApiResult<NotificationDto> {
    let Some(account) = parts.accounts.get(&row.from_account_id) else {
        return Err(ApiError::not_found("Record not found"));
    };
    let status = match &row.status_id {
        None => None,
        Some(id) => match parts.statuses.get(id) {
            Some(status) => status_from_page(state, status, parts, now)?,
            // A notification whose status was deleted stays readable as the event it
            // records; a client shows "liked your post" without a post body.
            None => None,
        },
    };
    let kind = KINDS
        .iter()
        .find(|kind| **kind == row.kind)
        .copied()
        .unwrap_or("status");
    Ok(NotificationDto {
        id: row.id.clone(),
        kind,
        created_at: row.created_at,
        account: AccountDto::from_row(account, state.instance())
            .with_pictures(parts.pictures.get(&row.from_account_id)),
        status,
        group_key: format!(
            "{}:{}",
            kind,
            row.status_id.as_deref().unwrap_or(&row.from_account_id)
        ),
        group_count: row.group_count,
        note: row.note.clone(),
        moderation: None,
    })
}

/// Builds the payload, reading the sender and the status it refers to.
///
/// Public inside the crate: the streaming handler renders the notification it was just
/// told about through this same function, so an SSE frame and a list row cannot drift.
/// One row is a page of one; the shaping is shared with [`list`], and the moderation
/// fields — two per-row lookups that only a `moderation` line needs — are added here.
pub(crate) async fn dto(
    state: &AppState,
    row: &NotificationRow,
    viewer: Option<&Auth>,
) -> ApiResult<NotificationDto> {
    let viewer_id = viewer.map_or(row.account_id.as_str(), |auth| auth.0.account.id.as_str());
    let parts = page_parts(state, viewer_id, std::slice::from_ref(row)).await?;
    let mut dto = dto_from_page(state, row, &parts, Utc::now())?;
    if dto.kind == "moderation" {
        dto.moderation = Some(moderation_dto(state, row).await?);
    }
    Ok(dto)
}

/// Fills in the structured half of a `moderation` row, including the answer the reader
/// may give.
///
/// `can_appeal` is deliberately conservative: the notice must still be true of the account
/// *now*. A silence that was later lifted keeps its own row (that is what requirement one
/// asks of the trail), but its `can_appeal` becomes false, because there is nothing left to
/// appeal. It is likewise false while an appeal is pending — the moderator, not the person,
/// owes the next word.
async fn moderation_dto(state: &AppState, row: &NotificationRow) -> ApiResult<ModerationNoticeDto> {
    let action = row
        .moderation_action
        .clone()
        .unwrap_or_else(|| "warn".to_owned());
    let restricted_now = matches!(action.as_str(), "silence" | "suspend" | "reject");
    let pending =
        nodus_server_store::appeals::pending(state.store().pool(), &row.account_id).await?;
    let mut can_appeal = false;
    if restricted_now {
        let in_force = appeals::restriction(state.store().pool(), &row.account_id)
            .await?
            .is_some_and(|restriction| restriction.as_str() == action);
        can_appeal = in_force && pending.is_none();
    }
    Ok(ModerationNoticeDto {
        action,
        reason: row
            .moderation_reason
            .clone()
            .filter(|text| !text.is_empty()),
        rule: row.moderation_rule.clone(),
        expires_at: row.moderation_expires_at,
        can_appeal,
        appeal: pending.map(AppealDto::from_row),
    })
}

/// The router fragment, mounted by `crate::router`.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/api/v1/notifications", get(list))
        .route("/api/v1/notifications/clear", post(clear))
        .route("/api/v1/notifications/{id}", get(show).post(mark_seen))
        .route("/api/v1/notifications/{id}/dismiss", post(dismiss))
}
