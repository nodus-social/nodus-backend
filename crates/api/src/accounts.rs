//! Account lookup, follow graph and relationship endpoints.

use axum::extract::{Path, Query, RawQuery, State};
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use nodus_server_core::{PageParams, PageSize};
use nodus_server_store::accounts::AccountRow;
use nodus_server_store::social::{FollowOutcome, Relationship};

use crate::auth::Auth;
use crate::body::JsonOrForm;
use crate::dto::AccountDto;
use crate::error::{ApiError, ApiResult};
use crate::mastodon::PageQuery;
use crate::state::{AppState, InstanceConfig};

/// The fields a client may send to `PATCH /api/v1/accounts/update_credentials`.
///
/// Everything is optional so a form that only changes the display name does not blank the
/// rest of the profile.
#[derive(Debug, Deserialize)]
pub struct UpdateCredentials {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub locked: Option<bool>,
    #[serde(default)]
    pub bot: Option<bool>,
    #[serde(default)]
    pub discoverable: Option<bool>,
    #[serde(default)]
    pub indexable: Option<bool>,
    /// A media id the reader has already uploaded, not a URL.
    #[serde(default)]
    pub avatar: Option<String>,
    #[serde(default)]
    pub header: Option<String>,
}

/// `PATCH /api/v1/accounts/update_credentials`
pub async fn update_credentials(
    State(state): State<AppState>,
    auth: Auth,
    JsonOrForm(request): JsonOrForm<UpdateCredentials>,
) -> ApiResult<Json<AccountDto>> {
    auth.require_scope("write:accounts")?;
    let display_name = request.display_name.as_deref().map(str::trim);
    if let Some(value) = display_name {
        if value.chars().count() > 30 {
            return Err(ApiError::unprocessable(
                "display_name must be at most 30 characters",
            ));
        }
    }
    let note = request.note.as_deref();
    if let Some(value) = note {
        if value.chars().count() > 500 {
            return Err(ApiError::unprocessable(
                "note must be at most 500 characters",
            ));
        }
    }
    let avatar_ref = attachment_ref(&state, &auth, request.avatar.as_deref()).await?;
    let header_ref = attachment_ref(&state, &auth, request.header.as_deref()).await?;
    let update = nodus_server_store::accounts::ProfileUpdate {
        display_name,
        note,
        locked: request.locked,
        bot: request.bot,
        discoverable: request.discoverable,
        indexable: request.indexable,
        avatar_ref: avatar_ref.as_deref(),
        header_ref: header_ref.as_deref(),
    };
    let row = nodus_server_store::accounts::update_profile(
        state.store().pool(),
        &auth.0.account.id,
        &update,
    )
    .await?;
    Ok(Json(AccountDto::from_row(&row, state.instance())))
}

/// Turns an uploaded picture into the reference a profile stores.
///
/// The preview variant is the one sized for a profile, so that is what the avatar points
/// at; the media has to be the reader's own, or one account could point its profile at
/// another's upload.
async fn attachment_ref(
    state: &AppState,
    auth: &Auth,
    media_id: Option<&str>,
) -> ApiResult<Option<String>> {
    let Some(media_id) = media_id.map(str::trim).filter(|id| !id.is_empty()) else {
        return Ok(None);
    };
    let Some(media) = nodus_server_store::media::by_id(state.store().pool(), media_id).await?
    else {
        return Err(ApiError::unprocessable("unknown media attachment"));
    };
    if media.account_id != auth.0.account.id {
        return Err(ApiError::unprocessable("media attachment is not available"));
    }
    if !media.content_type.starts_with("image/") {
        return Err(ApiError::unprocessable(
            "an avatar or header must be an image",
        ));
    }
    Ok(Some(format!("{media_id}/preview")))
}

#[derive(Debug, Serialize)]
pub struct RelationshipDto {
    pub id: String,
    pub following: bool,
    pub showing_reblogs: bool,
    pub notifying: bool,
    pub requested: bool,
    /// Whether the target blocks the reader — spelled `blocking`, not `blocked`, because that
    /// is the key every client reads and a missing one defaults to `false` without complaint.
    pub blocking: bool,
    pub blocked_by: bool,
    pub followed_by: bool,
    pub muting: bool,
    pub muting_notifications: bool,
    pub domain_blocking: bool,
    pub endorsed: bool,
    pub languages: Vec<String>,
}

impl RelationshipDto {
    fn new(id: &str, relationship: &Relationship) -> Self {
        Self {
            id: id.to_owned(),
            following: relationship.following,
            showing_reblogs: relationship.showing_reblogs,
            notifying: relationship.notifying,
            requested: relationship.requested,
            blocking: relationship.blocked,
            blocked_by: relationship.blocked_by,
            followed_by: relationship.followed_by,
            muting: relationship.muting,
            muting_notifications: relationship.muting_notifications,
            domain_blocking: false,
            endorsed: false,
            languages: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LookupQuery {
    pub acct: String,
}

pub async fn show(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<AccountDto>> {
    let account = nodus_server_store::accounts::by_id(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    Ok(Json(AccountDto::from_row(&account, state.instance())))
}

pub async fn lookup(
    State(state): State<AppState>,
    Query(query): Query<LookupQuery>,
) -> ApiResult<Json<AccountDto>> {
    // Mastodon treats `user@this-instance` as the local account, because that is how a
    // handle is written when it is shared: pasted in full, with the domain it was read
    // from. The store keys local accounts by name alone, so the suffix is dropped here —
    // otherwise `/accounts/{host}/{name}` could not be resolved on the host it names.
    let instance = state.instance();
    let acct = query.acct.trim().trim_start_matches('@');
    let wanted = match acct.rsplit_once('@') {
        Some((name, host)) if host.eq_ignore_ascii_case(&instance.domain) => name,
        _ => acct,
    };
    let account = nodus_server_store::accounts::lookup(state.store().pool(), wanted)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    Ok(Json(AccountDto::from_row(&account, instance)))
}

pub async fn followers(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<PageQuery>,
) -> ApiResult<Response> {
    follow_list(state, id, query, true).await
}

pub async fn following(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<PageQuery>,
) -> ApiResult<Response> {
    follow_list(state, id, query, false).await
}

async fn follow_list(
    state: AppState,
    id: String,
    query: PageQuery,
    followers: bool,
) -> ApiResult<Response> {
    let params = query.params()?;
    let size = PageSize::clamp(params.limit, nodus_server_core::limits::PAGE_MAX_ACCOUNTS);
    let page =
        nodus_server_store::accounts::follow_page(state.store().pool(), &id, followers, params)
            .await?;
    let items: Vec<_> = page
        .items
        .iter()
        .map(|row| AccountDto::from_row(row, state.instance()))
        .collect();
    let mut response = Json(items).into_response();
    if let Some(next) = page.next_max_id {
        let path = format!(
            "/api/v1/accounts/{id}/{}",
            if followers { "followers" } else { "following" }
        );
        if let Some(link) = params.next_link(&path, next.parse().ok(), size) {
            if let Ok(value) = HeaderValue::from_str(&link) {
                response
                    .headers_mut()
                    .insert(axum::http::header::LINK, value);
            }
        }
    }
    Ok(response)
}

pub async fn follow(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<RelationshipDto>> {
    auth.require_scope("write:follows")?;
    let target = target(&state, &id).await?;
    let outcome = nodus_server_store::social::follow(
        state.store().pool(),
        &auth.0.account.id,
        &target.id,
        true,
        false,
    )
    .await?;
    crate::outbox::deliver_follow(
        &state,
        &auth.0.account.id,
        &target.id,
        outcome == FollowOutcome::Following,
    )
    .await;
    if outcome == FollowOutcome::Following {
        nodus_server_store::social::notify(
            state.store().pool(),
            &target.id,
            "follow",
            &auth.0.account.id,
            None,
        )
        .await?;
    }
    let relationship =
        nodus_server_store::social::relationship(state.store().pool(), &auth.0.account.id, &id)
            .await?;
    Ok(Json(RelationshipDto::new(&id, &relationship)))
}

pub async fn unfollow(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<RelationshipDto>> {
    auth.require_scope("write:follows")?;
    nodus_server_store::social::unfollow(state.store().pool(), &auth.0.account.id, &id).await?;
    crate::outbox::deliver_follow(&state, &auth.0.account.id, &id, false).await;
    let relationship =
        nodus_server_store::social::relationship(state.store().pool(), &auth.0.account.id, &id)
            .await?;
    Ok(Json(RelationshipDto::new(&id, &relationship)))
}

pub async fn block(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<RelationshipDto>> {
    auth.require_scope("write:blocks")?;
    nodus_server_store::social::block(state.store().pool(), &auth.0.account.id, &id).await?;
    let relationship =
        nodus_server_store::social::relationship(state.store().pool(), &auth.0.account.id, &id)
            .await?;
    Ok(Json(RelationshipDto::new(&id, &relationship)))
}

pub async fn unblock(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<RelationshipDto>> {
    auth.require_scope("write:blocks")?;
    nodus_server_store::social::unblock(state.store().pool(), &auth.0.account.id, &id).await?;
    let relationship =
        nodus_server_store::social::relationship(state.store().pool(), &auth.0.account.id, &id)
            .await?;
    Ok(Json(RelationshipDto::new(&id, &relationship)))
}

pub async fn mute(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    axum::extract::RawForm(body): axum::extract::RawForm,
) -> ApiResult<Json<RelationshipDto>> {
    auth.require_scope("write:mutes")?;
    let notifications = !url::form_urlencoded::parse(&body)
        .any(|(key, value)| key == "notifications" && value == "false");
    nodus_server_store::social::mute(state.store().pool(), &auth.0.account.id, &id, notifications)
        .await?;
    let relationship =
        nodus_server_store::social::relationship(state.store().pool(), &auth.0.account.id, &id)
            .await?;
    Ok(Json(RelationshipDto::new(&id, &relationship)))
}

pub async fn unmute(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<RelationshipDto>> {
    auth.require_scope("write:mutes")?;
    nodus_server_store::social::unmute(state.store().pool(), &auth.0.account.id, &id).await?;
    let relationship =
        nodus_server_store::social::relationship(state.store().pool(), &auth.0.account.id, &id)
            .await?;
    Ok(Json(RelationshipDto::new(&id, &relationship)))
}

pub async fn blocks(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<AccountDto>>> {
    auth.require_scope("read:blocks")?;
    let rows =
        nodus_server_store::social::relations(state.store().pool(), &auth.0.account.id, "block")
            .await?;
    Ok(Json(
        rows.iter()
            .map(|row| AccountDto::from_row(row, state.instance()))
            .collect(),
    ))
}

pub async fn mutes(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<AccountDto>>> {
    auth.require_scope("read:mutes")?;
    let rows =
        nodus_server_store::social::relations(state.store().pool(), &auth.0.account.id, "mute")
            .await?;
    Ok(Json(
        rows.iter()
            .map(|row| AccountDto::from_row(row, state.instance()))
            .collect(),
    ))
}

pub async fn relationships(
    State(state): State<AppState>,
    auth: Auth,
    RawQuery(query): RawQuery,
) -> ApiResult<Json<Vec<RelationshipDto>>> {
    auth.require_scope("read:follows")?;
    let ids = parse_id_list(query.as_deref().unwrap_or_default());
    let mut relationships = Vec::with_capacity(ids.len());
    for id in ids {
        let relationship =
            nodus_server_store::social::relationship(state.store().pool(), &auth.0.account.id, &id)
                .await?;
        relationships.push(RelationshipDto::new(&id, &relationship));
    }
    Ok(Json(relationships))
}

fn parse_id_list(raw: &str) -> Vec<String> {
    url::form_urlencoded::parse(raw.as_bytes())
        .filter(|(key, _)| key == "id[]" || key == "id")
        .map(|(_, value)| value.into_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

async fn target(state: &AppState, id: &str) -> ApiResult<AccountRow> {
    nodus_server_store::accounts::by_id(state.store().pool(), id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))
}

/// How far one non-status section of an export reads before it says it stopped.
///
/// The statuses section pages because it is the one that grows without bound; these are
/// capped instead, and each says so rather than silently truncating. 1000 is a ceiling a
/// person's notifications and audit history sit far below, and a bound a hostile account
/// cannot use to make one request read the whole table.
const EXPORT_SECTION_MAX: i64 = 1000;

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    /// Cursor into the statuses section.
    ///
    /// The export is one JSON document, but the largest section is paginated inside it:
    /// `?max_id=` names the last status the previous page carried, and the response's
    /// `paging.statuses.next_max_id` is that cursor (or null at the end). A 50 000-post
    /// account is therefore answered in 250 bounded pages rather than one assembled string.
    #[serde(default)]
    pub max_id: Option<String>,
    /// Statuses per page, clamped to `EXPORT_PAGE_MAX`.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// A fully-qualified handle, which is what a portability export is read by.
fn export_handle(row: &AccountRow, instance: &InstanceConfig) -> String {
    match row.domain.as_deref() {
        Some(domain) => format!("{}@{domain}", row.username),
        None => format!("{}@{}", row.username, instance.domain),
    }
}

/// `GET /api/v1/accounts/{id}/export` — everything this instance holds about one account,
/// in one document a person can keep.
///
/// The projection below is the whole point of the endpoint, and it is assembled field by
/// field rather than by serializing `AccountRow`. That row carries `private_key_pem` and a
/// `client_metadata` blob, and the tables beside it hold `account_credential.email`, a
/// password hash, `auth_session.token_hash` and `oauth_token.token_hash`. None of that is
/// data *about* the person's activity, and an export is precisely where a credential leaks:
/// a file downloaded once outlives the session it was downloaded in, gets copied to a
/// backup, and is read by whoever finds it. So the omission is deliberate and permanent —
/// no email, no password hash, no session or OAuth token, no private key — and it is a
/// projection instead of "serialize then delete keys" so a column added to `account` later
/// is absent by default rather than published by accident.
pub async fn export(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Query(query): Query<ExportQuery>,
) -> ApiResult<Response> {
    let pool = state.store().pool();
    let instance = state.instance();
    // Only local accounts have data here: a remote account's posts live on the instance
    // that minted them, and exporting the cached copy as though it were theirs would be a
    // worse answer than saying it is not ours to export.
    let account = nodus_server_store::accounts::by_id(pool, &id)
        .await?
        .filter(|row| row.local)
        .ok_or_else(|| ApiError::not_found("Record not found"))?;

    if auth.0.account.id == account.id {
        auth.require_scope("read:accounts")?;
    } else {
        // Someone else's export is a staff read, not a public one: the role gate comes
        // first, then the scope, exactly as every other `admin:read` surface does.
        auth.require_admin("admin:read")?;
    }

    let page = nodus_server_store::statuses::export_page(
        pool,
        &account.id,
        query.max_id.as_deref(),
        query.limit.map_or(i64::from(nodus_server_store::statuses::EXPORT_PAGE_MAX), i64::from),
    )
    .await?;
    let status_ids: Vec<String> = page.items.iter().map(|row| row.id.clone()).collect();
    let attachments = if status_ids.is_empty() {
        Vec::new()
    } else {
        nodus_server_store::media::by_statuses(pool, &status_ids).await?
    };

    // Media is described, never carried: {url, digest} is what lets a person re-fetch or
    // verify a file, and the bytes are what would turn an export into a second archive of
    // everything they ever posted.
    let mut media_by_status: std::collections::HashMap<&str, Vec<serde_json::Value>> =
        std::collections::HashMap::new();
    for row in &attachments {
        if let Some(status_id) = row.status_id.as_deref() {
            media_by_status.entry(status_id).or_default().push(json!({
                "url": row
                    .remote_url
                    .clone()
                    .unwrap_or_else(|| instance.url(&format!("/media/{}", row.id))),
                "digest": row.digest,
                "content_type": row.content_type,
                "size": row.size,
                "width": row.width,
                "height": row.height,
                "description": row.description,
                "blurhash": row.blurhash,
                "sensitive": row.sensitive,
                "remote": row.remote,
            }));
        }
    }

    let statuses: Vec<serde_json::Value> = page
        .items
        .iter()
        .map(|row| {
            json!({
                "id": row.id,
                "url": instance.url(&format!("/@{}/{}", account.username, row.id)),
                "uri": row.uri,
                "created_at": row.created_at,
                "edited_at": row.edited_at,
                "visibility": row.visibility,
                "sensitive": row.sensitive,
                "spoiler_text": row.spoiler_text,
                "language": row.language,
                "content": row.content,
                "content_html": row.content_html,
                "in_reply_to_id": row.in_reply_to_id,
                "reblog_of_id": row.reblog_of_id,
                "favourites_count": row.favourites_count,
                "reblogs_count": row.reblogs_count,
                "replies_count": row.replies_count,
                "media": media_by_status.get(row.id.as_str()).cloned().unwrap_or_default(),
            })
        })
        .collect();

    let single_page = PageParams {
        limit: Some(nodus_server_core::limits::PAGE_MAX_ACCOUNTS),
        ..PageParams::default()
    };
    let following =
        nodus_server_store::accounts::follow_page(pool, &account.id, false, single_page).await?;
    let followers =
        nodus_server_store::accounts::follow_page(pool, &account.id, true, single_page).await?;
    let handles = |page: &nodus_server_store::accounts::FollowPage| {
        page.items
            .iter()
            .map(|row| export_handle(row, instance))
            .collect::<Vec<String>>()
    };

    let notifications = nodus_server_store::social::notifications(
        pool,
        &account.id,
        None,
        EXPORT_SECTION_MAX + 1,
        &[],
    )
    .await?;
    let notifications_truncated = notifications.len() as i64 > EXPORT_SECTION_MAX;
    let notifications: Vec<serde_json::Value> = notifications
        .into_iter()
        .take(EXPORT_SECTION_MAX as usize)
        .map(|row| {
            json!({
                "id": row.id,
                "kind": row.kind,
                "from_account_id": row.from_account_id,
                "status_id": row.status_id,
                "note": row.note,
                "moderation_action": row.moderation_action,
                "moderation_reason": row.moderation_reason,
                "moderation_rule": row.moderation_rule,
                "moderation_expires_at": row.moderation_expires_at,
                "created_at": row.created_at,
                "seen_at": row.seen_at,
            })
        })
        .collect();

    // A warning is a moderation notification whose decision was `warn`: the action changed
    // nothing about the account, so the sentence is the whole record. It is read out of the
    // notification list rather than queried again, so the two sections cannot disagree.
    let warnings: Vec<&serde_json::Value> = notifications
        .iter()
        .filter(|row| {
            row["kind"] == json!("moderation") && row["moderation_action"] == json!("warn")
        })
        .collect();

    let appeals = nodus_server_store::appeals::mine(pool, &account.id).await?;
    let appeals: Vec<serde_json::Value> = appeals
        .iter()
        .map(|row| {
            json!({
                "id": row.id,
                "action": row.action,
                "reason": row.reason,
                "status": row.status,
                "decision_note": row.decision_note,
                "decided_by": row.decided_by,
                "created_at": row.created_at,
                "decided_at": row.decided_at,
            })
        })
        .collect();

    let strikes = nodus_server_store::escalation::strikes(pool, &account.id).await?;
    let strikes: Vec<serde_json::Value> = strikes
        .iter()
        .map(|row| {
            json!({
                "id": row.id,
                "action": row.action,
                "rule": row.rule_name,
                "reason": row.reason,
                "created_at": row.created_at,
                "expires_at": row.expires_at,
            })
        })
        .collect();

    let mut actions = nodus_server_store::moderation::audit_for_account(
        pool,
        &account.id,
        EXPORT_SECTION_MAX + 1,
    )
    .await?;
    let actions_truncated = actions.len() as i64 > EXPORT_SECTION_MAX;
    actions.truncate(EXPORT_SECTION_MAX as usize);
    let actions: Vec<serde_json::Value> = actions
        .iter()
        .map(|row| {
            json!({
                "id": row.id,
                "action": row.action,
                "actor_id": row.actor_id,
                "detail": row.detail,
                "created_at": row.created_at,
            })
        })
        .collect();

    let document = json!({
        "contract": "nodus-1",
        "generated_at": chrono::Utc::now(),
        "account": {
            "id": account.id,
            "handle": export_handle(&account, instance),
            "username": account.username,
            "domain": account.domain,
            "display_name": account.display_name,
            "note": account.note,
            "uri": account.uri,
            "url": crate::dto::account_url(&account, instance),
            "avatar_url": account.avatar_url,
            "header_url": account.header_url,
            "fields": account.fields,
            "locked": account.locked,
            "bot": account.bot,
            "discoverable": account.discoverable,
            "indexable": account.indexable,
            "staff_role": account.staff_role,
            "approved": account.approved,
            "followers_count": account.followers_count,
            "following_count": account.following_count,
            "statuses_count": account.statuses_count,
            "suspended_at": account.suspended_at,
            "silenced_at": account.silenced_at,
            "created_at": account.created_at,
        },
        "paging": {
            "statuses": {
                "next_max_id": page.next_max_id,
                "limit": query.limit,
                "path": instance.url(&format!("/api/v1/accounts/{}/export", account.id)),
            },
            "notifications_truncated": notifications_truncated,
            "actions_truncated": actions_truncated,
            "relationships_truncated": following.next_max_id.is_some()
                || followers.next_max_id.is_some(),
        },
        "statuses": statuses,
        "relationships": {
            "following": handles(&following),
            "followers": handles(&followers),
        },
        "notifications": notifications,
        "appeals": appeals,
        "moderation": {
            "strikes": strikes,
            "actions": actions,
            "warnings": warnings,
        },
    });
    Ok(Json(document).into_response())
}
