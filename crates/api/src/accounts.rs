//! Account lookup, follow graph and relationship endpoints.

use axum::extract::{Path, Query, RawQuery, State};
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use nodus_server_core::PageSize;
use nodus_server_store::accounts::AccountRow;
use nodus_server_store::social::{FollowOutcome, Relationship};

use crate::auth::Auth;
use crate::body::JsonOrForm;
use crate::dto::AccountDto;
use crate::error::{ApiError, ApiResult};
use crate::mastodon::PageQuery;
use crate::state::AppState;

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
