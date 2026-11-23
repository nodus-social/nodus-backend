//! Publishing one account's banners for other readers, and reading them back.
//!
//! A style lives in two places with different audiences. The owner's whole arrangement is
//! private client metadata, read only with that account's token. This surface is the
//! narrow, public half: the three banners, replaced wholesale, so a profile can draw the
//! banners its account chose without learning its navigation layout or modules.
//!
//! `PUT /api/v1/style/public` is the write; `GET /api/v1/accounts/{id}/style_public` is
//! the read. The two are separate route families because they have different audiences:
//! the write is an owner action under `write:accounts`, while the read is any client
//! looking at a profile and takes no token at all.

use axum::extract::{Path, State};
use axum::routing::{get, put};
use axum::{Json, Router};
use serde_json::Value;

use nodus_server_store::style_public::StylePublic;

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// The published-style routes.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/style/public", put(publish))
        .route("/api/v1/accounts/{id}/style_public", get(show))
}

/// `PUT /api/v1/style/public`
///
/// Wholesale replacement, not a merge: the body is the whole published document. A
/// picture left out of it disappears from the profile, which is the only way "remove this
/// banner" can reach viewers.
///
/// The body is read as JSON and deserialised here rather than through `Json<StylePublic>`
/// so an unknown key or a wrong type answers this API's `{"error": "…"}` shape naming the
/// offending field, instead of axum's extractor text.
pub async fn publish(
    State(state): State<AppState>,
    auth: Auth,
    Json(body): Json<Value>,
) -> ApiResult<Json<StylePublic>> {
    auth.require_scope("write:accounts")?;
    let style: StylePublic = serde_json::from_value(body).map_err(|error| {
        ApiError::unprocessable(format!("published style is not the banner shape: {error}"))
    })?;
    let style = style.cleaned().map_err(ApiError::unprocessable)?;
    state
        .store()
        .publish_style_public(&auth.0.account.id, &style)
        .await?;
    Ok(Json(style))
}

/// `GET /api/v1/accounts/{id}/style_public`
///
/// Readable without a token, like the rest of a public profile. An account that never
/// published a style answers `404`: an empty object would claim it published banners and
/// chose none.
///
/// A deleted, suspended or silenced account answers `404` as well, matching how the rest of
/// the account surface stops serving an account that moderation has taken out of view.
pub async fn show(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<StylePublic>> {
    let account = state
        .store()
        .account(&id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    if account.deleted_at.is_some()
        || account.suspended_at.is_some()
        || account.silenced_at.is_some()
    {
        return Err(ApiError::not_found("Record not found"));
    }
    let style = state
        .store()
        .style_public(&id)
        .await?
        .ok_or_else(|| ApiError::not_found("This account has published no style"))?;
    Ok(Json(style))
}
