//! Tag pages and subscriptions.
//!
//! A tag is not a row of its own; it exists because posts used it. So a name nobody has
//! used and nobody follows is a 404 here, the same answer Mastodon gives for a tag that
//! does not exist, rather than a fabricated object with an empty history.

use axum::extract::{Path, State};
use axum::Json;

use crate::auth::Auth;
use crate::discovery::{tag as tag_dto, TagDto};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// The name as it is stored: clients sometimes keep the leading `#`.
fn clean(name: &str) -> &str {
    name.trim().trim_start_matches('#')
}

/// Loads the tag and the viewer's subscription state, or 404s an unknown name.
async fn view(state: &AppState, account_id: &str, name: &str) -> ApiResult<TagDto> {
    let pool = state.store().pool();
    let row = nodus_server_store::tags::tag(pool, name)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    let following = nodus_server_store::tags::followed(pool, account_id, name).await?;
    Ok(tag_dto(state, row, following))
}

/// `GET /api/v1/tags/{name}`
///
/// The tag object with `following` resolved for the caller. The scope is
/// `read:statuses` because a tag page is a view over posts.
pub async fn show(
    State(state): State<AppState>,
    auth: Auth,
    Path(name): Path<String>,
) -> ApiResult<Json<TagDto>> {
    auth.require_scope("read:statuses")?;
    let name = clean(&name);
    Ok(Json(view(&state, &auth.0.account.id, name).await?))
}

/// `POST /api/v1/tags/{name}/follow`
///
/// Idempotent: a second follow answers 200 with `following: true` and writes nothing.
pub async fn follow(
    State(state): State<AppState>,
    auth: Auth,
    Path(name): Path<String>,
) -> ApiResult<Json<TagDto>> {
    auth.require_scope("write:follows")?;
    let name = clean(&name);
    if nodus_server_store::tags::tag(state.store().pool(), name)
        .await?
        .is_none()
    {
        return Err(ApiError::not_found("Record not found"));
    }
    nodus_server_store::tags::follow(state.store().pool(), &auth.0.account.id, name).await?;
    Ok(Json(view(&state, &auth.0.account.id, name).await?))
}

/// `POST /api/v1/tags/{name}/unfollow`
///
/// Idempotent as well: unfollowing a tag one does not follow still answers the tag with
/// `following: false`.
pub async fn unfollow(
    State(state): State<AppState>,
    auth: Auth,
    Path(name): Path<String>,
) -> ApiResult<Json<TagDto>> {
    auth.require_scope("write:follows")?;
    let name = clean(&name);
    if nodus_server_store::tags::tag(state.store().pool(), name)
        .await?
        .is_none()
    {
        return Err(ApiError::not_found("Record not found"));
    }
    nodus_server_store::tags::unfollow(state.store().pool(), &auth.0.account.id, name).await?;
    Ok(Json(view(&state, &auth.0.account.id, name).await?))
}

/// The router fragment, mounted by `crate::router`.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/api/v1/tags/{name}", get(show))
        .route("/api/v1/tags/{name}/follow", post(follow))
        .route("/api/v1/tags/{name}/unfollow", post(unfollow))
}
