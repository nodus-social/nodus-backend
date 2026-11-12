//! Reaction endpoints.
//!
//! Mastodon has favourites; Misskey has one reaction per account per note. This
//! surface exposes the latter without making the storage layer depend on a
//! particular client dialect.

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use nodus_server_sdk::misskey::Reaction;
use nodus_server_store::statuses::{self, ReactionCount};

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ReactionBody {
    reaction: String,
}

/// `PUT /api/v1/statuses/{id}/reaction`
pub async fn set(
    auth: Auth,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<ReactionBody>,
) -> ApiResult<Json<Value>> {
    auth.require_scope("write")?;
    let status = statuses::by_id(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    let reaction = Reaction::parse(&body.reaction)
        .map_err(|error| ApiError::unprocessable(error.to_string()))?;
    statuses::set_reaction(
        state.store().pool(),
        &status.id,
        &auth.0.account.id,
        reaction.as_str(),
    )
    .await?;
    Ok(Json(json!({ "ok": true })))
}

/// `DELETE /api/v1/statuses/{id}/reaction`
pub async fn remove(
    auth: Auth,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    auth.require_scope("write")?;
    let status = statuses::by_id(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    statuses::remove_reaction(state.store().pool(), &status.id, &auth.0.account.id).await?;
    Ok(Json(json!({ "ok": true })))
}

/// `GET /api/v1/statuses/{id}/reactions`
pub async fn list(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<ReactionCount>>> {
    let status = statuses::by_id(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    Ok(Json(
        statuses::reactions(state.store().pool(), &status.id).await?,
    ))
}
