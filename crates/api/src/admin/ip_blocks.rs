//! Source-address blocks, with an end.
//!
//! The console writes them; registration and the authenticated-request extractor read
//! them. Expiry needs no sweep: every query filters on `expires_at`, so a lapsed block stops
//! applying the next time anything asks.
//!
//! Matching happens on the truncated address the instance actually keeps — a `/24` for IPv4
//! and a `/48` for IPv6. A single address is widened to that prefix and a wider CIDR is kept
//! as written; the comment on [`nodus_server_store::ip_block::normalize`] says why.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use nodus_server_store::ip_block::{self, IpBlock};

use super::Body;
use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// The severities an operator may set, in the order the table's constraint names them.
const SEVERITIES: [&str; 3] = [
    ip_block::SIGN_UP_REQUIRES_APPROVAL,
    ip_block::SIGN_UP_BLOCK,
    ip_block::NO_ACCESS,
];

#[derive(Debug, Deserialize)]
pub struct BlockForm {
    ip: String,
    severity: String,
    #[serde(default)]
    comment: String,
    /// Seconds until the block lapses; absent or empty means forever. A string rather than
    /// an integer because Mastodon clients send forms, where "no expiry" is an empty field.
    #[serde(default)]
    expires_in: Option<String>,
}

fn seconds(raw: Option<&str>) -> ApiResult<Option<i64>> {
    raw.map(str::trim)
        .filter(|raw| !raw.is_empty())
        .map(|raw| {
            raw.parse::<i64>()
                .map_err(|_| ApiError::unprocessable("expires_in must be a whole number of seconds"))
        })
        .transpose()
}

fn severity(raw: &str) -> ApiResult<&str> {
    let raw = raw.trim();
    if SEVERITIES.contains(&raw) {
        Ok(raw)
    } else {
        Err(ApiError::unprocessable(format!(
            "severity must be one of {}",
            SEVERITIES.join(", ")
        )))
    }
}

/// `GET /api/v1/admin/ip_blocks` — the blocks still in force.
async fn list(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<IpBlock>>> {
    auth.require_admin("admin:read")?;
    Ok(Json(ip_block::list(state.store().pool()).await?))
}

/// `POST /api/v1/admin/ip_blocks`
async fn create(
    State(state): State<AppState>,
    auth: Auth,
    Body(form): Body<BlockForm>,
) -> ApiResult<Json<IpBlock>> {
    auth.require_admin("admin:write")?;
    let ip = ip_block::normalize(&form.ip).map_err(ApiError::unprocessable)?;
    let severity = severity(&form.severity)?;
    let expires_in = seconds(form.expires_in.as_deref())?;
    let block = match ip_block::insert(
        state.store().pool(),
        &ip,
        severity,
        form.comment.trim(),
        expires_in,
    )
    .await
    {
        Ok(block) => block,
        // One row per network: a second block on the same prefix is an edit, and telling
        // the operator that is more useful than silently overwriting the first.
        Err(error) if is_unique(&error) => {
            return Err(ApiError::unprocessable(
                "a block already exists for that address",
            ));
        }
        Err(error) => return Err(error.into()),
    };
    audit(&state, &auth, "ip_block_created", &block.id, detail(&block, &json!({}))).await?;
    Ok(Json(block))
}

/// `PUT /api/v1/admin/ip_blocks/{id}`
async fn update(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Body(form): Body<BlockForm>,
) -> ApiResult<Json<IpBlock>> {
    auth.require_admin("admin:write")?;
    let severity = severity(&form.severity)?;
    let expires_in = seconds(form.expires_in.as_deref())?;
    let before = ip_block::find(state.store().pool(), &id).await?;
    let block = ip_block::update(
        state.store().pool(),
        &id,
        severity,
        form.comment.trim(),
        expires_in,
    )
    .await?
    .ok_or_else(|| ApiError::not_found("that block does not exist"))?;
    audit(
        &state,
        &auth,
        "ip_block_updated",
        &block.id,
        detail(&block, &json!({ "before": before })),
    )
    .await?;
    Ok(Json(block))
}

/// `DELETE /api/v1/admin/ip_blocks/{id}`
async fn delete(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    auth.require_admin("admin:write")?;
    if !ip_block::delete(state.store().pool(), &id).await? {
        return Err(ApiError::not_found("that block does not exist"));
    }
    audit(&state, &auth, "ip_block_deleted", &id, json!({})).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn audit(
    state: &AppState,
    auth: &Auth,
    action: &str,
    id: &str,
    extra: serde_json::Value,
) -> ApiResult<()> {
    super::audit_write_detail(state, auth, action, "ip_block", id, extra).await
}

/// The block as the audit row records it, plus whatever the caller adds.
fn detail(block: &IpBlock, extra: &serde_json::Value) -> serde_json::Value {
    let mut detail = json!({
        "ip": block.ip,
        "severity": block.severity,
        "comment": block.comment,
        "expires_at": block.expires_at,
    });
    if let (Some(detail), Some(extra)) = (detail.as_object_mut(), extra.as_object()) {
        detail.extend(extra.clone());
    }
    detail
}

/// A unique violation names the field, not the row; the handler already knows the field.
fn is_unique(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(database) if database.code().as_deref() == Some("23505"))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/ip_blocks", get(list).post(create))
        .route(
            "/api/v1/admin/ip_blocks/{id}",
            axum::routing::put(update).delete(delete),
        )
}
