//! Administrator alert endpoints.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use nodus_server_store::alerts;

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
struct LosslessBody {
    images: bool,
    videos: bool,
}

#[derive(Debug, Deserialize)]
struct AlertQuery {
    #[serde(default)]
    unacknowledged: bool,
    #[serde(default = "default_limit")]
    limit: i64,
}

const fn default_limit() -> i64 {
    50
}

/// One alert in the admin API.
#[derive(Debug, Serialize)]
pub struct AlertDto {
    pub id: String,
    pub kind: String,
    pub severity: String,
    pub method: Option<String>,
    pub path: Option<String>,
    pub status: Option<i32>,
    pub remote_ip: Option<String>,
    pub account_id: Option<String>,
    pub detail: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub acknowledged_at: Option<chrono::DateTime<chrono::Utc>>,
    pub acknowledged_by: Option<String>,
}

impl From<alerts::AlertRow> for AlertDto {
    fn from(row: alerts::AlertRow) -> Self {
        Self {
            id: row.id,
            kind: row.kind,
            severity: row.severity,
            method: row.method,
            path: row.path,
            status: row.status,
            remote_ip: row.remote_ip,
            account_id: row.account_id,
            detail: row.detail,
            created_at: row.created_at,
            acknowledged_at: row.acknowledged_at,
            acknowledged_by: row.acknowledged_by,
        }
    }
}

fn administrator(auth: &Auth) -> ApiResult<()> {
    if auth.0.account.admin {
        Ok(())
    } else {
        Err(ApiError::forbidden("Administrator access is required"))
    }
}

async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<AlertQuery>,
) -> ApiResult<Json<Vec<AlertDto>>> {
    administrator(&auth)?;
    let rows = alerts::recent(state.store().pool(), query.limit, query.unacknowledged).await?;
    Ok(Json(rows.into_iter().map(AlertDto::from).collect()))
}

async fn acknowledge(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<AlertDto>> {
    administrator(&auth)?;
    let changed = alerts::acknowledge(state.store().pool(), &id, &auth.0.account.id).await?;
    if !changed {
        return Err(ApiError::not_found(
            "alert is already acknowledged or does not exist",
        ));
    }
    let rows = alerts::recent(state.store().pool(), 200, false).await?;
    rows.into_iter()
        .find(|row| row.id == id)
        .map(AlertDto::from)
        .map(Json)
        .ok_or_else(|| ApiError::not_found("alert does not exist"))
}

async fn set_lossless(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(body): Json<LosslessBody>,
) -> ApiResult<StatusCode> {
    administrator(&auth)?;
    let changed = nodus_server_store::accounts::set_lossless_permissions(
        state.store().pool(),
        &id,
        body.images,
        body.videos,
    )
    .await?;
    if !changed {
        return Err(ApiError::not_found("account does not exist"));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Admin alert routes.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/alerts", get(list))
        .route("/api/v1/admin/alerts/{id}/ack", post(acknowledge))
        .route("/api/v1/admin/accounts/{id}/lossless", post(set_lossless))
}
