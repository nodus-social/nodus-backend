//! Mastodon markers: where a reader stopped reading each timeline.
//!
//! The write is a merge, not a replace: a client sends only the timelines it moved, and
//! a marker it does not mention stays where it was.

use std::collections::{BTreeMap, HashMap};

use axum::extract::State;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// One timeline's new position, as a client sends it.
#[derive(Debug, Deserialize)]
pub struct MarkerInput {
    pub last_read_id: String,
    #[serde(default)]
    pub version: Option<i32>,
}

/// One timeline's position, as a client reads it back.
#[derive(Debug, Serialize)]
pub struct MarkerDto {
    pub last_read_id: String,
    pub version: i32,
    pub updated_at: DateTime<Utc>,
}

/// `GET /api/v1/markers?timeline[]=home` — without a filter, every marker.
pub async fn show(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<HashMap<String, MarkerDto>>> {
    auth.require_scope("read:statuses")?;
    let rows = nodus_server_store::markers::list(state.store().pool(), &auth.0.account.id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| {
                (
                    row.timeline,
                    MarkerDto {
                        last_read_id: row.last_read_id,
                        version: row.version,
                        updated_at: row.updated_at,
                    },
                )
            })
            .collect(),
    ))
}

/// `POST /api/v1/markers` — body is `{ "home": { "last_read_id": "…" } }`.
///
/// JSON rather than form encoding: the nested shape has no unambiguous form
/// representation, and the SDK sends JSON for this call.
pub async fn save(
    State(state): State<AppState>,
    auth: Auth,
    Json(input): Json<BTreeMap<String, MarkerInput>>,
) -> ApiResult<Json<HashMap<String, MarkerDto>>> {
    auth.require_scope("write:statuses")?;
    if input.is_empty() {
        return Err(ApiError::unprocessable("no markers given"));
    }
    let mut saved = HashMap::with_capacity(input.len());
    for (timeline, marker) in input {
        if marker.last_read_id.trim().is_empty() {
            return Err(ApiError::unprocessable(format!(
                "{timeline}: last_read_id is required"
            )));
        }
        let row = nodus_server_store::markers::upsert(
            state.store().pool(),
            &auth.0.account.id,
            &timeline,
            marker.last_read_id.trim(),
            marker.version.unwrap_or(1),
        )
        .await?;
        saved.insert(
            row.timeline,
            MarkerDto {
                last_read_id: row.last_read_id,
                version: row.version,
                updated_at: row.updated_at,
            },
        );
    }
    Ok(Json(saved))
}

/// The router fragment, mounted by `crate::router`.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::get;
    axum::Router::new().route("/api/v1/markers", get(show).post(save))
}
