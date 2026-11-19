//! Appeals from the restricted account's side.
//!
//! An appeal is the only write a suspended or refused account can make: the token every
//! other route refuses still resolves here, through [`AppealAuth`]. The handler is
//! therefore small on purpose — read it as "this is the door that stays open".

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use nodus_server_store::appeals::{self, AppealRow, OpenOutcome};

use crate::auth::AppealAuth;
use crate::body::JsonOrForm;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// A long enough explanation for a person to be understood, short enough to read.
const REASON_MAX: usize = 2000;

/// One appeal as the person who wrote it sees it.
#[derive(Debug, Serialize)]
pub struct AppealDto {
    pub id: String,
    /// The restriction being appealed: `suspend`, `silence` or `reject`.
    pub action: String,
    pub reason: String,
    pub status: String,
    pub decision_note: Option<String>,
    pub created_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
}

impl AppealDto {
    /// Also used by the notification reader, which shows a pending appeal beside the
    /// notice that prompted it.
    pub fn from_row(row: AppealRow) -> Self {
        Self {
            id: row.id,
            action: row.action,
            reason: row.reason,
            status: row.status,
            decision_note: row.decision_note,
            created_at: row.created_at,
            decided_at: row.decided_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct NewAppeal {
    #[serde(default)]
    pub reason: String,
}

/// `POST /api/v1/appeals` — opens an appeal for the caller's own account.
///
/// The scope is the one the codebase already uses for self-service profile writes; a
/// client that can edit its own profile can ask for a review of its own restriction.
async fn open(
    State(state): State<AppState>,
    auth: AppealAuth,
    JsonOrForm(request): JsonOrForm<NewAppeal>,
) -> ApiResult<(StatusCode, Json<AppealDto>)> {
    auth.0.require_scope("write:accounts")?;
    let reason = request.reason.trim();
    if reason.is_empty() {
        return Err(ApiError::unprocessable("reason must not be empty"));
    }
    if reason.chars().count() > REASON_MAX {
        return Err(ApiError::unprocessable(format!(
            "reason must be at most {REASON_MAX} characters"
        )));
    }
    match appeals::open(state.store().pool(), &auth.0 .0.account.id, reason).await? {
        OpenOutcome::Opened(row) => Ok((StatusCode::OK, Json(AppealDto::from_row(row)))),
        OpenOutcome::NotRestricted => {
            Err(ApiError::unprocessable("this account is not restricted"))
        }
        OpenOutcome::AlreadyPending(row) => Err(ApiError::unprocessable(format!(
            "an appeal is already pending for this account: {}",
            row.id
        ))),
    }
}

/// `GET /api/v1/appeals` — the caller's own appeals, newest first.
async fn list(State(state): State<AppState>, auth: AppealAuth) -> ApiResult<Json<Vec<AppealDto>>> {
    auth.0.require_scope("read:accounts")?;
    let rows = appeals::mine(state.store().pool(), &auth.0 .0.account.id).await?;
    Ok(Json(rows.into_iter().map(AppealDto::from_row).collect()))
}

/// The router fragment, mounted by `crate::router`.
pub fn router() -> Router<AppState> {
    Router::new().route("/api/v1/appeals", get(list).post(open))
}
