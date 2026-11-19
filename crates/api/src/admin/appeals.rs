//! The appeal queue.
//!
//! A moderation decision is a judgement about a person, and a person may disagree. The
//! queue is what makes the disagreement actionable: the row carries the account, the
//! restriction it was written under, why the person wrote it and how long it has waited,
//! so a moderator can decide without opening five other pages.

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use nodus_server_store::appeals::{self, AdminAppealRow, DecideOutcome};
use nodus_server_store::social;

use super::Body;
use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

use super::{offset, page};

/// How long a decision note may be; a note is read by the person it is about.
const NOTE_MAX: usize = 2000;

/// One appeal in the moderator's queue.
#[derive(Debug, Serialize)]
pub struct AdminAppealDto {
    pub id: String,
    pub account_id: String,
    /// `@user`, or `@user@host` for a remote account.
    pub handle: String,
    /// The restriction in force *now*; `null` when the decision accepted the appeal.
    pub restriction: Option<String>,
    /// The restriction the appeal was written against.
    pub action: String,
    pub reason: String,
    pub status: String,
    pub decision_note: Option<String>,
    pub decided_by: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Whole seconds since the appeal was opened; the queue shows how long it has waited.
    pub age_seconds: i64,
    pub decided_at: Option<DateTime<Utc>>,
}

impl AdminAppealDto {
    fn from_row(row: AdminAppealRow) -> Self {
        let handle = match row.domain.as_deref() {
            Some(domain) => format!("@{}@{}", row.username, domain),
            None => format!("@{}", row.username),
        };
        let age_seconds = Utc::now()
            .signed_duration_since(row.created_at)
            .num_seconds()
            .max(0);
        let restriction = row.restriction().map(|value| value.as_str().to_owned());
        Self {
            id: row.id,
            account_id: row.account_id,
            handle,
            restriction,
            action: row.action,
            reason: row.reason,
            status: row.status,
            decision_note: row.decision_note,
            decided_by: row.decided_by,
            created_at: row.created_at,
            age_seconds,
            decided_at: row.decided_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AppealQuery {
    status: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<AppealQuery>,
) -> ApiResult<Json<Vec<AdminAppealDto>>> {
    auth.require_admin("admin:read")?;
    let status = match query.status.as_deref() {
        None | Some("all") => None,
        Some(value @ ("pending" | "accepted" | "rejected")) => Some(value),
        Some(value) => {
            return Err(ApiError::unprocessable(format!(
                "unknown appeal status: {value}"
            )))
        }
    };
    let rows = appeals::admin_list(
        state.store().pool(),
        status,
        page(query.limit),
        offset(query.offset),
    )
    .await?;
    Ok(Json(
        rows.into_iter().map(AdminAppealDto::from_row).collect(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct DecideBody {
    pub accept: bool,
    #[serde(default)]
    pub note: Option<String>,
}

/// `POST /api/v1/admin/appeals/{id}/decide`
///
/// Accepting lifts the restriction the appeal named; either outcome writes its audit row
/// in the same transaction as the decision, and either outcome tells the person.
async fn decide(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Body(body): Body<DecideBody>,
) -> ApiResult<Json<AdminAppealDto>> {
    auth.require_admin("admin:write")?;
    let note = body
        .note
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if note.is_some_and(|value| value.chars().count() > NOTE_MAX) {
        return Err(ApiError::unprocessable(format!(
            "note must be at most {NOTE_MAX} characters"
        )));
    }
    let decided = appeals::decide(
        state.store().pool(),
        &id,
        body.accept,
        note,
        &auth.0.account.id,
    )
    .await?;
    let row = match decided {
        DecideOutcome::Decided(row) => row,
        DecideOutcome::AlreadyDecided => {
            return Err(ApiError::new(
                axum::http::StatusCode::CONFLICT,
                "this appeal has already been decided",
            ))
        }
        DecideOutcome::NotFound => return Err(ApiError::not_found("that appeal does not exist")),
    };
    // Best-effort like every other notification: the decision is already durable, and an
    // insert that fails must not turn it into an error the moderator would retry.
    let outcome = if body.accept { "accepted" } else { "rejected" };
    let message = match note {
        Some(value) => format!("Your appeal was {outcome}: {value}"),
        None => format!("Your appeal was {outcome}."),
    };
    if let Err(error) = social::notify_with_note(
        state.store().pool(),
        &row.account_id,
        "appeal",
        &auth.0.account.id,
        None,
        Some(&message),
    )
    .await
    {
        tracing::warn!(%error, appeal = %row.id, "could not notify the appellant");
    }
    let row = appeals::admin_row(state.store().pool(), &row.id)
        .await?
        .ok_or_else(|| ApiError::not_found("that appeal does not exist"))?;
    Ok(Json(AdminAppealDto::from_row(row)))
}

/// The router fragment, merged by `super::router`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/appeals", get(list))
        .route("/api/v1/admin/appeals/{id}/decide", post(decide))
}
