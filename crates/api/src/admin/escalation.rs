//! The escalation policy: how many strikes mean what.
//!
//! One row, edited by an administrator, never created by a request. The routes are small
//! because the decisions are not: validation names the offending step, and every write is
//! audited with the previous policy so "who loosened this" is answerable.
//!
//! The strikes themselves are readable per account, next to the account payload's
//! `strike_count` and `next_escalation`, so a moderator deciding a case sees the pattern
//! without opening the audit log.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use nodus_server_store::escalation::{self, PolicyInput, Step};

use super::{audit_write_detail, Body};
use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// The policy as an administrator reads it, with the defaults stated on an untouched
/// instance rather than implied.
#[derive(Debug, Serialize)]
pub struct PolicyDto {
    /// The name the audit trail cites.
    pub name: String,
    pub enabled: bool,
    pub window_days: i32,
    pub steps: Vec<Step>,
    pub updated_at: DateTime<Utc>,
    /// The administrator who last edited it; absent when nobody has.
    pub updated_by: Option<String>,
}

impl From<escalation::Policy> for PolicyDto {
    fn from(row: escalation::Policy) -> Self {
        let steps = row.steps();
        Self {
            name: row.name,
            enabled: row.enabled,
            window_days: row.window_days,
            steps,
            updated_at: row.updated_at,
            updated_by: row.updated_by,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct PolicyForm {
    enabled: bool,
    window_days: i64,
    steps: Vec<Step>,
}

/// One strike, as the account's page lists it.
#[derive(Debug, Serialize)]
pub struct StrikeDto {
    pub id: String,
    pub account_id: String,
    pub rule_id: Option<String>,
    /// The rule's name. A deleted rule leaves this null and the strike untouched.
    pub rule_name: Option<String>,
    pub action: String,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    /// When it stops counting. Always present: `live` is just `expires_at > now`.
    pub expires_at: DateTime<Utc>,
    pub live: bool,
}

/// `GET /api/v1/admin/escalation`
async fn read(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<PolicyDto>> {
    auth.require_admin("admin:read")?;
    let policy = escalation::policy(state.store().pool()).await?;
    Ok(Json(policy.into()))
}

/// `PUT /api/v1/admin/escalation` — the steps an instance escalates by.
///
/// Refused with 422 naming the step when the policy cannot be reasoned about: descending or
/// duplicated strike counts, an unknown action, or a step count outside the bound. A policy
/// that cannot be understood must not be storable, because it is applied by a background
/// consequence of a moderator's click.
async fn write(
    State(state): State<AppState>,
    auth: Auth,
    Body(form): Body<PolicyForm>,
) -> ApiResult<Json<PolicyDto>> {
    auth.require_admin("admin:write")?;
    let input = PolicyInput {
        enabled: form.enabled,
        window_days: form.window_days,
        steps: &form.steps,
    };
    let before = escalation::policy(state.store().pool()).await?;
    let saved = escalation::save_policy(state.store().pool(), &input, &auth.0.account.id)
        .await?
        .map_err(ApiError::unprocessable)?;
    audit_write_detail(
        &state,
        &auth,
        "escalation_policy_updated",
        "escalation_policy",
        &saved.name,
        json!({
            "enabled": saved.enabled,
            "window_days": saved.window_days,
            "steps": saved.steps(),
            // The policy it replaced, so the audit row can answer "what changed" without a
            // second lookup that a later edit would already have overwritten.
            "before": {
                "enabled": before.enabled,
                "window_days": before.window_days,
                "steps": before.steps(),
            },
        }),
    )
    .await?;
    Ok(Json(saved.into()))
}

/// `GET /api/v1/admin/accounts/{id}/strikes`
async fn strikes(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<StrikeDto>>> {
    auth.require_admin("admin:read")?;
    let now = Utc::now();
    let rows = escalation::strikes(state.store().pool(), &id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| StrikeDto {
                id: row.id,
                account_id: row.account_id,
                rule_id: row.rule_id,
                rule_name: row.rule_name,
                action: row.action,
                reason: row.reason,
                created_at: row.created_at,
                expires_at: row.expires_at,
                live: row.expires_at > now,
            })
            .collect(),
    ))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/escalation", get(read).put(write))
        .route("/api/v1/admin/accounts/{id}/strikes", get(strikes))
}
