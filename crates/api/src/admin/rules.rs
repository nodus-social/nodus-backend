//! The instance's rules: the document a report is about.
//!
//! The list is ordered, and the order is the interface: a reader cites "rule 3", and a
//! report that cites it has to keep meaning the same thing. Writes therefore go through
//! the store's renumbering machinery, which holds the unique position constraint at every
//! statement and keeps the ordinals contiguous.
//!
//! Every change is audited, like the rest of this module: the rules are instance policy,
//! and "who removed rule 4" is a question the console has to be able to answer.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use nodus_server_store::rules as store_rules;

use super::{audit_write_detail, Body};
use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// One rule as an administrator sees it: the public fields plus when it changed.
#[derive(Debug, Serialize)]
pub struct AdminRuleDto {
    pub id: String,
    pub text: String,
    pub ordinal: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<store_rules::RuleRow> for AdminRuleDto {
    fn from(row: store_rules::RuleRow) -> Self {
        Self {
            id: row.id,
            text: row.text,
            ordinal: row.ordinal,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RuleForm {
    /// Required when creating; on `PUT`, absent means "leave the text alone", so a pure
    /// reorder does not have to resend what is not changing.
    #[serde(default)]
    text: Option<String>,
    /// Zero-based target position. Absent on create appends to the end.
    #[serde(default)]
    ordinal: Option<i32>,
}

/// `GET /api/v1/admin/rules`
async fn list(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<AdminRuleDto>>> {
    auth.require_admin("admin:read")?;
    let rows = store_rules::rules(state.store().pool()).await?;
    Ok(Json(rows.into_iter().map(AdminRuleDto::from).collect()))
}

/// `POST /api/v1/admin/rules`
async fn create(
    State(state): State<AppState>,
    auth: Auth,
    Body(form): Body<RuleForm>,
) -> ApiResult<Json<AdminRuleDto>> {
    auth.require_admin("admin:write")?;
    let text = form
        .text
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::unprocessable("a rule needs text"))?;
    check_ordinal(form.ordinal)?;
    let row = store_rules::create(state.store().pool(), text, form.ordinal).await?;
    audit_write_detail(
        &state,
        &auth,
        "create_instance_rule",
        "instance_rule",
        &row.id,
        json!({ "text": row.text, "ordinal": row.ordinal }),
    )
    .await?;
    Ok(Json(AdminRuleDto::from(row)))
}

/// `PUT /api/v1/admin/rules/{id}` — rewrite the text and/or move the rule.
async fn update(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Body(form): Body<RuleForm>,
) -> ApiResult<Json<AdminRuleDto>> {
    auth.require_admin("admin:write")?;
    let text = match form.text.as_deref() {
        Some(value) => {
            let value = value.trim();
            if value.is_empty() {
                return Err(ApiError::unprocessable("a rule needs text"));
            }
            Some(value)
        }
        None => None,
    };
    check_ordinal(form.ordinal)?;
    let row = store_rules::update(state.store().pool(), &id, text, form.ordinal)
        .await?
        .ok_or_else(|| ApiError::not_found("that rule does not exist"))?;
    audit_write_detail(
        &state,
        &auth,
        "update_instance_rule",
        "instance_rule",
        &row.id,
        json!({ "text": row.text, "ordinal": row.ordinal }),
    )
    .await?;
    Ok(Json(AdminRuleDto::from(row)))
}

/// `DELETE /api/v1/admin/rules/{id}` — reports that cited it keep the id.
async fn delete_rule(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    auth.require_admin("admin:write")?;
    if !store_rules::delete(state.store().pool(), &id).await? {
        return Err(ApiError::not_found("that rule does not exist"));
    }
    audit_write_detail(
        &state,
        &auth,
        "delete_instance_rule",
        "instance_rule",
        &id,
        json!({}),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn check_ordinal(ordinal: Option<i32>) -> ApiResult<()> {
    match ordinal {
        Some(value) if value < 0 => Err(ApiError::unprocessable(
            "ordinal must be zero or greater; positions start at zero",
        )),
        _ => Ok(()),
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/rules", get(list).post(create))
        .route("/api/v1/admin/rules/{id}", put(update).delete(delete_rule))
}
