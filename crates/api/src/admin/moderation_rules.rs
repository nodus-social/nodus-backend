//! Rules that act without a person: the console's side.
//!
//! A rule is a pattern, a scope and an action. The store evaluates it while a post is
//! stored ([`nodus_server_store::moderation_rules`]); this module is where an
//! administrator writes one, sees what it has done, and tests it before turning it on.
//!
//! Two promises the handlers keep:
//!
//! * a pattern that cannot compile is refused with `422` and the byte offset of the
//!   error, because a stored rule that silently never matches is worse than not having it;
//! * the dry run writes nothing — no hit is counted, no audit row is written — so an
//!   administrator can try a rule against a real spam post without the test itself
//!   becoming a moderation action.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use nodus_server_store::moderation_rules::{
    self as store_rules, PatternError, RuleRow, NAME_MAX_CHARS,
};

use super::{audit_write_detail, Body};
use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// One rule as an administrator sees it.
#[derive(Debug, Serialize)]
pub struct RuleDto {
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub pattern_kind: String,
    pub scope: String,
    pub action: String,
    pub enabled: bool,
    pub hits: i64,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<RuleRow> for RuleDto {
    fn from(row: RuleRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            pattern: row.pattern,
            pattern_kind: row.pattern_kind,
            scope: row.scope,
            action: row.action,
            enabled: row.enabled,
            hits: row.hits,
            created_by: row.created_by,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RuleForm {
    name: Option<String>,
    pattern: Option<String>,
    pattern_kind: Option<String>,
    scope: Option<String>,
    action: Option<String>,
    enabled: Option<bool>,
}

/// What a rule will be once a form is applied; every field is a replacement.
struct Fields {
    name: String,
    pattern: String,
    pattern_kind: String,
    scope: String,
    action: String,
    enabled: bool,
}

impl Fields {
    fn from_row(row: &RuleRow) -> Self {
        Self {
            name: row.name.clone(),
            pattern: row.pattern.clone(),
            pattern_kind: row.pattern_kind.clone(),
            scope: row.scope.clone(),
            action: row.action.clone(),
            enabled: row.enabled,
        }
    }
}

/// `GET /api/v1/admin/moderation-rules`
async fn list(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<RuleDto>>> {
    auth.require_admin("admin:read")?;
    let rows = store_rules::rules(state.store().pool()).await?;
    Ok(Json(rows.into_iter().map(RuleDto::from).collect()))
}

/// `GET /api/v1/admin/moderation-rules/{id}`
async fn one(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<RuleDto>> {
    auth.require_admin("admin:read")?;
    let row = load(&state, &id).await?;
    Ok(Json(RuleDto::from(row)))
}

/// `POST /api/v1/admin/moderation-rules`
///
/// Defaults match the table's: a keyword rule watching arrivals, which flags. The kind is
/// required in practice (a regex and a keyword are not the same test), but defaulting to
/// `keyword` keeps a one-field form from being a 422 about a field it did not send.
async fn create(
    State(state): State<AppState>,
    auth: Auth,
    Body(form): Body<RuleForm>,
) -> ApiResult<Json<RuleDto>> {
    auth.require_admin("admin:write")?;
    let name = form
        .name
        .as_deref()
        .ok_or_else(|| ApiError::unprocessable("a rule needs a name"))?;
    let pattern = form
        .pattern
        .as_deref()
        .ok_or_else(|| ApiError::unprocessable("a rule needs a pattern"))?;
    let fields = Fields {
        name: name.to_owned(),
        pattern: pattern.to_owned(),
        pattern_kind: form.pattern_kind.unwrap_or_else(|| "keyword".to_owned()),
        scope: form.scope.unwrap_or_else(|| "inbound".to_owned()),
        action: form.action.unwrap_or_else(|| "flag".to_owned()),
        enabled: form.enabled.unwrap_or(true),
    };
    let fields = checked(fields)?;
    let row = store_rules::create(
        state.store().pool(),
        &store_rules::NewRule {
            name: &fields.name,
            pattern: &fields.pattern,
            pattern_kind: &fields.pattern_kind,
            scope: &fields.scope,
            action: &fields.action,
            enabled: fields.enabled,
            created_by: Some(&auth.0.account.id),
        },
    )
    .await?;
    audit_write_detail(
        &state,
        &auth,
        "create_moderation_rule",
        "moderation_rule",
        &row.id,
        json!({
            "name": row.name,
            "pattern": row.pattern,
            "pattern_kind": row.pattern_kind,
            "scope": row.scope,
            "action": row.action,
            "enabled": row.enabled,
        }),
    )
    .await?;
    Ok(Json(RuleDto::from(row)))
}

/// `PUT /api/v1/admin/moderation-rules/{id}` — any subset of the fields.
async fn update(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Body(form): Body<RuleForm>,
) -> ApiResult<Json<RuleDto>> {
    auth.require_admin("admin:write")?;
    let existing = load(&state, &id).await?;
    let mut fields = Fields::from_row(&existing);
    if let Some(value) = form.name {
        fields.name = value;
    }
    if let Some(value) = form.pattern {
        fields.pattern = value;
    }
    if let Some(value) = form.pattern_kind {
        fields.pattern_kind = value;
    }
    if let Some(value) = form.scope {
        fields.scope = value;
    }
    if let Some(value) = form.action {
        fields.action = value;
    }
    if let Some(value) = form.enabled {
        fields.enabled = value;
    }
    let fields = checked(fields)?;
    let row = store_rules::update(
        state.store().pool(),
        &id,
        &store_rules::RuleFields {
            name: &fields.name,
            pattern: &fields.pattern,
            pattern_kind: &fields.pattern_kind,
            scope: &fields.scope,
            action: &fields.action,
            enabled: fields.enabled,
        },
    )
    .await?
    .ok_or_else(|| ApiError::not_found("that rule does not exist"))?;
    audit_write_detail(
        &state,
        &auth,
        "update_moderation_rule",
        "moderation_rule",
        &row.id,
        json!({
            "name": row.name,
            "pattern": row.pattern,
            "pattern_kind": row.pattern_kind,
            "scope": row.scope,
            "action": row.action,
            "enabled": row.enabled,
        }),
    )
    .await?;
    Ok(Json(RuleDto::from(row)))
}

/// `DELETE /api/v1/admin/moderation-rules/{id}`
///
/// The rule goes; what it did does not. Fire history lives in `audit_log.detail` and in
/// the queue entries it opened, both of which keep the id and the name.
async fn delete_rule(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    auth.require_admin("admin:write")?;
    let existing = load(&state, &id).await?;
    if !store_rules::delete(state.store().pool(), &id).await? {
        return Err(ApiError::not_found("that rule does not exist"));
    }
    audit_write_detail(
        &state,
        &auth,
        "delete_moderation_rule",
        "moderation_rule",
        &id,
        json!({
            "name": existing.name,
            "pattern": existing.pattern,
            "pattern_kind": existing.pattern_kind,
            "hits": existing.hits,
        }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct DryRunForm {
    #[serde(default)]
    sample: String,
}

/// Where a pattern matched, in the sample the administrator sent.
#[derive(Debug, Serialize)]
pub struct SpanDto {
    pub start: usize,
    pub end: usize,
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct DryRunDto {
    pub rule: DryRunRuleDto,
    pub matched: bool,
    /// `None` when nothing matched — an offset pair of zeros would look like a match.
    pub span: Option<SpanDto>,
    /// What happened, in one sentence: which rule, which span, or that there was none.
    pub reason: String,
    /// How much of the sample was actually scanned, and whether it was cut. The cap is
    /// the one ingest uses, so a test against a 100 KiB post answers the same way
    /// delivery would.
    pub scanned_bytes: usize,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct DryRunRuleDto {
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub pattern_kind: String,
    pub scope: String,
    pub action: String,
    pub enabled: bool,
}

/// `POST /api/v1/admin/moderation-rules/{id}/dry-run`
///
/// Runs the rule against `sample` and writes nothing: no `hits` increment, no audit row,
/// no report. A disabled rule is still tested, because the point is to check it before
/// enabling it; `rule.enabled` in the answer says whether ingest would currently apply it.
async fn dry_run(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Body(form): Body<DryRunForm>,
) -> ApiResult<Json<DryRunDto>> {
    auth.require_admin("admin:read")?;
    let rule = load(&state, &id).await?;
    let scanned = store_rules::scan_text(&form.sample);
    let hit = store_rules::test(&rule.pattern_kind, &rule.pattern, &form.sample)
        .map_err(|error| ApiError::unprocessable(error.to_string()))?;
    let (matched, span, reason) = match hit {
        Some(hit) => (
            true,
            Some(SpanDto {
                start: hit.start,
                end: hit.end,
                text: hit.excerpt.clone(),
            }),
            format!(
                "rule \"{}\" ({}) matched bytes {}..{}: \"{}\"",
                rule.name, rule.pattern_kind, hit.start, hit.end, hit.excerpt
            ),
        ),
        None => (
            false,
            None,
            format!(
                "rule \"{}\" ({}) did not match the sample",
                rule.name, rule.pattern_kind
            ),
        ),
    };
    Ok(Json(DryRunDto {
        rule: DryRunRuleDto {
            id: rule.id,
            name: rule.name,
            pattern: rule.pattern,
            pattern_kind: rule.pattern_kind,
            scope: rule.scope,
            action: rule.action,
            enabled: rule.enabled,
        },
        matched,
        span,
        reason,
        scanned_bytes: scanned.len(),
        truncated: scanned.len() < form.sample.len(),
    }))
}

async fn load(state: &AppState, id: &str) -> ApiResult<RuleRow> {
    store_rules::rule(state.store().pool(), id)
        .await?
        .ok_or_else(|| ApiError::not_found("that rule does not exist"))
}

/// Trims and validates a rule before it reaches SQL.
///
/// This is the only door a pattern comes through, so it is where the three limits that
/// keep ingest bounded are enforced for people: a name that fits a report body, a kind and
/// scope and action from their closed sets, and a pattern that compiles and is short
/// enough to be run on every delivery.
fn checked(mut fields: Fields) -> ApiResult<Fields> {
    fields.name = fields.name.trim().to_owned();
    if fields.name.is_empty() {
        return Err(ApiError::unprocessable("a rule needs a name"));
    }
    if fields.name.chars().count() > NAME_MAX_CHARS {
        return Err(ApiError::unprocessable(format!(
            "the name is longer than {NAME_MAX_CHARS} characters"
        )));
    }
    fields.pattern = fields.pattern.trim().to_owned();
    let pattern_kind = fields.pattern_kind.trim().to_ascii_lowercase();
    let scope = fields.scope.trim().to_ascii_lowercase();
    let action = fields.action.trim().to_ascii_lowercase();
    if !store_rules::SCOPES.contains(&scope.as_str()) {
        return Err(ApiError::unprocessable(
            "scope must be one of inbound, local, both",
        ));
    }
    if !store_rules::ACTIONS.contains(&action.as_str()) {
        return Err(ApiError::unprocessable(
            "action must be one of flag, silence, suspend",
        ));
    }
    if !store_rules::KINDS.contains(&pattern_kind.as_str()) {
        return Err(ApiError::unprocessable(
            "pattern_kind must be one of keyword, regex, domain",
        ));
    }
    // Every error already names what is wrong (and, for a regex, where), so the message
    // is passed through rather than reworded here.
    store_rules::validate_pattern(&pattern_kind, &fields.pattern)
        .map_err(|error: PatternError| ApiError::unprocessable(error.to_string()))?;
    fields.pattern_kind = pattern_kind;
    fields.scope = scope;
    fields.action = action;
    Ok(fields)
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/moderation-rules", get(list).post(create))
        .route(
            "/api/v1/admin/moderation-rules/{id}",
            get(one).put(update).delete(delete_rule),
        )
        .route("/api/v1/admin/moderation-rules/{id}/dry-run", post(dry_run))
}
