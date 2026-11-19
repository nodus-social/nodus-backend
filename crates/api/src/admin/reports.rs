//! The report queue.
//!
//! A report is a person saying "look at this". The queue is therefore ordered by what a
//! moderator needs next: untouched reports first, then whatever they claimed, with the
//! statuses and the account inline so triage does not need a second request per row.

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use nodus_server_store::moderation::{self, NewReport, ReportRow};
use nodus_server_store::rules as store_rules;
use nodus_server_store::{accounts, statuses};

use super::Body;
use crate::auth::Auth;
use crate::dto::{AccountDto, StatusDto};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

use super::{audit_write_detail, offset, page};
use super::{check_batch, BulkFailure, BulkItemDto, BulkResponseDto};

#[derive(Debug, Serialize)]
pub struct ReportDto {
    pub id: String,
    pub state: String,
    pub category: String,
    pub comment: String,
    pub rule_ids: Vec<String>,
    /// The cited rules with their current text, in the order they were cited.
    pub rules: Vec<ReportRuleDto>,
    /// Cited ids whose rule has since been deleted. The ids above stay in `rule_ids`
    /// either way: a report is history, and history is not rewritten by a later delete.
    pub missing_rule_ids: Vec<String>,
    pub action_taken: bool,
    pub action_taken_note: String,
    pub action_taken_at: Option<DateTime<Utc>>,
    pub action_taken_by: Option<AccountDto>,
    pub assigned_account_id: Option<String>,
    pub assigned_account: Option<AccountDto>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub reporter: Option<AccountDto>,
    pub target_account: Option<AccountDto>,
    pub statuses: Vec<StatusDto>,
}

/// One rule a report cites, as the moderation payload carries it.
#[derive(Debug, Serialize)]
pub struct ReportRuleDto {
    pub id: String,
    /// `None` once the rule was deleted — the citation itself is kept.
    pub text: Option<String>,
}

/// Builds one report for the queue. Statuses are hydrated in order: a report is about a
/// handful of posts, and a moderator reads them, so the cost is worth paying once.
pub(super) async fn report_dto(state: &AppState, row: ReportRow) -> ApiResult<ReportDto> {
    let pool = state.store().pool();
    let mut hydrated = Vec::with_capacity(row.status_ids.len());
    for id in &row.status_ids {
        if let Some(status) = statuses::by_id(pool, id).await? {
            hydrated.push(crate::statuses::dto(state, &status, None).await?);
        }
    }
    // The instance files some reports itself (a content-set match), so a report may have
    // no reporter account; the console renders the field as optional either way.
    let reporter = match row.account_id.as_deref() {
        Some(id) => accounts::by_id(pool, id).await?,
        None => None,
    };
    let target = accounts::by_id(pool, &row.target_account_id).await?;
    let assigned = match row.assigned_account_id.as_deref() {
        Some(id) => accounts::by_id(pool, id).await?,
        None => None,
    };
    let action_by = match row.action_taken_by_account_id.as_deref() {
        Some(id) => accounts::by_id(pool, id).await?,
        None => None,
    };
    // A citation outlives the rule it names. Resolve what still exists and mark the rest
    // rather than dropping them: the console has to be able to say "rule 4 (deleted)".
    let cited = store_rules::by_ids(pool, &row.rule_ids).await?;
    let mut rules = Vec::with_capacity(row.rule_ids.len());
    let mut missing_rule_ids = Vec::new();
    for id in &row.rule_ids {
        match cited.iter().find(|rule| &rule.id == id) {
            Some(rule) => rules.push(ReportRuleDto {
                id: id.clone(),
                text: Some(rule.text.clone()),
            }),
            None => {
                missing_rule_ids.push(id.clone());
                rules.push(ReportRuleDto {
                    id: id.clone(),
                    text: None,
                });
            }
        }
    }
    let instance = state.instance();
    Ok(ReportDto {
        id: row.id,
        state: row.state,
        category: row.category,
        comment: row.comment,
        rule_ids: row.rule_ids,
        rules,
        missing_rule_ids,
        action_taken: row.action_taken,
        action_taken_note: row.action_taken_note,
        action_taken_at: row.action_taken_at,
        action_taken_by: action_by.map(|account| AccountDto::from_row(&account, instance)),
        assigned_account_id: row.assigned_account_id,
        assigned_account: assigned.map(|account| AccountDto::from_row(&account, instance)),
        created_at: row.created_at,
        updated_at: row.updated_at,
        reporter: reporter.map(|account| AccountDto::from_row(&account, instance)),
        target_account: target.map(|account| AccountDto::from_row(&account, instance)),
        statuses: hydrated,
    })
}

#[derive(Debug, Deserialize)]
pub struct ReportQuery {
    state: Option<String>,
    category: Option<String>,
    target_account_id: Option<String>,
    account_id: Option<String>,
    assigned_account_id: Option<String>,
    #[serde(default)]
    unassigned: bool,
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<ReportQuery>,
) -> ApiResult<Json<Vec<ReportDto>>> {
    auth.require_admin("admin:read")?;
    let rows = moderation::reports(
        state.store().pool(),
        &moderation::ReportFilter {
            state: query.state.as_deref().filter(|value| *value != "all"),
            category: query.category.as_deref(),
            target_account_id: query.target_account_id.as_deref(),
            reporter_account_id: query.account_id.as_deref(),
            assigned_account_id: query.assigned_account_id.as_deref(),
            unassigned: query.unassigned,
            limit: page(query.limit),
            offset: offset(query.offset),
        },
    )
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(report_dto(&state, row).await?);
    }
    Ok(Json(out))
}

async fn detail(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<ReportDto>> {
    auth.require_admin("admin:read")?;
    let row = moderation::report(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that report does not exist"))?;
    Ok(Json(report_dto(&state, row).await?))
}

#[derive(Debug, Default, Deserialize)]
pub struct ResolveBody {
    #[serde(default)]
    note: String,
    /// Mastodon's report UI calls this "forward": send the report on to the peer that
    /// hosts the account. Off by default, because the same moderation decision means
    /// different things on different instances and must not leave this one silently.
    #[serde(default)]
    forward_to_peer: bool,
}

async fn resolve(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    body: Option<Json<ResolveBody>>,
) -> ApiResult<Json<ReportDto>> {
    auth.require_admin("admin:write")?;
    let body = body.map(|Json(body)| body).unwrap_or_default();
    let note = body.note;
    // Forwarding happens before the local decision is written: a refused forward must
    // leave the report open so the moderator can pick a different path, and a forward
    // that fails to queue must not look delivered because the report says "resolved".
    if body.forward_to_peer {
        super::forwarded::forward_report(&state, &auth, &id, note.trim()).await?;
    }
    let row =
        moderation::resolve_report(state.store().pool(), &id, &auth.0.account.id, note.trim())
            .await?
            .ok_or_else(|| ApiError::not_found("that report does not exist"))?;
    audit_write_detail(
        &state,
        &auth,
        if note.trim().is_empty() {
            "resolve_report"
        } else {
            "resolve_report_with_note"
        },
        "report",
        &row.id,
        json!({ "note": note.trim() }),
    )
    .await?;
    Ok(Json(report_dto(&state, row).await?))
}

async fn reopen(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<ReportDto>> {
    auth.require_admin("admin:write")?;
    let row = moderation::reopen_report(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that report does not exist"))?;
    audit_write_detail(&state, &auth, "reopen_report", "report", &row.id, json!({})).await?;
    Ok(Json(report_dto(&state, row).await?))
}

#[derive(Debug, Deserialize)]
pub struct AssignBody {
    /// `null` puts the report back in the unclaimed queue.
    account_id: Option<String>,
}

async fn assign(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(body): Json<AssignBody>,
) -> ApiResult<Json<ReportDto>> {
    auth.require_admin("admin:write")?;
    if let Some(account_id) = body.account_id.as_deref() {
        let exists = accounts::by_id(state.store().pool(), account_id)
            .await?
            .is_some();
        if !exists {
            return Err(ApiError::unprocessable("that account does not exist"));
        }
    }
    let row = moderation::assign_report(state.store().pool(), &id, body.account_id.as_deref())
        .await?
        .ok_or_else(|| ApiError::not_found("that report does not exist"))?;
    audit_write_detail(
        &state,
        &auth,
        "assign_report",
        "report",
        &row.id,
        json!({ "account_id": body.account_id }),
    )
    .await?;
    Ok(Json(report_dto(&state, row).await?))
}

// ---------------------------------------------------------------------------------------
// Filing a report
// ---------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct NewReportForm {
    account_id: String,
    /// Comma-separated, which is how both the web client and the SDK send a list in a form.
    #[serde(default)]
    status_ids: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    comment: String,
    /// Comma-separated rule ids the reporter believes were broken.
    #[serde(default)]
    rule_ids: String,
}

fn split_ids(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Keeps the first occurrence of each id, so a client that repeats one does not make the
/// report cite it twice.
fn unique_ids(ids: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    ids.into_iter()
        .filter(|id| seen.insert(id.clone()))
        .collect()
}

/// The public half: anyone signed in can file a report.
async fn create(
    State(state): State<AppState>,
    auth: Auth,
    Body(form): Body<NewReportForm>,
) -> ApiResult<Json<ReportDto>> {
    if form.account_id.trim().is_empty() {
        return Err(ApiError::unprocessable("account_id is required"));
    }
    if form.account_id == auth.0.account.id {
        return Err(ApiError::unprocessable("you cannot report yourself"));
    }
    let target = accounts::by_id(state.store().pool(), &form.account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("that account does not exist"))?;
    let status_ids = split_ids(&form.status_ids);
    let rule_ids = unique_ids(split_ids(&form.rule_ids));
    // A citation is checked here, where the reporter's request can still be answered: an
    // id that names nothing is a mistake in this request, and blaming it on the rule is
    // more useful than storing a reference nobody can resolve.
    let existing = store_rules::existing_ids(state.store().pool(), &rule_ids).await?;
    if let Some(unknown) = rule_ids.iter().find(|id| !existing.contains(id)) {
        return Err(ApiError::unprocessable(format!(
            "rule {unknown} does not exist; cite one of the ids from /api/v1/instance/rules"
        )));
    }
    let stored_rules: Vec<String> = rule_ids
        .into_iter()
        .filter(|id| existing.contains(id))
        .collect();
    let category = if form.category.trim().is_empty() {
        "other"
    } else {
        form.category.trim()
    };
    let row = moderation::create_report(
        state.store().pool(),
        &NewReport {
            account_id: Some(&auth.0.account.id),
            target_account_id: &target.id,
            status_ids: &status_ids,
            category,
            comment: form.comment.trim(),
            rule_ids: &stored_rules,
            activity_uri: None,
        },
    )
    .await?;
    audit_write_detail(
        &state,
        &auth,
        "create_report",
        "account",
        &target.id,
        json!({ "report": row.id }),
    )
    .await?;
    // A moderator filing the report is the moment the instance already decided there is
    // something to say, so send it without a second click. Anyone else's report goes to
    // the local queue and is forwarded later, by a moderator, through `resolve`.
    // Best effort on purpose: the report exists either way, and a refusal is not a reason
    // to reject a member's report.
    if auth.0.account.staff_role != "none" && !target.local {
        if let Err(error) = super::forwarded::forward_report(&state, &auth, &row.id, "").await {
            tracing::warn!(
                report = %row.id,
                error = %error.message(),
                "could not forward a staff report to its peer"
            );
        }
    }
    Ok(Json(report_dto(&state, row).await?))
}

#[derive(Debug, Deserialize)]
pub struct BulkReportForm {
    #[serde(default)]
    ids: Vec<String>,
    action: String,
    /// Required by `assign`, ignored otherwise; `null` leaves the report unclaimed.
    assignee_id: Option<String>,
    /// The decision's reason, recorded exactly as the single-report route records it.
    #[serde(default)]
    note: String,
}

/// Applies one queue action and writes its audit row on the request's transaction.
async fn apply_bulk_report(
    conn: &mut sqlx::PgConnection,
    auth: &Auth,
    id: &str,
    action: &str,
    assignee: Option<&str>,
    note: &str,
) -> Result<(), BulkFailure> {
    let missing = || BulkFailure::Rejected("that report does not exist".to_owned());
    let (audit_action, detail) = match action {
        "assign" => {
            if moderation::assign_report_in(conn, id, assignee)
                .await?
                .is_none()
            {
                return Err(missing());
            }
            ("assign_report", json!({ "account_id": assignee }))
        }
        "resolve" => {
            let reviewer = auth.0.account.id.clone();
            if moderation::resolve_report_in(conn, id, &reviewer, note)
                .await?
                .is_none()
            {
                return Err(missing());
            }
            let audit_action = if note.is_empty() {
                "resolve_report"
            } else {
                "resolve_report_with_note"
            };
            (audit_action, json!({ "note": note }))
        }
        _ => {
            if moderation::reopen_report_in(conn, id).await?.is_none() {
                return Err(missing());
            }
            ("reopen_report", json!({}))
        }
    };
    moderation::audit_in(
        conn,
        &auth.0.account.id,
        audit_action,
        "report",
        Some(id),
        &detail,
    )
    .await?;
    Ok(())
}

/// `POST /api/v1/admin/reports/bulk` — claim, close or reopen a selection of reports.
///
/// Same contract as the account batch: one transaction, per-id results, one audit row per
/// report actually changed. An unknown assignee is a request-level mistake (422) because
/// it is the same person for every id in the batch.
async fn bulk_reports(
    State(state): State<AppState>,
    auth: Auth,
    Json(form): Json<BulkReportForm>,
) -> ApiResult<Json<BulkResponseDto>> {
    auth.require_admin("admin:write")?;
    check_batch(&form.ids, "report")?;
    let action = form.action.trim();
    if !matches!(action, "assign" | "resolve" | "reopen") {
        return Err(ApiError::unprocessable(format!(
            "unknown report action: {action}; use assign, resolve or reopen"
        )));
    }
    let assignee = form
        .assignee_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if action == "assign" {
        if let Some(assignee) = assignee {
            let exists = accounts::by_id(state.store().pool(), assignee)
                .await?
                .is_some();
            if !exists {
                return Err(ApiError::unprocessable("that account does not exist"));
            }
        }
    }
    let note = form.note.trim();
    let mut tx = state.store().pool().begin().await?;
    let mut results = Vec::with_capacity(form.ids.len());
    let mut applied = 0i64;
    for id in &form.ids {
        match apply_bulk_report(&mut tx, &auth, id, action, assignee, note).await {
            Ok(()) => {
                applied += 1;
                results.push(BulkItemDto {
                    id: id.clone(),
                    ok: true,
                    error: None,
                });
            }
            Err(BulkFailure::Rejected(message)) => results.push(BulkItemDto {
                id: id.clone(),
                ok: false,
                error: Some(message),
            }),
            Err(BulkFailure::Database(error)) => return Err(error.into()),
        }
    }
    tx.commit().await?;
    Ok(Json(BulkResponseDto { results, applied }))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/reports", get(list))
        .route("/api/v1/admin/reports/bulk", post(bulk_reports))
        .route("/api/v1/admin/reports/{id}", get(detail))
        .route("/api/v1/admin/reports/{id}/resolve", post(resolve))
        .route("/api/v1/admin/reports/{id}/reopen", post(reopen))
        .route("/api/v1/admin/reports/{id}/assign", post(assign))
}

/// Routes outside the admin namespace: filing a report is not an administrative act.
pub fn public_router() -> Router<AppState> {
    Router::new().route("/api/v1/reports", post(create))
}
