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
    let reporter = accounts::by_id(pool, &row.account_id).await?;
    let target = accounts::by_id(pool, &row.target_account_id).await?;
    let assigned = match row.assigned_account_id.as_deref() {
        Some(id) => accounts::by_id(pool, id).await?,
        None => None,
    };
    let action_by = match row.action_taken_by_account_id.as_deref() {
        Some(id) => accounts::by_id(pool, id).await?,
        None => None,
    };
    let instance = state.instance();
    Ok(ReportDto {
        id: row.id,
        state: row.state,
        category: row.category,
        comment: row.comment,
        rule_ids: row.rule_ids,
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
}

async fn resolve(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    body: Option<Json<ResolveBody>>,
) -> ApiResult<Json<ReportDto>> {
    auth.require_admin("admin:write")?;
    let note = body.map(|Json(body)| body.note).unwrap_or_default();
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
    let category = if form.category.trim().is_empty() {
        "other"
    } else {
        form.category.trim()
    };
    let row = moderation::create_report(
        state.store().pool(),
        &NewReport {
            account_id: &auth.0.account.id,
            target_account_id: &target.id,
            status_ids: &status_ids,
            category,
            comment: form.comment.trim(),
            rule_ids: &split_ids(&form.rule_ids),
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
