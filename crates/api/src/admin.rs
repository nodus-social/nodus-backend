//! Administrator alert endpoints.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Form, Json, Router};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use serde_json::json;

use nodus_server_core::limits::PAGE_MAX;
use nodus_server_store::alerts;
use nodus_server_store::moderation::{self, Action, NewDomainBlock, NewReport};

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

#[derive(Debug, Deserialize)]
struct StateQuery {
    #[serde(default = "open_state")]
    state: String,
    #[serde(default = "default_limit")]
    limit: i64,
}

fn open_state() -> String {
    "open".to_owned()
}

#[derive(Debug, Serialize)]
struct ReportDto {
    id: String,
    action_taken: bool,
    category: String,
    comment: String,
    created_at: chrono::DateTime<chrono::Utc>,
    target_account: Option<crate::dto::AccountDto>,
    statuses: Vec<serde_json::Value>,
}

async fn report_dto(state: &AppState, row: moderation::ReportRow) -> ApiResult<ReportDto> {
    let target =
        nodus_server_store::accounts::by_id(state.store().pool(), &row.target_account_id).await?;
    Ok(ReportDto {
        id: row.id,
        action_taken: row.action_taken,
        category: row.category,
        comment: row.comment,
        created_at: row.created_at,
        target_account: target
            .as_ref()
            .map(|account| crate::dto::AccountDto::from_row(account, state.instance())),
        statuses: Vec::new(),
    })
}

async fn reports(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<StateQuery>,
) -> ApiResult<Json<Vec<ReportDto>>> {
    administrator(&auth)?;
    let rows = moderation::reports(
        state.store().pool(),
        &query.state,
        query.limit.clamp(1, i64::from(PAGE_MAX)),
    )
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(report_dto(&state, row).await?);
    }
    Ok(Json(out))
}

async fn resolve_report(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<ReportDto>> {
    administrator(&auth)?;
    let row = moderation::set_report_state(state.store().pool(), &id, "resolved")
        .await?
        .ok_or_else(|| ApiError::not_found("report does not exist"))?;
    moderation::audit(
        state.store().pool(),
        &auth.0.account.id,
        "resolve_report",
        "report",
        Some(&id),
        &json!({}),
    )
    .await?;
    Ok(Json(report_dto(&state, row).await?))
}

async fn reopen_report(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<ReportDto>> {
    administrator(&auth)?;
    let row = moderation::set_report_state(state.store().pool(), &id, "open")
        .await?
        .ok_or_else(|| ApiError::not_found("report does not exist"))?;
    moderation::audit(
        state.store().pool(),
        &auth.0.account.id,
        "reopen_report",
        "report",
        Some(&id),
        &json!({}),
    )
    .await?;
    Ok(Json(report_dto(&state, row).await?))
}

#[derive(Debug, Deserialize)]
struct AccountQuery {
    #[serde(default = "local_true")]
    local: bool,
    #[serde(default = "default_limit")]
    limit: i64,
}

const fn local_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
struct AdminAccountDto {
    id: String,
    username: String,
    domain: Option<String>,
    email: Option<String>,
    confirmed: bool,
    approved: bool,
    silenced: bool,
    suspended: bool,
    disabled: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    account: crate::dto::AccountDto,
}

fn admin_account_dto(state: &AppState, row: moderation::AdminAccountRow) -> AdminAccountDto {
    AdminAccountDto {
        id: row.account.id.clone(),
        username: row.account.username.clone(),
        domain: row.account.domain.clone(),
        email: row.email,
        confirmed: true,
        approved: row.account.approved,
        silenced: row.account.silenced_at.is_some(),
        suspended: row.account.suspended_at.is_some(),
        disabled: !row.account.approved,
        created_at: row.account.created_at,
        account: crate::dto::AccountDto::from_row(&row.account, state.instance()),
    }
}

async fn accounts(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<AccountQuery>,
) -> ApiResult<Json<Vec<AdminAccountDto>>> {
    administrator(&auth)?;
    let rows = moderation::admin_accounts(
        state.store().pool(),
        query.local,
        false,
        query.limit.clamp(1, i64::from(PAGE_MAX)),
    )
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| admin_account_dto(&state, row))
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
struct PendingQuery {
    #[serde(default)]
    status: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
}

async fn pending_accounts(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<PendingQuery>,
) -> ApiResult<Json<Vec<AdminAccountDto>>> {
    administrator(&auth)?;
    let pending = query.status.as_deref() == Some("pending");
    let rows = moderation::admin_accounts(
        state.store().pool(),
        true,
        pending,
        query.limit.clamp(1, i64::from(PAGE_MAX)),
    )
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| admin_account_dto(&state, row))
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
struct ActionForm {
    #[serde(rename = "type")]
    kind: String,
}

async fn account_action(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Form(form): Form<ActionForm>,
) -> ApiResult<Json<AdminAccountDto>> {
    administrator(&auth)?;
    let action = Action::parse(&form.kind)
        .ok_or_else(|| ApiError::unprocessable("unknown moderation action"))?;
    let account = moderation::apply_action(state.store().pool(), &id, action)
        .await?
        .ok_or_else(|| ApiError::not_found("account does not exist"))?;
    moderation::audit(
        state.store().pool(),
        &auth.0.account.id,
        form.kind.as_str(),
        "account",
        Some(&id),
        &json!({}),
    )
    .await?;
    let email = sqlx::query_scalar::<_, String>(
        "SELECT email::text FROM account_credential WHERE account_id = $1",
    )
    .bind(&id)
    .fetch_optional(state.store().pool())
    .await?;
    Ok(Json(admin_account_dto(
        &state,
        moderation::AdminAccountRow { account, email },
    )))
}

#[derive(Debug, Serialize)]
struct DomainBlockDto {
    id: String,
    domain: String,
    severity: String,
    reject_media: bool,
    reject_reports: bool,
    obfuscate: bool,
    public_comment: String,
}

async fn domain_blocks(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<Vec<DomainBlockDto>>> {
    administrator(&auth)?;
    let rows = moderation::blocks(state.store().pool(), i64::from(PAGE_MAX)).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| DomainBlockDto {
                id: row.id,
                domain: row.domain,
                severity: row.severity,
                reject_media: row.reject_media,
                reject_reports: row.reject_reports,
                obfuscate: row.obfuscate,
                public_comment: row.public_comment,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
struct DomainForm {
    domain: String,
    #[serde(default = "suspend")]
    severity: String,
    #[serde(default)]
    reject_media: bool,
    #[serde(default)]
    reject_reports: bool,
    #[serde(default)]
    obfuscate: bool,
    #[serde(default)]
    public_comment: String,
}

fn suspend() -> String {
    "suspend".to_owned()
}

async fn create_domain_block(
    State(state): State<AppState>,
    auth: Auth,
    Form(form): Form<DomainForm>,
) -> ApiResult<Json<DomainBlockDto>> {
    administrator(&auth)?;
    if form.domain.trim().is_empty() {
        return Err(ApiError::unprocessable("domain is required"));
    }
    let row = moderation::create_block(
        state.store().pool(),
        &NewDomainBlock {
            domain: form.domain.trim(),
            severity: &form.severity,
            reject_media: form.reject_media,
            reject_reports: form.reject_reports,
            obfuscate: form.obfuscate,
            public_comment: &form.public_comment,
        },
    )
    .await?;
    moderation::audit(
        state.store().pool(),
        &auth.0.account.id,
        "create_domain_block",
        "domain",
        Some(&row.id),
        &json!({ "domain": row.domain, "severity": row.severity }),
    )
    .await?;
    Ok(Json(DomainBlockDto {
        id: row.id,
        domain: row.domain,
        severity: row.severity,
        reject_media: row.reject_media,
        reject_reports: row.reject_reports,
        obfuscate: row.obfuscate,
        public_comment: row.public_comment,
    }))
}

async fn delete_domain_block(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    administrator(&auth)?;
    if !moderation::delete_block(state.store().pool(), &id).await? {
        return Err(ApiError::not_found("domain block does not exist"));
    }
    moderation::audit(
        state.store().pool(),
        &auth.0.account.id,
        "delete_domain_block",
        "domain",
        Some(&id),
        &json!({}),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
struct DomainAllowDto {
    id: String,
    domain: String,
}

async fn domain_allows(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<Vec<DomainAllowDto>>> {
    administrator(&auth)?;
    let rows = moderation::allows(state.store().pool(), i64::from(PAGE_MAX)).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| DomainAllowDto {
                id: row.id,
                domain: row.domain,
            })
            .collect(),
    ))
}

async fn create_domain_allow(
    State(state): State<AppState>,
    auth: Auth,
    Form(form): Form<DomainForm>,
) -> ApiResult<Json<DomainAllowDto>> {
    administrator(&auth)?;
    if form.domain.trim().is_empty() {
        return Err(ApiError::unprocessable("domain is required"));
    }
    let row = moderation::create_allow(state.store().pool(), form.domain.trim()).await?;
    moderation::audit(
        state.store().pool(),
        &auth.0.account.id,
        "create_domain_allow",
        "domain",
        Some(&row.id),
        &json!({ "domain": row.domain }),
    )
    .await?;
    Ok(Json(DomainAllowDto {
        id: row.id,
        domain: row.domain,
    }))
}

async fn delete_domain_allow(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    administrator(&auth)?;
    if !moderation::delete_allow(state.store().pool(), &id).await? {
        return Err(ApiError::not_found("domain allow does not exist"));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct MeasuresRequest {
    keys: Vec<String>,
    start_at: String,
    end_at: String,
}

#[derive(Debug, Serialize)]
struct MeasurePointDto {
    date: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct MeasureDto {
    key: String,
    total: Option<String>,
    previous_total: Option<String>,
    data: Vec<MeasurePointDto>,
}

async fn measures(
    State(state): State<AppState>,
    auth: Auth,
    Json(body): Json<MeasuresRequest>,
) -> ApiResult<Json<Vec<MeasureDto>>> {
    administrator(&auth)?;
    let start = NaiveDate::parse_from_str(&body.start_at, "%Y-%m-%d")
        .map_err(|_| ApiError::unprocessable("start_at must be YYYY-MM-DD"))?;
    let end = NaiveDate::parse_from_str(&body.end_at, "%Y-%m-%d")
        .map_err(|_| ApiError::unprocessable("end_at must be YYYY-MM-DD"))?;
    let mut out = Vec::with_capacity(body.keys.len());
    for key in body.keys {
        let rows = moderation::measure(state.store().pool(), &key, start, end).await?;
        let total: i64 = rows.iter().map(|row| row.value).sum();
        out.push(MeasureDto {
            key,
            total: Some(total.to_string()),
            previous_total: None,
            data: rows
                .into_iter()
                .map(|row| MeasurePointDto {
                    date: row.date.format("%Y-%m-%d").to_string(),
                    value: row.value.to_string(),
                })
                .collect(),
        });
    }
    Ok(Json(out))
}

#[derive(Debug, Serialize)]
struct AuditDto {
    id: String,
    actor_id: Option<String>,
    action: String,
    target_type: String,
    target_id: Option<String>,
    detail: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn audit_log(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<AuditDto>>> {
    administrator(&auth)?;
    let rows = moderation::audit_page(state.store().pool(), 100).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| AuditDto {
                id: row.id,
                actor_id: row.actor_id,
                action: row.action,
                target_type: row.target_type,
                target_id: row.target_id,
                detail: row.detail,
                created_at: row.created_at,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
struct NewReportForm {
    account_id: String,
    #[serde(default)]
    status_ids: Option<String>,
    #[serde(default = "other")]
    category: String,
    #[serde(default)]
    comment: String,
}

fn other() -> String {
    "other".to_owned()
}

async fn create_report(
    State(state): State<AppState>,
    auth: Auth,
    Form(form): Form<NewReportForm>,
) -> ApiResult<Json<ReportDto>> {
    if auth.0.account.id == form.account_id {
        return Err(ApiError::unprocessable("you cannot report yourself"));
    }
    let status_ids: Vec<String> = form
        .status_ids
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .collect();
    let row = moderation::create_report(
        state.store().pool(),
        &NewReport {
            account_id: &auth.0.account.id,
            target_account_id: &form.account_id,
            status_ids: &status_ids,
            category: &form.category,
            comment: &form.comment,
        },
    )
    .await?;
    moderation::audit(
        state.store().pool(),
        &auth.0.account.id,
        "create_report",
        "account",
        Some(&form.account_id),
        &json!({ "report": row.id }),
    )
    .await?;
    Ok(Json(report_dto(&state, row).await?))
}

/// Admin and moderation routes.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/alerts", get(list))
        .route("/api/v1/admin/alerts/{id}/ack", post(acknowledge))
        .route("/api/v1/admin/accounts/{id}/lossless", post(set_lossless))
        .route("/api/v1/admin/reports", get(reports))
        .route("/api/v1/admin/reports/{id}/resolve", post(resolve_report))
        .route("/api/v1/admin/reports/{id}/reopen", post(reopen_report))
        .route("/api/v1/admin/accounts", get(accounts))
        .route("/api/v1/admin/accounts/{id}/action", post(account_action))
        .route("/api/v2/admin/accounts", get(pending_accounts))
        .route(
            "/api/v1/admin/domain_blocks",
            get(domain_blocks).post(create_domain_block),
        )
        .route(
            "/api/v1/admin/domain_blocks/{id}",
            delete(delete_domain_block),
        )
        .route(
            "/api/v1/admin/domain_allows",
            get(domain_allows).post(create_domain_allow),
        )
        .route(
            "/api/v1/admin/domain_allows/{id}",
            delete(delete_domain_allow),
        )
        .route("/api/v1/admin/measures", post(measures))
        .route("/api/v1/admin/audit", get(audit_log))
        .route("/api/v1/reports", post(create_report))
}
