//! The administration API.
//!
//! Every route here is behind an `admin:read` or `admin:write` scope, and every handler
//! checks it first: the grant is what a moderator signs in with, so a route that forgot
//! the check would be a hole in the only wall there is.
//!
//! The surface is grouped by what an administrator is looking at, not by table: the report
//! queue, the account directory, federation, scanning, and the read-only machinery
//! (overview, measures, audit, alerts, warning presets).

mod accounts;
mod federation;
mod reports;
mod scanners;
mod topology;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use nodus_server_core::limits::PAGE_MAX;
use nodus_server_store::alerts;
use nodus_server_store::moderation::{self, AuditFilter};

use crate::auth::Auth;
use crate::dto::AccountDto;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Routes that are not behind an admin scope: reporting a post, and the endpoints a
/// scanner service uses to fetch its own configuration.
pub fn public_router() -> Router<AppState> {
    reports::public_router().merge(scanners::node_router())
}

/// One page, whatever the caller asked for, bounded by what the instance will serve.
fn page(limit: Option<i64>) -> i64 {
    limit.unwrap_or(50).clamp(1, i64::from(PAGE_MAX))
}

fn offset(value: Option<i64>) -> i64 {
    value.unwrap_or(0).max(0)
}

/// A request body that may arrive as a form or as JSON.
///
/// Mastodon clients send forms; anything written against this instance sends JSON. Both
/// deserialize into the same struct, so a handler never has to care which it got.
pub struct Body<T>(pub T);

impl<T> axum::extract::FromRequest<AppState> for Body<T>
where
    T: serde::de::DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(
        request: axum::extract::Request,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let json = request
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/json"));
        let bytes = axum::body::to_bytes(request.into_body(), 256 * 1024)
            .await
            .map_err(|_| ApiError::unprocessable("could not read the request body"))?;
        let decoded = if json {
            serde_json::from_slice(&bytes).map_err(|error| {
                ApiError::unprocessable(format!("that JSON body does not fit: {error}"))
            })
        } else {
            serde_urlencoded::from_bytes(&bytes).map_err(|error| {
                ApiError::unprocessable(format!("that form body does not fit: {error}"))
            })
        };
        decoded.map(Self)
    }
}

// ---------------------------------------------------------------------------------------
// Who am I, and what is waiting
// ---------------------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct CountsDto {
    pub open_reports: i64,
    pub unassigned_reports: i64,
    pub pending_accounts: i64,
    pub open_flags: i64,
}

#[derive(Debug, Serialize)]
pub struct ScanSummaryDto {
    pub scanners: i64,
    pub enabled: i64,
    pub rules: i64,
    pub assets: i64,
    /// Scans waiting for a scanner to answer. A number that keeps growing means a scanner
    /// is down, and no moderator should have to guess that from an empty queue.
    pub queued: i64,
}

/// What the console needs before it renders anything: who the grant belongs to, what that
/// account may do, and how much work is waiting.
#[derive(Debug, Serialize)]
pub struct MetaDto {
    pub account: AccountDto,
    /// The account behind the grant is an administrator, not merely a moderator.
    pub staff: bool,
    pub scopes: Vec<String>,
    pub counts: CountsDto,
    pub domain: String,
    pub base_url: String,
    pub version: String,
    pub scanning: ScanSummaryDto,
    /// Per-label severities, so the console can explain a flag without a second request.
    pub severities: Vec<SeverityCountDto>,
}

#[derive(Debug, Serialize)]
pub struct SeverityCountDto {
    pub severity: String,
    pub count: i64,
}

async fn meta(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<MetaDto>> {
    auth.require_admin("admin:read")?;
    let pool = state.store().pool();
    let overview = moderation::overview(pool).await?;
    let scanners = nodus_server_store::scanners::scanners(pool).await?;
    let rules = nodus_server_store::scanners::rules_all(pool).await?;
    let assets = nodus_server_store::scanners::assets(pool).await?;
    let open_flags = nodus_server_store::scanners::open_flags(pool).await?;
    let queued: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM scan WHERE state IN ('pending', 'running')",
    )
    .fetch_one(pool)
    .await?;
    let flags =
        nodus_server_store::scanners::flags(pool, Some("open"), i64::from(PAGE_MAX) * 4, 0).await?;
    let mut severities: Vec<SeverityCountDto> = Vec::new();
    for flag in flags {
        match severities
            .iter_mut()
            .find(|entry| entry.severity == flag.severity)
        {
            Some(entry) => entry.count += 1,
            None => severities.push(SeverityCountDto {
                severity: flag.severity,
                count: 1,
            }),
        }
    }
    Ok(Json(MetaDto {
        account: AccountDto::from_row(&auth.0.account, state.instance()),
        staff: auth.0.account.admin,
        scopes: auth.0.scopes.clone(),
        counts: CountsDto {
            open_reports: overview.open_reports,
            unassigned_reports: overview.unassigned_reports,
            pending_accounts: overview.pending_accounts,
            open_flags,
        },
        domain: state.instance().domain.clone(),
        base_url: state.instance().base_url.clone(),
        version: state.instance().version.clone(),
        scanning: ScanSummaryDto {
            scanners: i64::try_from(scanners.len()).unwrap_or(i64::MAX),
            enabled: i64::try_from(scanners.iter().filter(|scanner| scanner.enabled).count())
                .unwrap_or(i64::MAX),
            rules: i64::try_from(rules.len()).unwrap_or(i64::MAX),
            assets: i64::try_from(assets.len()).unwrap_or(i64::MAX),
            queued,
        },
        severities,
    }))
}

// ---------------------------------------------------------------------------------------
// Overview and measures
// ---------------------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct OverviewDto {
    pub accounts: i64,
    pub local_accounts: i64,
    pub active_accounts: i64,
    pub statuses: i64,
    pub open_reports: i64,
    pub resolved_reports: i64,
    pub unassigned_reports: i64,
    pub pending_accounts: i64,
    pub silences: i64,
    pub suspensions: i64,
    pub domain_blocks: i64,
    pub email_domain_blocks: i64,
    pub staff: i64,
}

async fn overview(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<OverviewDto>> {
    auth.require_admin("admin:read")?;
    let row = moderation::overview(state.store().pool()).await?;
    Ok(Json(OverviewDto {
        accounts: row.accounts,
        local_accounts: row.local_accounts,
        active_accounts: row.active_accounts,
        statuses: row.statuses,
        open_reports: row.open_reports,
        resolved_reports: row.resolved_reports,
        unassigned_reports: row.unassigned_reports,
        pending_accounts: row.pending_accounts,
        silences: row.silences,
        suspensions: row.suspensions,
        domain_blocks: row.domain_blocks,
        email_domain_blocks: row.email_domain_blocks,
        staff: row.staff,
    }))
}

#[derive(Debug, Deserialize)]
pub struct MeasureQuery {
    /// Comma-separated keys; unknown keys are dropped rather than failing the request, so
    /// a client asking for a measure this build does not have still renders the rest.
    keys: Option<String>,
    days: Option<i64>,
    start_at: Option<String>,
    end_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MeasurePointDto {
    pub date: String,
    pub value: i64,
}

#[derive(Debug, Serialize)]
pub struct MeasureDto {
    pub key: String,
    pub total: i64,
    /// The same span immediately before, so a chart can say "up from 12" without a second
    /// request.
    pub previous_total: i64,
    pub data: Vec<MeasurePointDto>,
}

const DEFAULT_MEASURES: &str = "new_users,statuses,active_user_count,interactions,\
     opened_reports,resolved_reports,open_reports";

const MAX_SPAN_DAYS: i64 = 366;

async fn measures(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<MeasureQuery>,
) -> ApiResult<Json<Vec<MeasureDto>>> {
    auth.require_admin("admin:read")?;
    let end = query
        .end_at
        .as_deref()
        .and_then(|value| NaiveDate::parse_from_str(value, "%Y-%m-%d").ok())
        .unwrap_or_else(|| chrono::Utc::now().date_naive());
    let days = query.days.unwrap_or(7).clamp(1, MAX_SPAN_DAYS);
    let start = query
        .start_at
        .as_deref()
        .and_then(|value| NaiveDate::parse_from_str(value, "%Y-%m-%d").ok())
        .unwrap_or_else(|| end - chrono::Duration::days(days - 1));
    if start > end {
        return Err(ApiError::unprocessable("start_at is after end_at"));
    }
    let span = (end - start).num_days() + 1;
    let previous_end = start - chrono::Duration::days(1);
    let previous_start = previous_end - chrono::Duration::days(span - 1);

    let keys: Vec<String> = query
        .keys
        .as_deref()
        .unwrap_or(DEFAULT_MEASURES)
        .split(',')
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(str::to_owned)
        .collect();

    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        let data = moderation::measure(state.store().pool(), &key, start, end).await?;
        if data.is_empty() && !DEFAULT_MEASURES.contains(&key) {
            continue;
        }
        let previous =
            moderation::measure(state.store().pool(), &key, previous_start, previous_end).await?;
        out.push(MeasureDto {
            key,
            total: data.iter().map(|point| point.value).sum(),
            previous_total: previous.iter().map(|point| point.value).sum(),
            data: data
                .into_iter()
                .map(|point| MeasurePointDto {
                    date: point.date.format("%Y-%m-%d").to_string(),
                    value: point.value,
                })
                .collect(),
        });
    }
    Ok(Json(out))
}

// ---------------------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    action: Option<String>,
    target_type: Option<String>,
    actor_id: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct AuditDto {
    pub id: String,
    pub actor_id: Option<String>,
    pub action: String,
    pub target_type: String,
    pub target_id: Option<String>,
    pub detail: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

async fn audit(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<Vec<AuditDto>>> {
    auth.require_admin("admin:read")?;
    let rows = moderation::audit_page(
        state.store().pool(),
        &AuditFilter {
            action: query.action.as_deref(),
            target_type: query.target_type.as_deref(),
            actor_id: query.actor_id.as_deref(),
            limit: page(query.limit),
            offset: offset(query.offset),
        },
    )
    .await?;
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

// ---------------------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AlertQuery {
    #[serde(default)]
    unacknowledged: bool,
    limit: Option<i64>,
}

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

async fn alerts_list(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<AlertQuery>,
) -> ApiResult<Json<Vec<AlertDto>>> {
    auth.require_admin("admin:read")?;
    let rows = alerts::recent(
        state.store().pool(),
        page(query.limit),
        query.unacknowledged,
    )
    .await?;
    Ok(Json(rows.into_iter().map(AlertDto::from).collect()))
}

async fn alert_acknowledge(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<AlertDto>> {
    auth.require_admin("admin:write")?;
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

// ---------------------------------------------------------------------------------------
// Warning presets
// ---------------------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct WarningPresetDto {
    pub id: String,
    pub title: String,
    pub text: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<moderation::WarningPresetRow> for WarningPresetDto {
    fn from(row: moderation::WarningPresetRow) -> Self {
        Self {
            id: row.id,
            title: row.title,
            text: row.text,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct WarningForm {
    title: String,
    text: String,
}

async fn warnings(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<Vec<WarningPresetDto>>> {
    auth.require_admin("admin:read")?;
    let rows = moderation::warning_presets(state.store().pool()).await?;
    Ok(Json(rows.into_iter().map(WarningPresetDto::from).collect()))
}

async fn create_warning(
    State(state): State<AppState>,
    auth: Auth,
    Json(form): Json<WarningForm>,
) -> ApiResult<Json<WarningPresetDto>> {
    auth.require_admin("admin:write")?;
    let title = form.title.trim();
    if title.is_empty() || form.text.trim().is_empty() {
        return Err(ApiError::unprocessable("a preset needs a title and a text"));
    }
    let row =
        moderation::create_warning_preset(state.store().pool(), title, form.text.trim()).await?;
    audit_write(
        &state,
        &auth,
        "create_warning_preset",
        "warning_preset",
        &row.id,
    )
    .await?;
    Ok(Json(WarningPresetDto::from(row)))
}

async fn update_warning(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(form): Json<WarningForm>,
) -> ApiResult<Json<WarningPresetDto>> {
    auth.require_admin("admin:write")?;
    let row = moderation::update_warning_preset(
        state.store().pool(),
        &id,
        form.title.trim(),
        form.text.trim(),
    )
    .await?
    .ok_or_else(|| ApiError::not_found("that preset does not exist"))?;
    audit_write(
        &state,
        &auth,
        "update_warning_preset",
        "warning_preset",
        &row.id,
    )
    .await?;
    Ok(Json(WarningPresetDto::from(row)))
}

async fn delete_warning(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    auth.require_admin("admin:write")?;
    if !moderation::delete_warning_preset(state.store().pool(), &id).await? {
        return Err(ApiError::not_found("that preset does not exist"));
    }
    audit_write(
        &state,
        &auth,
        "delete_warning_preset",
        "warning_preset",
        &id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------------------

/// Records an administrator's write. The audit log is the only place a moderation decision
/// is accountable after the fact, so every write goes through here.
pub(super) async fn audit_write(
    state: &AppState,
    auth: &Auth,
    action: &str,
    target_type: &str,
    target_id: &str,
) -> ApiResult<()> {
    moderation::audit(
        state.store().pool(),
        &auth.0.account.id,
        action,
        target_type,
        Some(target_id),
        &serde_json::json!({}),
    )
    .await?;
    Ok(())
}

pub(super) fn audit_write_detail<'a>(
    state: &'a AppState,
    auth: &'a Auth,
    action: &'a str,
    target_type: &'a str,
    target_id: &'a str,
    detail: serde_json::Value,
) -> impl std::future::Future<Output = ApiResult<()>> + 'a {
    let pool = state.store().pool().clone();
    let actor = auth.0.account.id.clone();
    let action = action.to_owned();
    let target_type = target_type.to_owned();
    let target_id = target_id.to_owned();
    async move {
        moderation::audit(
            &pool,
            &actor,
            &action,
            &target_type,
            Some(&target_id),
            &detail,
        )
        .await?;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct LosslessBody {
    images: bool,
    videos: bool,
}

async fn set_lossless(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(body): Json<LosslessBody>,
) -> ApiResult<StatusCode> {
    auth.require_admin("admin:write")?;
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

/// Administration and moderation routes.
pub fn router() -> Router<AppState> {
    Router::new()
        .merge(reports::router())
        .merge(accounts::router())
        .merge(federation::router())
        .merge(scanners::router())
        .merge(topology::router())
        .route("/api/v1/admin/meta", get(meta))
        .route("/api/v1/admin/overview", get(overview))
        .route("/api/v1/admin/measures", get(measures))
        .route("/api/v1/admin/audit", get(audit))
        .route("/api/v1/admin/alerts", get(alerts_list))
        .route("/api/v1/admin/alerts/{id}/ack", post(alert_acknowledge))
        .route("/api/v1/admin/accounts/{id}/lossless", post(set_lossless))
        .route(
            "/api/v1/admin/warning_presets",
            get(warnings).post(create_warning),
        )
        .route(
            "/api/v1/admin/warning_presets/{id}",
            put(update_warning).delete(delete_warning),
        )
}
