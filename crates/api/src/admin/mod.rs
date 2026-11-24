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
mod appeals;
/// The block-list transfer surface, which also owns the subscription sweep.
pub mod blocklist;
mod escalation;
mod federation;
mod forwarded;
mod ip_blocks;
mod media;
mod moderation_rules;
mod relays;
mod reports;
mod rules;
mod scanners;
mod settings_transfer;
pub(crate) mod stats;
mod topology;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, NaiveDate, Utc};
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

/// The largest batch one moderation request may carry.
///
/// A moderator selects a page of names, and a console page is a hundred rows at most. A
/// request that looks like a table dump is refused rather than held open for minutes: the
/// whole batch is one transaction, and a transaction that long blocks everyone else writing
/// to `account`. The number is also what makes "one transaction" affordable.
pub(super) const BULK_LIMIT: usize = 100;

/// Why one id in a batch did not go through.
///
/// A rejected id is a fact about that id — usually that it does not exist — and belongs in
/// the per-id results. A database failure is a fact about the request, so it aborts the
/// transaction and the whole batch rolls back.
pub(super) enum BulkFailure {
    Rejected(String),
    Database(sqlx::Error),
}

impl From<sqlx::Error> for BulkFailure {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(Debug, Serialize)]
pub(super) struct BulkItemDto {
    pub id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One account's outcome, keyed the way the account endpoints name an account.
///
/// Reports keep `id` above because a report is not an account; an account batch answers
/// `account_id`, so a console can join a result row to the row the moderator selected
/// without guessing which kind of id it is looking at.
#[derive(Debug, Serialize)]
pub(super) struct AccountBulkItemDto {
    pub account_id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct AccountBulkResponseDto {
    pub results: Vec<AccountBulkItemDto>,
    pub applied: i64,
}

#[derive(Debug, Serialize)]
pub(super) struct BulkResponseDto {
    pub results: Vec<BulkItemDto>,
    pub applied: i64,
}

/// Refuses an empty or oversized batch before anything is touched.
pub(super) fn check_batch(ids: &[String], what: &str) -> ApiResult<()> {
    if ids.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("a batch needs at least one {what} id"),
        ));
    }
    if ids.len() > BULK_LIMIT {
        return Err(ApiError::unprocessable(format!(
            "a batch may name at most {BULK_LIMIT} {what} ids"
        )));
    }
    Ok(())
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
    /// Whether the account behind the grant is staff at all.
    ///
    /// The console's navigation rail asks one question — show the moderation doors or not —
    /// and a moderator and an administrator both answer yes. `role` below is which of those
    /// doors actually opens; the two fields exist because a boolean cannot say "moderator".
    pub staff: bool,
    /// `moderator` or `admin` for staff, `none` otherwise.
    pub role: String,
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
        staff: auth.0.account.staff_role != "none",
        role: auth.0.account.staff_role.clone(),
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
    /// RFC 3339. Inclusive, and honest about the zone or it is a 422.
    since: Option<String>,
    until: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

/// Turns an optional query timestamp into a bound the database can compare against.
fn timestamp(value: Option<&str>, field: &str) -> ApiResult<Option<DateTime<Utc>>> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(None),
        Some(value) => DateTime::parse_from_rfc3339(value)
            .map(|at| Some(at.with_timezone(&Utc)))
            .map_err(|_| {
                ApiError::unprocessable(format!(
                    "{field} must be an RFC 3339 timestamp, like 2024-01-31T12:00:00Z"
                ))
            }),
    }
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
            since: timestamp(query.since.as_deref(), "since")?,
            until: timestamp(query.until.as_deref(), "until")?,
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
// Audit export
// ---------------------------------------------------------------------------------------

/// How much audit history one streamed chunk carries. The export is meant to open in a
/// spreadsheet, not to sit in a `String`: each page is formatted as it is read and dropped
/// as soon as the body has it.
const AUDIT_CSV_PAGE: i64 = 500;

/// One CSV cell.
///
/// RFC 4180 quoting, applied only when the value would otherwise break the row: a reason
/// is free text, and a comma or a newline in it must stay inside the column it belongs to.
fn csv_cell(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

/// The human-readable reason out of an audit detail, for the column a moderator scans.
fn audit_reason(detail: &serde_json::Value) -> &str {
    ["text", "note", "reason", "comment"]
        .iter()
        .find_map(|key| detail.get(*key).and_then(serde_json::Value::as_str))
        .unwrap_or("")
}

fn csv_row(row: &moderation::AuditRow) -> String {
    let detail = row.detail.to_string();
    let cells = [
        csv_cell(&row.id),
        csv_cell(&row.created_at.to_rfc3339()),
        csv_cell(row.actor_id.as_deref().unwrap_or("")),
        csv_cell(&row.action),
        csv_cell(&row.target_type),
        csv_cell(row.target_id.as_deref().unwrap_or("")),
        csv_cell(audit_reason(&row.detail)),
        csv_cell(&detail),
    ];
    let mut line = cells.join(",");
    line.push_str("\r\n");
    line
}

/// The state the stream carries between chunks: the filter, and how far it has read.
struct CsvCursor {
    pool: sqlx::PgPool,
    action: Option<String>,
    target_type: Option<String>,
    actor_id: Option<String>,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    offset: i64,
    header_sent: bool,
    done: bool,
}

/// `GET /api/v1/admin/audit.csv` — the audit trail as a file.
///
/// The same filters as the JSON route, plus a time window, and the same `admin:read`
/// grant. The header is the first chunk; every page after it is one more chunk.
async fn audit_csv(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Response> {
    auth.require_admin("admin:read")?;
    let cursor = CsvCursor {
        pool: state.store().pool().clone(),
        action: query.action,
        target_type: query.target_type,
        actor_id: query.actor_id,
        since: timestamp(query.since.as_deref(), "since")?,
        until: timestamp(query.until.as_deref(), "until")?,
        offset: 0,
        header_sent: false,
        done: false,
    };
    let stream = futures_util::stream::unfold(cursor, |mut cursor| async move {
        if !cursor.header_sent {
            cursor.header_sent = true;
            let header = "id,created_at,actor_id,action,target_type,target_id,reason,detail\r\n";
            return Some((
                Ok::<Bytes, std::io::Error>(Bytes::from_static(header.as_bytes())),
                cursor,
            ));
        }
        if cursor.done {
            return None;
        }
        let rows = moderation::audit_page(
            &cursor.pool,
            &AuditFilter {
                action: cursor.action.as_deref(),
                target_type: cursor.target_type.as_deref(),
                actor_id: cursor.actor_id.as_deref(),
                since: cursor.since,
                until: cursor.until,
                limit: AUDIT_CSV_PAGE,
                offset: cursor.offset,
            },
        )
        .await;
        match rows {
            // A failed read has to break the transfer: a stream that ends quietly would
            // hand the console a truncated file that looks complete.
            Err(error) => {
                tracing::error!(error = %error, "audit export read failed");
                Some((
                    Err::<Bytes, std::io::Error>(std::io::Error::other("audit export read failed")),
                    cursor,
                ))
            }
            Ok(rows) if rows.is_empty() => None,
            Ok(rows) => {
                if i64::try_from(rows.len()).unwrap_or(i64::MAX) < AUDIT_CSV_PAGE {
                    cursor.done = true;
                }
                cursor.offset += i64::try_from(rows.len()).unwrap_or(i64::MAX);
                let mut chunk = String::new();
                for row in &rows {
                    chunk.push_str(&csv_row(row));
                }
                Some((Ok::<Bytes, std::io::Error>(Bytes::from(chunk)), cursor))
            }
        }
    });
    let response = csv_response("audit.csv", stream)?;
    Ok(response)
}

/// A streamed CSV attachment.
///
/// The export never holds its result set: a handler renders one page to text, hands the
/// chunk to the body, and drops it, so a file of two hundred thousand rows costs one page
/// of memory. That is why none of the exports caps its row count — the response is linear
/// in pages, and a cap would only make an operator repeat the export in slices, guessing
/// where the last one stopped. The header travels as the first chunk, so even a transfer
/// that breaks mid-file names its columns.
fn csv_response(
    filename: &str,
    stream: impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
) -> ApiResult<Response> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/csv; charset=utf-8")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(axum::body::Body::from_stream(stream))
        .map_err(|error| {
            tracing::error!(error = %error, "csv export response failed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not build the export",
            )
        })
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
    auth.require_administrator("admin:write")?;
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
    auth.require_administrator("admin:write")?;
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
    auth.require_administrator("admin:write")?;
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
    auth.require_administrator("admin:write")?;
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
        .merge(escalation::router())
        .merge(appeals::router())
        .merge(blocklist::router())
        .merge(federation::router())
        .merge(forwarded::router())
        .merge(ip_blocks::router())
        .merge(scanners::router())
        .merge(media::router())
        .merge(rules::router())
        .merge(moderation_rules::router())
        .merge(relays::router())
        .merge(settings_transfer::router())
        .merge(topology::router())
        .route("/api/v1/admin/meta", get(meta))
        .route("/api/v1/admin/overview", get(overview))
        .route("/api/v1/admin/stats", get(stats::stats))
        .route("/api/v1/admin/measures", get(measures))
        .route("/api/v1/admin/audit", get(audit))
        .route("/api/v1/admin/audit.csv", get(audit_csv))
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
