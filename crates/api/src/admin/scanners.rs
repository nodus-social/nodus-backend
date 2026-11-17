//! Scanner administration, and the endpoints a scanner service itself talks to.
//!
//! The instance is the controller: it owns the registry, the per-label rules and the
//! content sets. A service is headless — it asks for its configuration and its set here,
//! and answers scan requests with labels and confidence. Nothing in this file decides what
//! a label *means*; `scanner_rule` does, and an administrator writes it.

use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;

use nodus_server_scan::{Manifest, Severity, Transport};
use nodus_server_store::scanners::{
    self, AssetRow, FlagRow, NewAsset, NewScanner, RuleRow, ScanRow, ScannerRow,
};

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

use super::{audit_write_detail, offset, page, Body};

#[derive(Debug, Serialize)]
pub struct RuleDto {
    pub id: String,
    pub label: String,
    pub threshold: f64,
    pub severity: String,
}

impl From<RuleRow> for RuleDto {
    fn from(row: RuleRow) -> Self {
        Self {
            id: row.id,
            label: row.label,
            threshold: row.threshold,
            severity: row.severity,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ScannerDto {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub endpoint: String,
    pub enabled: bool,
    pub asset_id: Option<String>,
    pub contract: i32,
    /// What the service last said it can report. Empty until a refresh succeeds.
    pub labels: Vec<String>,
    pub manifest: Value,
    pub manifest_at: Option<DateTime<Utc>>,
    pub timeout_ms: i32,
    pub rules: Vec<RuleDto>,
}

async fn scanner_dto(state: &AppState, row: ScannerRow) -> ApiResult<ScannerDto> {
    let rules = scanners::rules(state.store().pool(), &row.id).await?;
    Ok(ScannerDto {
        id: row.id,
        name: row.name,
        kind: row.kind,
        endpoint: row.endpoint,
        enabled: row.enabled,
        asset_id: row.asset_id,
        contract: row.contract,
        labels: row.labels,
        manifest: row.manifest,
        manifest_at: row.manifest_at,
        timeout_ms: row.timeout_ms,
        rules: rules.into_iter().map(RuleDto::from).collect(),
    })
}

#[derive(Debug, Deserialize)]
pub struct ScannerForm {
    name: String,
    kind: String,
    endpoint: String,
    #[serde(default)]
    secret: Option<String>,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
    #[serde(default)]
    asset_id: Option<String>,
    #[serde(default = "default_timeout")]
    timeout_ms: i32,
}

fn enabled_by_default() -> bool {
    true
}

fn default_timeout() -> i32 {
    5000
}

impl ScannerForm {
    fn check(&self) -> ApiResult<()> {
        if self.name.trim().is_empty() {
            return Err(ApiError::unprocessable("a scanner needs a name"));
        }
        if !matches!(self.kind.as_str(), "image" | "video" | "text") {
            return Err(ApiError::unprocessable("kind is image, video or text"));
        }
        let endpoint = self.endpoint.trim();
        if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
            return Err(ApiError::unprocessable(
                "the endpoint is the service's base URL, starting with http:// or https://",
            ));
        }
        if !(100..=60_000).contains(&self.timeout_ms) {
            return Err(ApiError::unprocessable(
                "timeout_ms is between 100 and 60000",
            ));
        }
        Ok(())
    }

    fn new_scanner(&self) -> NewScanner<'_> {
        NewScanner {
            name: self.name.trim(),
            kind: &self.kind,
            endpoint: self.endpoint.trim(),
            secret: self
                .secret
                .as_deref()
                .filter(|value| !value.trim().is_empty()),
            enabled: self.enabled,
            asset_id: self.asset_id.as_deref().filter(|value| !value.is_empty()),
            timeout_ms: self.timeout_ms,
        }
    }
}

async fn list(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<ScannerDto>>> {
    auth.require_admin("admin:read")?;
    let mut out = Vec::new();
    for row in scanners::scanners(state.store().pool()).await? {
        out.push(scanner_dto(&state, row).await?);
    }
    Ok(Json(out))
}

async fn show(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<ScannerDto>> {
    auth.require_admin("admin:read")?;
    let row = scanners::scanner(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that scanner does not exist"))?;
    Ok(Json(scanner_dto(&state, row).await?))
}

async fn create(
    State(state): State<AppState>,
    auth: Auth,
    Body(form): Body<ScannerForm>,
) -> ApiResult<Json<ScannerDto>> {
    auth.require_admin("admin:write")?;
    form.check()?;
    let row = scanners::create_scanner(state.store().pool(), &form.new_scanner()).await?;
    audit_write_detail(
        &state,
        &auth,
        "create_scanner",
        "scanner",
        &row.id,
        json!({ "name": row.name }),
    )
    .await?;
    Ok(Json(scanner_dto(&state, row).await?))
}

async fn update(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Body(form): Body<ScannerForm>,
) -> ApiResult<Json<ScannerDto>> {
    auth.require_admin("admin:write")?;
    form.check()?;
    let row = scanners::update_scanner(state.store().pool(), &id, &form.new_scanner())
        .await?
        .ok_or_else(|| ApiError::not_found("that scanner does not exist"))?;
    audit_write_detail(
        &state,
        &auth,
        "update_scanner",
        "scanner",
        &id,
        json!({ "enabled": row.enabled }),
    )
    .await?;
    Ok(Json(scanner_dto(&state, row).await?))
}

async fn remove(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    auth.require_admin("admin:write")?;
    if !scanners::delete_scanner(state.store().pool(), &id).await? {
        return Err(ApiError::not_found("that scanner does not exist"));
    }
    audit_write_detail(&state, &auth, "delete_scanner", "scanner", &id, json!({})).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Asks the service what it can report and stores the answer.
///
/// This is the only place the instance believes a scanner about itself, which is why it is
/// a deliberate button rather than something a failed sweep retries forever.
async fn refresh(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<ScannerDto>> {
    auth.require_admin("admin:write")?;
    let row = scanners::scanner(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that scanner does not exist"))?;
    let transport = Transport::new().map_err(|error| ApiError::unprocessable(error.to_string()))?;
    let timeout = Duration::from_millis(u64::try_from(row.timeout_ms).unwrap_or(5000));
    let manifest: Manifest = transport
        .manifest(&row.endpoint, row.secret.as_deref(), timeout)
        .await
        .map_err(|error| {
            ApiError::unprocessable(format!(
                "{} did not answer a manifest: {error}",
                row.endpoint
            ))
        })?;
    manifest.check(&row.kind).map_err(|error| {
        ApiError::unprocessable(format!("that service is the wrong shape: {error}"))
    })?;
    let labels = manifest.label_names();
    let detail = serde_json::to_value(&manifest).unwrap_or_else(|_| json!({}));
    let row = scanners::record_manifest(
        state.store().pool(),
        &row.id,
        i32::try_from(manifest.contract).unwrap_or(1),
        &labels,
        &detail,
    )
    .await?
    .ok_or_else(|| ApiError::not_found("that scanner does not exist"))?;
    audit_write_detail(
        &state,
        &auth,
        "refresh_scanner",
        "scanner",
        &id,
        json!({ "labels": labels }),
    )
    .await?;
    Ok(Json(scanner_dto(&state, row).await?))
}

#[derive(Debug, Deserialize)]
pub struct RuleForm {
    label: String,
    #[serde(default = "default_threshold")]
    threshold: f64,
    severity: String,
}

fn default_threshold() -> f64 {
    0.5
}

/// The decision an administrator is making: this label, this confident, means this much.
async fn put_rule(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Body(form): Body<RuleForm>,
) -> ApiResult<Json<RuleDto>> {
    auth.require_admin("admin:write")?;
    let label = form.label.trim();
    if label.is_empty() {
        return Err(ApiError::unprocessable("a rule needs a label"));
    }
    if !(0.0..=1.0).contains(&form.threshold) {
        return Err(ApiError::unprocessable("threshold is between 0 and 1"));
    }
    let row = scanners::upsert_rule(
        state.store().pool(),
        &id,
        label,
        form.threshold,
        severity_str(&form.severity)?,
    )
    .await?;
    audit_write_detail(
        &state,
        &auth,
        "set_scanner_rule",
        "scanner",
        &id,
        json!({ "label": label, "threshold": form.threshold, "severity": form.severity }),
    )
    .await?;
    Ok(Json(RuleDto::from(row)))
}

fn severity_str(raw: &str) -> ApiResult<&'static str> {
    match Severity::parse(raw) {
        Severity::Ignore if raw != "ignore" && raw != "none" => {
            Err(ApiError::unprocessable(format!("unknown severity: {raw}")))
        }
        severity => Ok(severity.as_str()),
    }
}

async fn delete_rule(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    auth.require_admin("admin:write")?;
    if !scanners::delete_rule(state.store().pool(), &id).await? {
        return Err(ApiError::not_found("that rule does not exist"));
    }
    audit_write_detail(&state, &auth, "delete_scanner_rule", "rule", &id, json!({})).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
pub struct AssetDto {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub digest: String,
    pub size: i64,
    pub content_type: String,
    pub created_at: DateTime<Utc>,
}

impl From<AssetRow> for AssetDto {
    fn from(row: AssetRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            kind: row.kind,
            digest: row.digest,
            size: row.size,
            content_type: row.content_type,
            created_at: row.created_at,
        }
    }
}

async fn assets(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<AssetDto>>> {
    auth.require_admin("admin:read")?;
    Ok(Json(
        scanners::assets(state.store().pool())
            .await?
            .into_iter()
            .map(AssetDto::from)
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct AssetForm {
    name: String,
    kind: String,
    #[serde(default = "octet_stream")]
    content_type: String,
    /// The bytes, base64. Uploaded through the API so a scanner can be configured from a
    /// browser on a machine that never sees the server's filesystem.
    data: String,
}

fn octet_stream() -> String {
    "application/octet-stream".to_owned()
}

/// The digest is what a scanner verifies its copy against, so it is computed here, from the
/// bytes, and never taken from the client.
async fn upload_asset(
    State(state): State<AppState>,
    auth: Auth,
    Json(form): Json<AssetForm>,
) -> ApiResult<Json<AssetDto>> {
    auth.require_admin("admin:write")?;
    if !matches!(form.kind.as_str(), "hashes" | "weights" | "words") {
        return Err(ApiError::unprocessable("kind is hashes, weights or words"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(form.data.as_bytes())
        .map_err(|_| ApiError::unprocessable("data is not valid base64"))?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err(ApiError::unprocessable("a content set is at most 64 MiB"));
    }
    let digest = sha2::Sha256::digest(&bytes);
    let digest = digest.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    });
    let row = scanners::create_asset(
        state.store().pool(),
        &NewAsset {
            name: form.name.trim(),
            kind: &form.kind,
            digest: &digest,
            size: i64::try_from(bytes.len()).unwrap_or(i64::MAX),
            content_type: form.content_type.trim(),
            content: &bytes,
        },
    )
    .await?;
    audit_write_detail(
        &state,
        &auth,
        "upload_scanner_asset",
        "asset",
        &row.id,
        json!({ "name": row.name, "digest": digest, "size": row.size }),
    )
    .await?;
    Ok(Json(AssetDto::from(row)))
}

async fn delete_asset(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    auth.require_admin("admin:write")?;
    if scanners::asset_in_use(state.store().pool(), &id).await? {
        return Err(ApiError::unprocessable(
            "a scanner still points at that set; point it elsewhere first",
        ));
    }
    if !scanners::delete_asset(state.store().pool(), &id).await? {
        return Err(ApiError::not_found("that set does not exist"));
    }
    audit_write_detail(
        &state,
        &auth,
        "delete_scanner_asset",
        "asset",
        &id,
        json!({}),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The bytes back out, so an administrator can check what a service received.
async fn download_asset(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<impl axum::response::IntoResponse> {
    auth.require_admin("admin:read")?;
    let row = scanners::asset(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that set does not exist"))?;
    let bytes = scanners::asset_bytes(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that set has no content"))?;
    Ok((
        [
            (header::CONTENT_TYPE, row.content_type),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", row.name),
            ),
        ],
        bytes,
    ))
}

#[derive(Debug, Serialize)]
pub struct FlagDto {
    pub id: String,
    pub scan_id: String,
    pub status_id: Option<String>,
    pub account_id: Option<String>,
    pub reason: String,
    pub score: Option<f32>,
    pub labels: Vec<String>,
    pub severity: String,
    pub state: String,
    pub created_at: DateTime<Utc>,
}

impl From<FlagRow> for FlagDto {
    fn from(row: FlagRow) -> Self {
        Self {
            id: row.id,
            scan_id: row.scan_id,
            status_id: row.status_id,
            account_id: row.account_id,
            reason: row.reason,
            score: row.score,
            labels: row.labels,
            severity: row.severity,
            state: row.state,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct FlagQuery {
    state: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn flags(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<FlagQuery>,
) -> ApiResult<Json<Vec<FlagDto>>> {
    auth.require_admin("admin:read")?;
    let rows = scanners::flags(
        state.store().pool(),
        query.state.as_deref().filter(|value| *value != "all"),
        page(query.limit),
        offset(query.offset),
    )
    .await?;
    Ok(Json(rows.into_iter().map(FlagDto::from).collect()))
}

#[derive(Debug, Deserialize)]
pub struct FlagBody {
    state: String,
}

/// A moderator's verdict on what a scanner found. Dismissing a flag is not deleting it: the
/// scan stays, so the same content does not come back round the queue.
async fn resolve_flag(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Body(body): Body<FlagBody>,
) -> ApiResult<Json<FlagDto>> {
    auth.require_admin("admin:write")?;
    if !matches!(body.state.as_str(), "dismissed" | "actioned" | "open") {
        return Err(ApiError::unprocessable(
            "state is open, dismissed or actioned",
        ));
    }
    let row = scanners::resolve_flag(state.store().pool(), &id, &body.state, &auth.0.account.id)
        .await?
        .ok_or_else(|| ApiError::not_found("that flag does not exist"))?;
    audit_write_detail(
        &state,
        &auth,
        "resolve_scan_flag",
        "flag",
        &id,
        json!({ "state": body.state }),
    )
    .await?;
    Ok(Json(FlagDto::from(row)))
}

#[derive(Debug, Serialize)]
pub struct ScanDto {
    pub id: String,
    pub scanner_id: String,
    pub kind: String,
    pub subject_type: String,
    pub subject_id: String,
    pub state: String,
    pub score: Option<f32>,
    pub labels: Vec<String>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

impl From<ScanRow> for ScanDto {
    fn from(row: ScanRow) -> Self {
        Self {
            id: row.id,
            scanner_id: row.scanner_id,
            kind: row.kind,
            subject_type: row.subject_type,
            subject_id: row.subject_id,
            state: row.state,
            score: row.score,
            labels: row.labels,
            error: row.error,
            created_at: row.created_at,
            finished_at: row.finished_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ScanQuery {
    state: Option<String>,
    limit: Option<i64>,
}

async fn scan_queue(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<ScanQuery>,
) -> ApiResult<Json<Vec<ScanDto>>> {
    auth.require_admin("admin:read")?;
    let rows = scanners::scans(
        state.store().pool(),
        query.state.as_deref().filter(|value| *value != "all"),
        page(query.limit),
    )
    .await?;
    Ok(Json(rows.into_iter().map(ScanDto::from).collect()))
}

#[derive(Debug, Deserialize)]
pub struct ScanBody {
    subject_type: String,
    subject_id: String,
    kind: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    mime: Option<String>,
}

/// Queues a subject by hand. The sweep queues new statuses and media on its own; this is
/// for re-running something a moderator is looking at now.
async fn enqueue(
    State(state): State<AppState>,
    auth: Auth,
    Json(body): Json<ScanBody>,
) -> ApiResult<Json<Value>> {
    auth.require_admin("admin:write")?;
    if !matches!(body.subject_type.as_str(), "status" | "media") {
        return Err(ApiError::unprocessable("subject_type is status or media"));
    }
    if !matches!(body.kind.as_str(), "image" | "video" | "text") {
        return Err(ApiError::unprocessable("kind is image, video or text"));
    }
    let queued = scanners::enqueue_for(
        state.store().pool(),
        &body.kind,
        &body.subject_type,
        &body.subject_id,
        body.url.as_deref(),
        body.text.as_deref(),
        body.mime.as_deref(),
    )
    .await?;
    audit_write_detail(
        &state,
        &auth,
        "enqueue_scan",
        &body.subject_type,
        &body.subject_id,
        json!({ "kind": body.kind, "queued": queued }),
    )
    .await?;
    Ok(Json(json!({ "queued": queued })))
}

// ---------------------------------------------------------------------------------------
// What a scanner service asks for
// ---------------------------------------------------------------------------------------

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
}

/// Refuses unless the caller proves it is this scanner.
///
/// A scanner with no secret is unreachable: it cannot prove anything, and handing content
/// sets to an endpoint anyone can call would make the set public.
async fn node(state: &AppState, id: &str, headers: &HeaderMap) -> ApiResult<ScannerRow> {
    let row = scanners::scanner(state.store().pool(), id)
        .await?
        .ok_or_else(|| ApiError::not_found("no such node"))?;
    let Some(secret) = row.secret.as_deref() else {
        return Err(ApiError::forbidden(
            "this node has no secret, so it cannot be configured remotely",
        ));
    };
    if bearer(headers) != Some(secret) {
        return Err(ApiError::unauthorized("wrong node secret"));
    }
    Ok(row)
}

/// The configuration a service needs, and nothing else: what to look for, how strict each
/// label is, and which set to verify its copy of the data against.
async fn node_config(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let row = node(&state, &id, &headers).await?;
    let rules = scanners::rules(state.store().pool(), &row.id).await?;
    let asset = match row.asset_id.as_deref() {
        Some(asset_id) => scanners::asset(state.store().pool(), asset_id).await?,
        None => None,
    };
    Ok(Json(json!({
        "contract": row.contract,
        "id": row.id,
        "name": row.name,
        "kind": row.kind,
        "enabled": row.enabled,
        "timeout_ms": row.timeout_ms,
        "labels": row.labels,
        "rules": rules
            .into_iter()
            .map(|rule| json!({
                "label": rule.label,
                "threshold": rule.threshold,
                "severity": rule.severity,
            }))
            .collect::<Vec<_>>(),
        "asset": asset.map(|asset| json!({
            "id": asset.id,
            "name": asset.name,
            "kind": asset.kind,
            "digest": asset.digest,
            "size": asset.size,
            "content_type": asset.content_type,
        })),
    })))
}

async fn node_asset(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<impl axum::response::IntoResponse> {
    let row = node(&state, &id, &headers).await?;
    let asset_id = row
        .asset_id
        .ok_or_else(|| ApiError::not_found("this node has no content set"))?;
    let asset = scanners::asset(state.store().pool(), &asset_id)
        .await?
        .ok_or_else(|| ApiError::not_found("this node's content set is missing"))?;
    let bytes = scanners::asset_bytes(state.store().pool(), &asset_id)
        .await?
        .ok_or_else(|| ApiError::not_found("this node's content set is missing"))?;
    Ok((
        [
            (header::CONTENT_TYPE, asset.content_type),
            (
                header::HeaderName::from_static("x-nodus-digest"),
                asset.digest,
            ),
        ],
        bytes,
    ))
}

/// Public routes: a scanner proves itself with its own secret, not with an account.
pub fn node_router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/scan/nodes/{id}/config", get(node_config))
        .route("/api/v1/scan/nodes/{id}/asset", get(node_asset))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/scanners", get(list).post(create))
        .route(
            "/api/v1/admin/scanners/{id}",
            get(show).put(update).post(update).delete(remove),
        )
        .route("/api/v1/admin/scanners/{id}/refresh", post(refresh))
        .route(
            "/api/v1/admin/scanners/{id}/rules",
            put(put_rule).post(put_rule),
        )
        .route("/api/v1/admin/scanner_rules/{id}", delete(delete_rule))
        .route(
            "/api/v1/admin/scanner_assets",
            get(assets).post(upload_asset),
        )
        .route("/api/v1/admin/scanner_assets/{id}", delete(delete_asset))
        .route(
            "/api/v1/admin/scanner_assets/{id}/download",
            get(download_asset),
        )
        .route("/api/v1/admin/flags", get(flags))
        .route("/api/v1/admin/flags/{id}/resolve", post(resolve_flag))
        .route("/api/v1/admin/scans", get(scan_queue).post(enqueue))
}
