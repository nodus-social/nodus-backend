//! Federation policy: which remote domains are silenced or suspended, which are allowed
//! through a block, and which mail domains may register.
//!
//! Blocks and allows are separate lists that both apply — a block widens, an allow carves
//! an exception back out of it — so the endpoints mirror that instead of pretending one
//! list overrides the other.

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use nodus_server_store::blocks as store_blocks;
use nodus_server_store::delivery;
use nodus_server_store::moderation::{
    self, DomainBlockFilter, DomainBlockRow, EmailDomainBlockRow, NewDomainBlock,
};
use nodus_server_store::remote_moderation;

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

use super::{offset, page, Body};

#[derive(Debug, Serialize)]
pub struct DomainBlockDto {
    pub id: String,
    pub domain: String,
    pub created_at: DateTime<Utc>,
    pub severity: String,
    pub reject_media: bool,
    pub reject_reports: bool,
    pub obfuscate: bool,
    pub public_comment: String,
}

impl From<DomainBlockRow> for DomainBlockDto {
    fn from(row: DomainBlockRow) -> Self {
        Self {
            id: row.id,
            domain: row.domain,
            created_at: row.created_at,
            severity: row.severity,
            reject_media: row.reject_media,
            reject_reports: row.reject_reports,
            obfuscate: row.obfuscate,
            public_comment: row.public_comment,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct BlockQuery {
    severity: Option<String>,
    domain: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn blocks(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<BlockQuery>,
) -> ApiResult<Json<Vec<DomainBlockDto>>> {
    auth.require_admin("admin:read")?;
    let rows = moderation::blocks(
        state.store().pool(),
        &DomainBlockFilter {
            severity: query.severity.as_deref(),
            domain: query.domain.as_deref(),
            limit: page(query.limit),
            offset: offset(query.offset),
        },
    )
    .await?;
    Ok(Json(rows.into_iter().map(DomainBlockDto::from).collect()))
}

/// The fields every block write accepts, in either a form or a JSON body.
#[derive(Debug, Deserialize)]
pub struct DomainForm {
    domain: String,
    #[serde(default = "default_severity")]
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

fn default_severity() -> String {
    "suspend".to_owned()
}

impl DomainForm {
    fn new_block(&self) -> NewDomainBlock<'_> {
        NewDomainBlock {
            domain: self.domain.trim(),
            severity: self.severity.trim(),
            reject_media: self.reject_media,
            reject_reports: self.reject_reports,
            obfuscate: self.obfuscate,
            public_comment: self.public_comment.trim(),
        }
    }

    fn check(&self) -> ApiResult<()> {
        let domain = self.domain.trim();
        if domain.is_empty()
            || !domain.contains('.')
            || domain.contains('/')
            || domain.contains(' ')
        {
            return Err(ApiError::unprocessable(
                "a domain looks like example.com, with no scheme and no path",
            ));
        }
        if !matches!(self.severity.as_str(), "suspend" | "silence") {
            return Err(ApiError::unprocessable(
                "severity is either suspend or silence",
            ));
        }
        Ok(())
    }
}

async fn create_block(
    State(state): State<AppState>,
    auth: Auth,
    Body(form): Body<DomainForm>,
) -> ApiResult<Json<DomainBlockDto>> {
    auth.require_admin("admin:write")?;
    form.check()?;
    let row = moderation::create_block(state.store().pool(), &form.new_block()).await?;
    super::audit_write_detail(
        &state,
        &auth,
        "create_domain_block",
        "domain",
        &row.domain,
        json!({ "severity": row.severity }),
    )
    .await?;
    Ok(Json(DomainBlockDto::from(row)))
}

async fn update_block(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Body(form): Body<DomainForm>,
) -> ApiResult<Json<DomainBlockDto>> {
    auth.require_admin("admin:write")?;
    form.check()?;
    let row = moderation::update_block(state.store().pool(), &id, &form.new_block())
        .await?
        .ok_or_else(|| ApiError::not_found("that block does not exist"))?;
    super::audit_write_detail(
        &state,
        &auth,
        "update_domain_block",
        "domain",
        &row.domain,
        json!({ "severity": row.severity }),
    )
    .await?;
    Ok(Json(DomainBlockDto::from(row)))
}

async fn show_block(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<DomainBlockDto>> {
    auth.require_admin("admin:read")?;
    let row = moderation::block(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that block does not exist"))?;
    Ok(Json(DomainBlockDto::from(row)))
}

async fn delete_block(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<axum::http::StatusCode> {
    auth.require_admin("admin:write")?;
    let row = moderation::block(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that block does not exist"))?;
    if !moderation::delete_block(state.store().pool(), &id).await? {
        return Err(ApiError::not_found("that block does not exist"));
    }
    super::audit_write_detail(
        &state,
        &auth,
        "delete_domain_block",
        "domain",
        &row.domain,
        json!({}),
    )
    .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct ImportBody {
    domains: Vec<String>,
    #[serde(default = "default_severity")]
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

#[derive(Debug, Serialize)]
pub struct ImportDto {
    pub blocked: usize,
    pub skipped: Vec<String>,
}

/// Bulk block. Mastodon's importer takes a CSV upload; a JSON list of domains is the same
/// operation without a parser that can disagree about quoting.
async fn import(
    State(state): State<AppState>,
    auth: Auth,
    Json(body): Json<ImportBody>,
) -> ApiResult<Json<ImportDto>> {
    auth.require_admin("admin:write")?;
    if body.domains.len() > 5000 {
        return Err(ApiError::unprocessable(
            "import at most 5000 domains at a time",
        ));
    }
    let mut blocked = 0_usize;
    let mut skipped = Vec::new();
    for raw in &body.domains {
        let form = DomainForm {
            domain: raw.clone(),
            severity: body.severity.clone(),
            reject_media: body.reject_media,
            reject_reports: body.reject_reports,
            obfuscate: body.obfuscate,
            public_comment: body.public_comment.clone(),
        };
        if form.check().is_err() {
            skipped.push(raw.clone());
            continue;
        }
        moderation::create_block(state.store().pool(), &form.new_block()).await?;
        blocked += 1;
    }
    super::audit_write_detail(
        &state,
        &auth,
        "import_domain_blocks",
        "domain",
        "",
        json!({ "blocked": blocked, "skipped": skipped.len() }),
    )
    .await?;
    Ok(Json(ImportDto { blocked, skipped }))
}

#[derive(Debug, Deserialize)]
pub struct DeliveryQuery {
    state: Option<String>,
    host: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct DeliveryDto {
    pub id: String,
    pub inbox_url: String,
    pub host: String,
    pub activity_id: String,
    pub activity_kind: Option<String>,
    pub state: String,
    pub attempts: i32,
    pub last_status_code: Option<i32>,
    pub last_error: Option<String>,
    pub next_attempt_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
}

impl From<delivery::DeliveryRecord> for DeliveryDto {
    fn from(row: delivery::DeliveryRecord) -> Self {
        Self {
            id: row.id,
            inbox_url: row.inbox_url,
            host: row.host,
            activity_id: row.activity_id,
            activity_kind: row.activity_kind,
            state: row.state,
            attempts: row.attempts,
            last_status_code: row.last_status_code,
            last_error: row.last_error,
            next_attempt_at: row.next_attempt_at,
            created_at: row.created_at,
            delivered_at: row.delivered_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DeliveryCountsDto {
    pub pending: i64,
    pub failed: i64,
    pub gave_up: i64,
    pub delivered: i64,
}

#[derive(Debug, Serialize)]
pub struct DeliveryListDto {
    pub deliveries: Vec<DeliveryDto>,
    pub counts: DeliveryCountsDto,
}

/// `GET /api/v1/admin/federation/deliveries` — every attempt, newest first.
async fn deliveries(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<DeliveryQuery>,
) -> ApiResult<Json<DeliveryListDto>> {
    auth.require_admin("admin:read")?;
    let wanted = query.state.as_deref().filter(|value| !value.is_empty());
    if let Some(value) = wanted {
        if !delivery::STATES.contains(&value) {
            return Err(ApiError::unprocessable(
                "state is pending, failed, gave_up or delivered",
            ));
        }
    }
    let host = query
        .host
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_lowercase);
    let (rows, counts) = delivery::list(
        state.store().pool(),
        &delivery::DeliveryFilter {
            state: wanted,
            host: host.as_deref(),
            limit: page(query.limit),
            offset: offset(query.offset),
        },
    )
    .await?;
    Ok(Json(DeliveryListDto {
        deliveries: rows.into_iter().map(DeliveryDto::from).collect(),
        counts: DeliveryCountsDto {
            pending: counts.pending,
            failed: counts.failed,
            gave_up: counts.gave_up,
            delivered: counts.delivered,
        },
    }))
}

/// `POST /api/v1/admin/federation/deliveries/{id}/retry` — send one delivery again now.
async fn retry_delivery(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_admin("admin:write")?;
    let id = delivery::requeue(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that delivery does not exist"))?;
    super::audit_write_detail(
        &state,
        &auth,
        "retry_federation_delivery",
        "federation_delivery",
        &id,
        json!({}),
    )
    .await?;
    Ok(Json(json!({ "id": id, "state": "pending" })))
}

#[derive(Debug, Default, Deserialize)]
pub struct RetryFailedForm {
    host: Option<String>,
}

/// `POST /api/v1/admin/federation/deliveries/retry-failed` — send every failure again.
///
/// Both `failed` and `gave_up` count as failed: neither has reached the peer, and an
/// operator retrying after fixing a key or unblocking a host means now, not when the next
/// backoff elapses. The answer is the number actually re-queued, so a UI can say it.
async fn retry_failed_deliveries(
    State(state): State<AppState>,
    auth: Auth,
    body: Option<Json<RetryFailedForm>>,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_admin("admin:write")?;
    let host = body
        .and_then(|Json(form)| form.host)
        .map(|value| value.trim().to_lowercase())
        .filter(|value| !value.is_empty());
    let requeued = delivery::requeue_failed(state.store().pool(), host.as_deref()).await?;
    super::audit_write_detail(
        &state,
        &auth,
        "retry_failed_federation_deliveries",
        "federation_delivery",
        host.as_deref().unwrap_or("*"),
        json!({ "requeued": requeued, "host": host }),
    )
    .await?;
    Ok(Json(json!({ "requeued": requeued })))
}

#[derive(Debug, Serialize)]
pub struct DomainAllowDto {
    pub id: String,
    pub domain: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct AllowForm {
    domain: String,
}

async fn allows(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<BlockQuery>,
) -> ApiResult<Json<Vec<DomainAllowDto>>> {
    auth.require_admin("admin:read")?;
    let rows = moderation::allows(state.store().pool(), page(query.limit)).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| DomainAllowDto {
                id: row.id,
                domain: row.domain,
                created_at: row.created_at,
            })
            .collect(),
    ))
}

async fn create_allow(
    State(state): State<AppState>,
    auth: Auth,
    Body(form): Body<AllowForm>,
) -> ApiResult<Json<DomainAllowDto>> {
    auth.require_admin("admin:write")?;
    let domain = form.domain.trim();
    if domain.is_empty() || !domain.contains('.') || domain.contains('/') {
        return Err(ApiError::unprocessable(
            "a domain looks like example.com, with no scheme and no path",
        ));
    }
    let row = moderation::create_allow(state.store().pool(), domain).await?;
    super::audit_write_detail(
        &state,
        &auth,
        "create_domain_allow",
        "domain",
        domain,
        json!({}),
    )
    .await?;
    Ok(Json(DomainAllowDto {
        id: row.id,
        domain: row.domain,
        created_at: row.created_at,
    }))
}

async fn delete_allow(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<axum::http::StatusCode> {
    auth.require_admin("admin:write")?;
    let domain = state.store().pool();
    if !moderation::delete_allow(domain, &id).await? {
        return Err(ApiError::not_found("that allowance does not exist"));
    }
    super::audit_write_detail(
        &state,
        &auth,
        "delete_domain_allow",
        "domain",
        &id,
        json!({}),
    )
    .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
pub struct EmailDomainBlockDto {
    pub id: String,
    pub domain: String,
    pub allow_registration: bool,
    pub created_at: DateTime<Utc>,
}

impl From<EmailDomainBlockRow> for EmailDomainBlockDto {
    fn from(row: EmailDomainBlockRow) -> Self {
        Self {
            id: row.id,
            domain: row.domain,
            allow_registration: row.allow_registration,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct EmailDomainForm {
    domain: String,
    #[serde(default)]
    allow_registration: bool,
}

#[derive(Debug, Deserialize)]
pub struct EmailQuery {
    domain: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn email_blocks(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<EmailQuery>,
) -> ApiResult<Json<Vec<EmailDomainBlockDto>>> {
    auth.require_administrator("admin:read")?;
    let rows = moderation::email_domain_blocks(
        state.store().pool(),
        query.domain.as_deref().filter(|value| !value.is_empty()),
        page(query.limit),
        offset(query.offset),
    )
    .await?;
    Ok(Json(
        rows.into_iter().map(EmailDomainBlockDto::from).collect(),
    ))
}

async fn create_email_block(
    State(state): State<AppState>,
    auth: Auth,
    Body(form): Body<EmailDomainForm>,
) -> ApiResult<Json<EmailDomainBlockDto>> {
    auth.require_administrator("admin:write")?;
    let domain = form.domain.trim();
    if domain.is_empty() || !domain.contains('.') || domain.contains('@') {
        return Err(ApiError::unprocessable(
            "a mail domain looks like example.com",
        ));
    }
    let row = moderation::create_email_domain_block(
        state.store().pool(),
        domain,
        form.allow_registration,
    )
    .await?;
    super::audit_write_detail(
        &state,
        &auth,
        "create_email_domain_block",
        "domain",
        domain,
        json!({ "allow_registration": form.allow_registration }),
    )
    .await?;
    Ok(Json(EmailDomainBlockDto::from(row)))
}

async fn delete_email_block(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<axum::http::StatusCode> {
    auth.require_administrator("admin:write")?;
    if !moderation::delete_email_domain_block(state.store().pool(), &id).await? {
        return Err(ApiError::not_found("that mail block does not exist"));
    }
    super::audit_write_detail(
        &state,
        &auth,
        "delete_email_domain_block",
        "domain",
        &id,
        json!({}),
    )
    .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
pub struct RemoteBlockDto {
    pub actor: String,
    pub host: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct RemoteBlocksDto {
    pub blocks: Vec<RemoteBlockDto>,
}

async fn list_remote_blocks(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<RemoteBlocksDto>> {
    auth.require_admin("admin:read")?;
    let rows = store_blocks::remote_blocks(state.store().pool()).await?;
    Ok(Json(RemoteBlocksDto {
        blocks: rows
            .into_iter()
            .map(|row| RemoteBlockDto {
                actor: row.actor,
                host: row.host,
                created_at: row.created_at,
            })
            .collect(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct RemoteBlockForm {
    host: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RemoteBlockQuery {
    host: Option<String>,
}

async fn clear_remote_blocks(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<RemoteBlockQuery>,
    Body(form): Body<RemoteBlockForm>,
) -> ApiResult<axum::http::StatusCode> {
    auth.require_admin("admin:write")?;
    let host = form
        .host
        .or(query.host)
        .map(|host| host.trim().to_owned())
        .filter(|host| !host.is_empty())
        .ok_or_else(|| ApiError::unprocessable("host is required"))?;
    if store_blocks::clear_remote_blocks(state.store().pool(), &host).await? == 0 {
        return Err(ApiError::not_found("no remote block names that host"));
    }
    super::audit_write_detail(
        &state,
        &auth,
        "clear_remote_blocks",
        "host",
        &host,
        json!({}),
    )
    .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// A moderation decision on one remote account, as the console reads it back.
#[derive(Debug, Serialize)]
pub struct RemoteModerationDto {
    pub actor_uri: String,
    pub handle: String,
    pub domain: Option<String>,
    pub action: String,
    pub reason: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub expired: bool,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<String>,
    pub created_by_handle: Option<String>,
}

impl RemoteModerationDto {
    fn new(listed: &remote_moderation::ListedRemoteModeration, now: DateTime<Utc>) -> Self {
        Self {
            actor_uri: listed.row.actor_uri.clone(),
            handle: listed.handle.clone(),
            domain: listed.domain.clone(),
            action: listed.row.action.clone(),
            reason: listed.row.reason.clone(),
            expires_at: listed.row.expires_at,
            expired: !listed.row.is_active(now),
            created_at: listed.row.created_at,
            created_by: listed.row.created_by.clone(),
            created_by_handle: listed.created_by_handle.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RemoteModerationForm {
    action: Option<String>,
    reason: Option<String>,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct RemoteModerationQuery {
    domain: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

/// `GET /api/v1/admin/federation/remote-accounts` — every decision, expired included.
///
/// An expired row is still shown, marked expired: the console needs to say that the
/// account was once moderated, by whom and why, without the row still applying.
async fn remote_accounts(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<RemoteModerationQuery>,
) -> ApiResult<Json<Vec<RemoteModerationDto>>> {
    auth.require_admin("admin:read")?;
    let rows = remote_moderation::list(
        state.store().pool(),
        query.domain.as_deref(),
        page(query.limit),
        offset(query.offset),
    )
    .await?;
    let now = Utc::now();
    Ok(Json(
        rows.iter()
            .map(|row| RemoteModerationDto::new(row, now))
            .collect(),
    ))
}

/// `PUT /api/v1/admin/federation/remote-accounts/{actor_uri}` — apply or change one.
async fn apply_remote_account(
    State(state): State<AppState>,
    auth: Auth,
    Path(actor_uri): Path<String>,
    Body(form): Body<RemoteModerationForm>,
) -> ApiResult<(axum::http::StatusCode, Json<RemoteModerationDto>)> {
    auth.require_admin("admin:write")?;
    let actor_uri = actor_uri.trim().to_owned();
    crate::activitypub::validate_remote_url(&actor_uri)?;
    let action = form
        .action
        .as_deref()
        .map(str::trim)
        .filter(|action| {
            *action == remote_moderation::SILENCE || *action == remote_moderation::SUSPEND
        })
        .ok_or_else(|| ApiError::unprocessable("action must be silence or suspend"))?;
    let reason = form
        .reason
        .map(|reason| reason.trim().to_owned())
        .filter(|reason| !reason.is_empty());
    let (row, inserted) = remote_moderation::upsert(
        state.store().pool(),
        &remote_moderation::NewRemoteModeration {
            actor_uri: &actor_uri,
            action,
            reason: reason.as_deref(),
            expires_at: form.expires_at,
            created_by: Some(auth.0.account.id.as_str()),
        },
    )
    .await?;
    super::audit_write_detail(
        &state,
        &auth,
        "remote_account_moderation",
        "actor",
        &actor_uri,
        json!({
            "action": action,
            "reason": reason,
            "expires_at": form.expires_at,
        }),
    )
    .await?;
    // The peer hears about the block from the admin who made the decision, which is also
    // what signs the delivery. Blocking is still delivered while the actor is suspended
    // (the decision has to reach them, if only so they can see it), and lifting is an Undo.
    let sender = crate::activitypub::ensure_identity(&state, auth.0.account.clone()).await?;
    crate::outbox::deliver_remote_block(&state, &sender.id, &sender.username, &actor_uri, true)
        .await;
    let dto = RemoteModerationDto::new(
        &remote_moderation::ListedRemoteModeration {
            row,
            handle: actor_uri
                .rsplit('/')
                .next()
                .unwrap_or(&actor_uri)
                .to_owned(),
            domain: store_blocks::host_of(&actor_uri),
            created_by_handle: Some(sender.username),
        },
        Utc::now(),
    );
    let status = if inserted {
        axum::http::StatusCode::CREATED
    } else {
        axum::http::StatusCode::OK
    };
    Ok((status, Json(dto)))
}

/// `DELETE /api/v1/admin/federation/remote-accounts/{actor_uri}` — lift the action.
async fn lift_remote_account(
    State(state): State<AppState>,
    auth: Auth,
    Path(actor_uri): Path<String>,
) -> ApiResult<axum::http::StatusCode> {
    auth.require_admin("admin:write")?;
    let actor_uri = actor_uri.trim().to_owned();
    if !remote_moderation::lift(state.store().pool(), &actor_uri).await? {
        return Err(ApiError::not_found("that account is not moderated"));
    }
    super::audit_write_detail(
        &state,
        &auth,
        "lift_remote_account_moderation",
        "actor",
        &actor_uri,
        json!({}),
    )
    .await?;
    let sender = crate::activitypub::ensure_identity(&state, auth.0.account.clone()).await?;
    crate::outbox::deliver_remote_block(&state, &sender.id, &sender.username, &actor_uri, false)
        .await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/federation/deliveries", get(deliveries))
        .route(
            "/api/v1/admin/federation/deliveries/retry-failed",
            post(retry_failed_deliveries),
        )
        .route(
            "/api/v1/admin/federation/deliveries/{id}/retry",
            post(retry_delivery),
        )
        .route(
            "/api/v1/admin/federation/remote-blocks",
            get(list_remote_blocks).delete(clear_remote_blocks),
        )
        .route(
            "/api/v1/admin/federation/remote-accounts",
            get(remote_accounts),
        )
        // The actor URI contains slashes, so the wildcard takes the rest of the path and
        // the handler trims it; a percent-encoded URI works too because axum decodes it.
        .route(
            "/api/v1/admin/federation/remote-accounts/{*actor_uri}",
            axum::routing::put(apply_remote_account).delete(lift_remote_account),
        )
        .route(
            "/api/v1/admin/domain_blocks",
            get(blocks).post(create_block),
        )
        .route("/api/v1/admin/domain_blocks/import", post(import))
        .route(
            "/api/v1/admin/domain_blocks/{id}",
            get(show_block)
                .post(update_block)
                .put(update_block)
                .delete(delete_block),
        )
        .route(
            "/api/v1/admin/domain_allows",
            get(allows).post(create_allow),
        )
        .route("/api/v1/admin/domain_allows/{id}", delete(delete_allow))
        .route(
            "/api/v1/admin/email_domain_blocks",
            get(email_blocks).post(create_email_block),
        )
        .route(
            "/api/v1/admin/email_domain_blocks/{id}",
            delete(delete_email_block),
        )
}
