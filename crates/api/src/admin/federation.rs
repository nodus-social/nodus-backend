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

use nodus_server_store::moderation::{
    self, DomainBlockFilter, DomainBlockRow, EmailDomainBlockRow, NewDomainBlock,
};

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
    auth.require_admin("admin:read")?;
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
    auth.require_admin("admin:write")?;
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
    auth.require_admin("admin:write")?;
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

pub fn router() -> Router<AppState> {
    Router::new()
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
