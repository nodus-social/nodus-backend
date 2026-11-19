//! The account directory.
//!
//! Two jobs live here: finding an account (by name, mail or domain) and doing something
//! about it (approve, silence, suspend, promote, annotate, purge). The action endpoint
//! takes the Mastodon form shape because that is what every existing client sends, and the
//! moderator's note is part of the action rather than a second request: a decision without
//! its reason is a decision nobody can review later.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use nodus_server_store::moderation::{self, AccountFilter, Action, AdminAccountRow};
use nodus_server_store::{accounts, scanners};

use super::Body;
use crate::auth::Auth;
use crate::dto::AccountDto;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

use super::{audit_write_detail, offset, page};
use super::{check_batch, BulkFailure, BulkItemDto, BulkResponseDto};

#[derive(Debug, Serialize)]
pub struct AdminAccountDto {
    pub id: String,
    pub username: String,
    pub domain: Option<String>,
    pub email: Option<String>,
    pub ip: Option<String>,
    /// Nodus gates registration on approval rather than on a mailed link, so this mirrors
    /// `approved`: it is what a client checking `confirmed` is really asking about.
    pub confirmed: bool,
    pub approved: bool,
    pub silenced: bool,
    pub suspended: bool,
    pub disabled: bool,
    pub admin: bool,
    /// `none`, `moderator` or `admin` — which door this account walks through. `admin`
    /// above stays for clients that only understand the boolean.
    pub role: String,
    pub created_at: DateTime<Utc>,
    pub open_reports: i64,
    pub notes_count: i64,
    /// Whether this account's images are stored at full size.
    pub lossless_images: bool,
    /// Whether this account's video is stored at full size.
    pub lossless_videos: bool,
    pub account: AccountDto,
}

impl AdminAccountDto {
    fn from_row(row: AdminAccountRow, state: &AppState) -> Self {
        let account = AccountDto::from_row(&row.account, state.instance());
        Self {
            id: row.account.id.clone(),
            username: row.account.username.clone(),
            domain: row.account.domain.clone(),
            email: row.email,
            ip: None,
            confirmed: row.account.approved,
            approved: row.account.approved,
            silenced: row.account.silenced_at.is_some(),
            suspended: row.account.suspended_at.is_some(),
            disabled: !row.account.approved,
            admin: row.account.admin,
            role: row.account.staff_role,
            created_at: row.account.created_at,
            open_reports: row.open_reports,
            notes_count: row.notes,
            lossless_images: row.account.lossless_images_default,
            lossless_videos: row.account.lossless_videos_default,
            account,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AccountsQuery {
    /// `local`, `remote` or absent for both.
    origin: Option<String>,
    status: Option<String>,
    username: Option<String>,
    display_name: Option<String>,
    email: Option<String>,
    by_domain: Option<String>,
    #[serde(default)]
    staff: bool,
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<AccountsQuery>,
) -> ApiResult<Json<Vec<AdminAccountDto>>> {
    auth.require_admin("admin:read")?;
    let local = match query.origin.as_deref() {
        Some("local") => Some(true),
        Some("remote") => Some(false),
        _ => None,
    };
    let rows = moderation::admin_accounts(
        state.store().pool(),
        &AccountFilter {
            local,
            status: query.status.as_deref().filter(|value| *value != "all"),
            username: query.username.as_deref(),
            display_name: query.display_name.as_deref(),
            email: query.email.as_deref(),
            by_domain: query.by_domain.as_deref(),
            staff: query.staff,
            limit: page(query.limit),
            offset: offset(query.offset),
        },
    )
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| AdminAccountDto::from_row(row, &state))
            .collect(),
    ))
}

/// The pending-registration view, kept at the v2 path Mastodon clients ask for.
async fn pending(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<AccountsQuery>,
) -> ApiResult<Json<Vec<AdminAccountDto>>> {
    auth.require_admin("admin:read")?;
    let pending = query.status.as_deref() == Some("pending");
    let rows = if pending {
        moderation::admin_accounts(
            state.store().pool(),
            &AccountFilter::pending(page(query.limit)),
        )
        .await?
    } else {
        moderation::admin_accounts(
            state.store().pool(),
            &AccountFilter {
                local: Some(true),
                status: query.status.as_deref().filter(|value| *value != "all"),
                username: None,
                display_name: None,
                email: None,
                by_domain: None,
                staff: false,
                limit: page(query.limit),
                offset: offset(query.offset),
            },
        )
        .await?
    };
    Ok(Json(
        rows.into_iter()
            .map(|row| AdminAccountDto::from_row(row, &state))
            .collect(),
    ))
}

#[derive(Debug, Serialize)]
pub struct NoteDto {
    pub id: String,
    pub account_id: String,
    pub author_id: String,
    pub author_username: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct AccountDetailDto {
    #[serde(flatten)]
    pub account: AdminAccountDto,
    pub notes: Vec<NoteDto>,
    /// What a scanner has said about this account's content, newest first. A moderator
    /// deciding on an account wants the evidence in the same response as the account.
    pub flags: Vec<FlagSummaryDto>,
    pub reports_against: i64,
}

#[derive(Debug, Serialize)]
pub struct FlagSummaryDto {
    pub id: String,
    pub reason: String,
    pub severity: String,
    pub labels: Vec<String>,
    pub score: Option<f32>,
    pub state: String,
    pub created_at: DateTime<Utc>,
}

async fn detail(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<AccountDetailDto>> {
    auth.require_admin("admin:read")?;
    let row = moderation::admin_account(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that account does not exist"))?;
    let notes = moderation::notes(state.store().pool(), &id).await?;
    let flags = scanners::flags(state.store().pool(), Some("open"), 100, 0).await?;
    let mut evidence = Vec::new();
    for flag in flags
        .into_iter()
        .filter(|flag| flag.account_id.as_deref() == Some(&id))
    {
        evidence.push(FlagSummaryDto {
            id: flag.id,
            reason: flag.reason,
            severity: flag.severity,
            labels: flag.labels,
            score: flag.score,
            state: flag.state,
            created_at: flag.created_at,
        });
    }
    let against = moderation::reports(
        state.store().pool(),
        &moderation::ReportFilter {
            state: None,
            category: None,
            target_account_id: Some(&id),
            reporter_account_id: None,
            assigned_account_id: None,
            unassigned: false,
            limit: 1,
            offset: 0,
        },
    )
    .await?;
    Ok(Json(AccountDetailDto {
        account: AdminAccountDto::from_row(row, &state),
        notes: notes
            .into_iter()
            .map(|note| NoteDto {
                id: note.id,
                account_id: note.account_id,
                author_id: note.author_id,
                author_username: note.author_username,
                body: note.body,
                created_at: note.created_at,
            })
            .collect(),
        flags: evidence,
        reports_against: i64::try_from(against.len()).unwrap_or(i64::MAX),
    }))
}

#[derive(Debug, Deserialize)]
pub struct ActionForm {
    #[serde(rename = "type")]
    kind: String,
    /// The moderator's reason. Stored on the audit entry and, when it came with a report,
    /// on the report itself.
    #[serde(default)]
    text: String,
    report_id: Option<String>,
    /// Accepted for compatibility; this instance does not send mail yet.
    #[serde(default)]
    send_email_notification: bool,
}

async fn action(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Body(form): Body<ActionForm>,
) -> ApiResult<Json<AdminAccountDto>> {
    auth.require_admin("admin:write")?;
    let action = Action::parse(&form.kind)
        .ok_or_else(|| ApiError::unprocessable(format!("unknown action: {}", form.kind)))?;
    let target = moderation::admin_account(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that account does not exist"))?;
    if target.account.id == auth.0.account.id && action != Action::Enable {
        return Err(ApiError::unprocessable(
            "you cannot take that action against your own account",
        ));
    }
    if target.account.admin && matches!(action, Action::Suspend | Action::Silence | Action::Reject)
    {
        return Err(ApiError::unprocessable(
            "demote an administrator before taking action against them",
        ));
    }
    moderation::apply_action(state.store().pool(), &id, action)
        .await?
        .ok_or_else(|| ApiError::not_found("that account does not exist"))?;
    if let Some(report_id) = form.report_id.as_deref() {
        if moderation::resolve_report(
            state.store().pool(),
            report_id,
            &auth.0.account.id,
            form.text.trim(),
        )
        .await?
        .is_some()
        {
            // The report's own audit row is what the dashboard's resolution count and
            // median time to decision are read from; without it a report closed through
            // this path would be invisible to both.
            let action = if form.text.trim().is_empty() {
                "resolve_report"
            } else {
                "resolve_report_with_note"
            };
            audit_write_detail(
                &state,
                &auth,
                action,
                "report",
                report_id,
                json!({ "note": form.text.trim(), "action": form.kind }),
            )
            .await?;
        }
    }
    let row = moderation::admin_account(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that account does not exist"))?;
    audit_write_detail(
        &state,
        &auth,
        &format!("account_{}", action.as_str()),
        "account",
        &id,
        json!({
            "type": form.kind,
            "text": form.text,
            "report_id": form.report_id,
            "email": form.send_email_notification,
        }),
    )
    .await?;
    Ok(Json(AdminAccountDto::from_row(row, &state)))
}

/// Mastodon's approve/reject endpoints. Kept as thin shims so existing clients work; the
/// console uses the action endpoint, which can carry a note.
async fn approve(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<AdminAccountDto>> {
    auth.require_admin("admin:write")?;
    moderation::apply_action(state.store().pool(), &id, Action::Approve)
        .await?
        .ok_or_else(|| ApiError::not_found("that account does not exist"))?;
    let row = moderation::admin_account(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that account does not exist"))?;
    audit_write_detail(&state, &auth, "account_approve", "account", &id, json!({})).await?;
    Ok(Json(AdminAccountDto::from_row(row, &state)))
}

async fn reject(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<AdminAccountDto>> {
    auth.require_admin("admin:write")?;
    moderation::apply_action(state.store().pool(), &id, Action::Reject)
        .await?
        .ok_or_else(|| ApiError::not_found("that account does not exist"))?;
    let row = moderation::admin_account(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that account does not exist"))?;
    audit_write_detail(&state, &auth, "account_reject", "account", &id, json!({})).await?;
    Ok(Json(AdminAccountDto::from_row(row, &state)))
}

#[derive(Debug, Deserialize)]
pub struct StaffBody {
    staff: bool,
}

#[derive(Debug, Deserialize)]
pub struct RoleBody {
    role: String,
}

/// Changes a staff account's role, mirroring the legacy `admin` boolean in the same write.
///
/// The last administrator cannot be demoted: an instance whose only administrator became
/// a moderator would have nobody left who could appoint one, and no way to fix it from
/// the console.
async fn set_role(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Body(body): Body<RoleBody>,
) -> ApiResult<Json<AdminAccountDto>> {
    auth.require_administrator("admin:write")?;
    let role = body.role.trim();
    if !matches!(role, "none" | "moderator" | "admin") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "role must be none, moderator or admin",
        ));
    }
    let target = moderation::admin_account(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that account does not exist"))?;
    let previous = target.account.staff_role.clone();
    if previous == "admin" && role != "admin" {
        let administrators = accounts::count_role(state.store().pool(), "admin").await?;
        if administrators <= 1 {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "the last administrator cannot be demoted; appoint another administrator first",
            ));
        }
    }
    if !accounts::set_staff_role(state.store().pool(), &id, role).await? {
        return Err(ApiError::not_found("that account does not exist"));
    }
    audit_write_detail(
        &state,
        &auth,
        "change_staff_role",
        "account",
        &id,
        json!({ "previous_role": previous, "role": role }),
    )
    .await?;
    let row = moderation::admin_account(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that account does not exist"))?;
    Ok(Json(AdminAccountDto::from_row(row, &state)))
}

async fn staff(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(body): Json<StaffBody>,
) -> ApiResult<Json<AdminAccountDto>> {
    auth.require_administrator("admin:write")?;
    let target = moderation::admin_account(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that account does not exist"))?;
    if target.account.id == auth.0.account.id && !body.staff {
        return Err(ApiError::unprocessable(
            "you cannot remove your own administration rights",
        ));
    }
    if !moderation::set_staff(state.store().pool(), &id, body.staff).await? {
        return Err(ApiError::not_found("that account does not exist"));
    }
    let row = moderation::admin_account(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that account does not exist"))?;
    audit_write_detail(
        &state,
        &auth,
        if body.staff {
            "grant_staff"
        } else {
            "revoke_staff"
        },
        "account",
        &id,
        json!({}),
    )
    .await?;
    Ok(Json(AdminAccountDto::from_row(row, &state)))
}

#[derive(Debug, Deserialize)]
pub struct NoteBody {
    body: String,
}

async fn add_note(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(body): Json<NoteBody>,
) -> ApiResult<Json<NoteDto>> {
    auth.require_admin("admin:write")?;
    let text = body.body.trim();
    if text.is_empty() {
        return Err(ApiError::unprocessable("a note needs a body"));
    }
    let note = moderation::add_note(state.store().pool(), &id, &auth.0.account.id, text).await?;
    audit_write_detail(
        &state,
        &auth,
        "add_moderator_note",
        "account",
        &id,
        json!({}),
    )
    .await?;
    Ok(Json(NoteDto {
        id: note.id,
        account_id: note.account_id,
        author_id: note.author_id,
        author_username: note.author_username,
        body: note.body,
        created_at: note.created_at,
    }))
}

async fn delete_note(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, note_id)): Path<(String, String)>,
) -> ApiResult<axum::http::StatusCode> {
    auth.require_admin("admin:write")?;
    if !moderation::delete_note(state.store().pool(), &id, &note_id).await? {
        return Err(ApiError::not_found("that note does not exist"));
    }
    audit_write_detail(
        &state,
        &auth,
        "delete_moderator_note",
        "account",
        &id,
        json!({}),
    )
    .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Purges an account and everything it owns. Irreversible, so it refuses the two cases
/// where the caller has almost certainly made a mistake: themselves, and staff.
async fn purge(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<axum::http::StatusCode> {
    auth.require_admin("admin:write")?;
    let target = moderation::admin_account(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that account does not exist"))?;
    if target.account.id == auth.0.account.id {
        return Err(ApiError::unprocessable("you cannot purge your own account"));
    }
    if target.account.admin {
        return Err(ApiError::unprocessable(
            "demote an administrator before purging them",
        ));
    }
    if !nodus_server_store::accounts::purge(state.store().pool(), &id).await? {
        return Err(ApiError::not_found("that account does not exist"));
    }
    audit_write_detail(&state, &auth, "purge_account", "account", &id, json!({})).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct BulkActionForm {
    /// The accounts the moderator selected. Order is preserved in the results.
    #[serde(default)]
    ids: Vec<String>,
    /// `action` is the console's spelling; `type` is what the single-account endpoint and
    /// Mastodon clients send. Both mean the same thing.
    #[serde(rename = "action", alias = "type")]
    kind: String,
    #[serde(default, alias = "text")]
    reason: String,
    /// Accepted for compatibility; this instance does not send mail yet.
    #[serde(default, alias = "send_email_notification")]
    notify: bool,
}

/// One id's outcome, applied on the request's own transaction.
async fn apply_bulk_one(
    conn: &mut sqlx::PgConnection,
    auth: &Auth,
    id: &str,
    action: Action,
    reason: &str,
    notify: bool,
) -> Result<(), BulkFailure> {
    let Some(target) = moderation::admin_account_in(conn, id).await? else {
        return Err(BulkFailure::Rejected(
            "that account does not exist".to_owned(),
        ));
    };
    // The same refusals as the single-row path: those are decisions about one account,
    // so they belong in that account's result rather than failing the other 199.
    if target.account.id == auth.0.account.id && action != Action::Enable {
        return Err(BulkFailure::Rejected(
            "you cannot take that action against your own account".to_owned(),
        ));
    }
    if target.account.admin && matches!(action, Action::Suspend | Action::Silence | Action::Reject)
    {
        return Err(BulkFailure::Rejected(
            "demote an administrator before taking action against them".to_owned(),
        ));
    }
    if moderation::apply_action_in(conn, id, action)
        .await?
        .is_none()
    {
        return Err(BulkFailure::Rejected(
            "that account does not exist".to_owned(),
        ));
    }
    moderation::audit_in(
        conn,
        &auth.0.account.id,
        &format!("account_{}", action.as_str()),
        "account",
        Some(id),
        &json!({
            "type": action.as_str(),
            "text": reason,
            "report_id": null,
            "email": notify,
        }),
    )
    .await?;
    Ok(())
}

/// `POST /api/v1/admin/accounts/bulk` — one action against many accounts.
///
/// One transaction, one audit row per applied account, and a result per id: a moderator
/// who selected 200 accounts needs to know which three did not go through, not just that
/// the request was rejected.
async fn bulk_action(
    State(state): State<AppState>,
    auth: Auth,
    Body(form): Body<BulkActionForm>,
) -> ApiResult<Json<BulkResponseDto>> {
    auth.require_admin("admin:write")?;
    check_batch(&form.ids, "account")?;
    let action = Action::parse(form.kind.trim())
        .ok_or_else(|| ApiError::unprocessable(format!("unknown action: {}", form.kind)))?;
    let reason = form.reason.trim();
    let mut tx = state.store().pool().begin().await?;
    let mut results = Vec::with_capacity(form.ids.len());
    let mut applied = 0i64;
    for id in &form.ids {
        match apply_bulk_one(&mut tx, &auth, id, action, reason, form.notify).await {
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
            // Dropping the transaction rolls back every id already applied.
            Err(BulkFailure::Database(error)) => return Err(error.into()),
        }
    }
    tx.commit().await?;
    Ok(Json(BulkResponseDto { results, applied }))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/accounts", get(list))
        .route("/api/v1/admin/accounts/bulk", post(bulk_action))
        .route("/api/v2/admin/accounts", get(pending))
        .route("/api/v1/admin/accounts/{id}", get(detail).delete(purge))
        .route("/api/v1/admin/accounts/{id}/action", post(action))
        .route("/api/v1/admin/accounts/{id}/approve", post(approve))
        .route("/api/v1/admin/accounts/{id}/reject", post(reject))
        .route("/api/v1/admin/accounts/{id}/staff", post(staff))
        .route("/api/v1/admin/accounts/{id}/role", put(set_role))
        .route("/api/v1/admin/accounts/{id}/notes", post(add_note))
        .route(
            "/api/v1/admin/accounts/{id}/notes/{note_id}",
            delete(delete_note),
        )
}
