//! The account directory.
//!
//! Two jobs live here: finding an account (by name, mail or domain) and doing something
//! about it (approve, silence, suspend, promote, annotate, purge). The action endpoint
//! takes the Mastodon form shape because that is what every existing client sends, and the
//! moderator's note is part of the action rather than a second request: a decision without
//! its reason is a decision nobody can review later.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use nodus_server_store::moderation::{self, AccountFilter, Action, AdminAccountRow, Notice};
use nodus_server_store::{accounts, rules, scanners};

use super::Body;
use crate::auth::Auth;
use crate::dto::AccountDto;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

use super::{audit_write_detail, offset, page};
use super::{check_batch, csv_cell, csv_response, AccountBulkItemDto, AccountBulkResponseDto, BulkFailure};

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
    /// This account's media is shown behind a warning without the account being silenced.
    pub sensitive: bool,
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
    /// Live strikes inside the policy window. A moderator reads this instead of opening the
    /// audit log to reconstruct how many times this account has been here.
    pub strike_count: i64,
    /// What the escalation policy would do next, and at how many strikes: `null` when the
    /// policy is disabled or the account already sits at its top step.
    pub next_escalation: Option<serde_json::Value>,
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
            sensitive: row.account.sensitized_at.is_some(),
            disabled: !row.account.approved,
            admin: row.account.admin,
            role: row.account.staff_role,
            created_at: row.account.created_at,
            open_reports: row.open_reports,
            notes_count: row.notes,
            lossless_images: row.account.lossless_images_default,
            lossless_videos: row.account.lossless_videos_default,
            strike_count: row.strike_count,
            next_escalation: row.next_escalation,
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
    moderation::apply_action_noted(
        state.store().pool(),
        &id,
        action,
        &Notice {
            reason: form.text.trim(),
            // A moderator's own click names no rule; only the rule engine does.
            rule: None,
            rule_id: None,
            actor_id: Some(&auth.0.account.id),
            expires_at: None,
            strike: None,
        },
    )
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
    moderation::apply_action_noted(
        state.store().pool(),
        &id,
        Action::Approve,
        &Notice {
            actor_id: Some(&auth.0.account.id),
            ..Notice::default()
        },
    )
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
    moderation::apply_action_noted(
        state.store().pool(),
        &id,
        Action::Reject,
        &Notice {
            actor_id: Some(&auth.0.account.id),
            ..Notice::default()
        },
    )
    .await?
    .ok_or_else(|| ApiError::not_found("that account does not exist"))?;
    let row = moderation::admin_account(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that account does not exist"))?;
    audit_write_detail(&state, &auth, "account_reject", "account", &id, json!({})).await?;
    Ok(Json(AdminAccountDto::from_row(row, &state)))
}

#[derive(Debug, Deserialize)]
pub struct WarnForm {
    /// A canned warning from the console's preset list. Its text stands in when the
    /// moderator writes none of their own.
    preset_id: Option<String>,
    /// The moderator's words, stored verbatim on the notification *and* on the audit row
    /// so the two records read as one decision.
    #[serde(default)]
    text: String,
    /// Instance rules the warning cites, so the person can look up what they broke.
    #[serde(default)]
    rule_ids: Vec<String>,
}

/// The longest warning worth sending; longer than this is a report, not a warning.
const WARN_TEXT_MAX: usize = 2000;

/// `POST /api/v1/admin/accounts/{id}/warn` — tell a person to stop, change nothing.
///
/// Every other decision here changes what the account may do. A warning does not: it
/// exists because the right answer to a first offence is often "we saw that" rather than
/// a silence the person has to appeal. So this handler writes a notification and an audit
/// row and touches no column of `account` — deliberately, so that a warning can never
/// quietly become a restriction.
async fn warn(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Body(form): Body<WarnForm>,
) -> ApiResult<Json<AdminAccountDto>> {
    auth.require_admin("admin:write")?;
    let target = moderation::admin_account(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that account does not exist"))?;
    if target.account.id == auth.0.account.id {
        return Err(ApiError::unprocessable("you cannot warn your own account"));
    }
    let text = match form.text.trim() {
        "" => match form.preset_id.as_deref() {
            Some(preset_id) => {
                moderation::warning_presets(state.store().pool())
                    .await?
                    .into_iter()
                    .find(|preset| preset.id == preset_id)
                    .ok_or_else(|| ApiError::not_found("that warning preset does not exist"))?
                    .text
            }
            None => return Err(ApiError::unprocessable("a warning needs text or a preset")),
        },
        written => written.to_owned(),
    };
    if text.chars().count() > WARN_TEXT_MAX {
        return Err(ApiError::unprocessable(format!(
            "text must be at most {WARN_TEXT_MAX} characters"
        )));
    }
    // A warning that cites a rule nobody can read is worse than one that cites none: the
    // person would be told they broke something they cannot find. Unknown ids are an
    // error rather than skipped.
    let cited = rules::by_ids(state.store().pool(), &form.rule_ids).await?;
    let distinct: std::collections::BTreeSet<&str> =
        form.rule_ids.iter().map(String::as_str).collect();
    if cited.len() != distinct.len() {
        return Err(ApiError::unprocessable("one of those rules does not exist"));
    }
    let rule = (!cited.is_empty()).then(|| {
        cited
            .iter()
            .map(|rule| rule.text.clone())
            .collect::<Vec<_>>()
            .join("\n")
    });

    let mut tx = state.store().pool().begin().await?;
    moderation::warn_in(&mut tx, &id, &auth.0.account.id, &text, rule.as_deref()).await?;
    moderation::audit_in(
        &mut tx,
        &auth.0.account.id,
        "account_warn",
        "account",
        Some(&id),
        &json!({
            "type": "warn",
            "text": text,
            "preset_id": form.preset_id,
            "rule_ids": form.rule_ids,
            "rule": rule,
        }),
    )
    .await?;
    tx.commit().await?;

    let row = moderation::admin_account(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that account does not exist"))?;
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
    /// The report the moderator is acting from, when there is one. Applied once for the
    /// whole batch: every account in it was selected from the same case.
    report_id: Option<String>,
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
    report_id: Option<&str>,
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
    if moderation::apply_action_noted_in(
        conn,
        id,
        action,
        &Notice {
            reason,
            rule: None,
            rule_id: None,
            actor_id: Some(&auth.0.account.id),
            expires_at: None,
            strike: None,
        },
    )
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
            "report_id": report_id,
            "email": notify,
        }),
    )
    .await?;
    Ok(())
}

/// `POST /api/v1/admin/accounts/bulk` — one action against many accounts.
///
/// The actions are the single-account ones plus the media flag: `silence`, `unsilence`,
/// `suspend`, `unsuspend`, `sensitive`, `unsensitive`, `approve`, `reject` and `enable`.
/// Every applied id goes through [`moderation::apply_action_noted_in`] and gets the same
/// audit row the single-account endpoint writes, so a later `unsuspend` leaves the earlier
/// `suspend` on the record instead of overwriting it.
///
/// # Partial failure
///
/// One transaction, and a result per id. A rejected id (unknown account, an administrator
/// who must be demoted first, the caller's own account) is a fact about that id: it is
/// reported in that id's result and the other decisions still commit. A *database* error
/// is a fact about the request — it aborts and rolls the whole batch back, because at that
/// point nobody knows which ids were written. The two are deliberately different: a
/// moderator mistyping one id must not lose the other ninety-nine decisions.
async fn bulk_action(
    State(state): State<AppState>,
    auth: Auth,
    Body(form): Body<BulkActionForm>,
) -> ApiResult<Json<AccountBulkResponseDto>> {
    auth.require_admin("admin:write")?;
    check_batch(&form.ids, "account")?;
    let action = Action::parse(form.kind.trim())
        .ok_or_else(|| ApiError::unprocessable(format!("unknown action: {}", form.kind)))?;
    let reason = form.reason.trim();
    let mut tx = state.store().pool().begin().await?;
    let mut results = Vec::with_capacity(form.ids.len());
    let mut applied = 0i64;
    for id in &form.ids {
        match apply_bulk_one(
            &mut tx,
            &auth,
            id,
            action,
            reason,
            form.report_id.as_deref(),
            form.notify,
        )
        .await
        {
            Ok(()) => {
                applied += 1;
                results.push(AccountBulkItemDto {
                    account_id: id.clone(),
                    ok: true,
                    error: None,
                });
            }
            Err(BulkFailure::Rejected(message)) => results.push(AccountBulkItemDto {
                account_id: id.clone(),
                ok: false,
                error: Some(message),
            }),
            // Dropping the transaction rolls back every id already applied.
            Err(BulkFailure::Database(error)) => return Err(error.into()),
        }
    }
    tx.commit().await?;
    if let Some(report_id) = form.report_id.as_deref() {
        if moderation::resolve_report(
            state.store().pool(),
            report_id,
            &auth.0.account.id,
            reason,
        )
        .await?
        .is_some()
        {
            // The same report audit row the single-account path writes, so a report closed
            // through a batch still counts towards the dashboard's resolution figures.
            let audit_action = if reason.is_empty() {
                "resolve_report"
            } else {
                "resolve_report_with_note"
            };
            audit_write_detail(
                &state,
                &auth,
                audit_action,
                "report",
                report_id,
                json!({
                    "note": reason,
                    "action": action.as_str(),
                    "accounts": form.ids.len(),
                }),
            )
            .await?;
        }
    }
    Ok(Json(AccountBulkResponseDto { results, applied }))
}

/// How many rows one export read asks for. A page is a few hundred kilobytes of text:
/// big enough that a long file is not one round trip per row, small enough that no page
/// ever holds more than one screenful of rows in memory.
const ACCOUNTS_CSV_PAGE: i64 = 500;

/// The state the account export stream carries between chunks.
struct AccountsCsvCursor {
    pool: sqlx::PgPool,
    local: Option<bool>,
    status: Option<String>,
    username: Option<String>,
    display_name: Option<String>,
    email: Option<String>,
    by_domain: Option<String>,
    staff: bool,
    offset: i64,
    header_sent: bool,
    done: bool,
}

fn account_csv_row(row: &AdminAccountRow) -> String {
    let account = &row.account;
    let cells = [
        csv_cell(&account.id),
        csv_cell(&account.username),
        csv_cell(account.domain.as_deref().unwrap_or("")),
        csv_cell(row.email.as_deref().unwrap_or("")),
        csv_cell(&account.created_at.to_rfc3339()),
        csv_cell(if account.approved { "true" } else { "false" }),
        csv_cell(if account.silenced_at.is_some() { "true" } else { "false" }),
        csv_cell(if account.suspended_at.is_some() { "true" } else { "false" }),
        csv_cell(if account.sensitized_at.is_some() { "true" } else { "false" }),
        csv_cell(&account.staff_role),
        csv_cell(&row.open_reports.to_string()),
        csv_cell(&row.strike_count.to_string()),
    ];
    let mut line = cells.join(",");
    line.push_str("\r\n");
    line
}

/// `GET /api/v1/admin/accounts/export.csv` — the account directory as a file.
///
/// The filters are [`AccountsQuery`]'s, minus `limit` and `offset`: the export pages
/// itself, so a client cannot widen what it sees by asking the file for more than the
/// list route would return at the same filters. Both routes also share the `admin:read`
/// grant.
///
/// # What leaves the instance, and why
///
/// One row per account the list would show, so an operator can act on a row after
/// closing the console:
///
/// - `id`, `username`, `domain` — the identity a bulk action has to name; `domain` is
///   empty for local accounts.
/// - `email` — local accounts only, empty when none is set. A decision has to be told to
///   the person it is about, and this file is where that address lives once the console
///   is closed. The list route already hands it to the same grant.
/// - `created_at`, `approved`, `silenced`, `suspended`, `sensitive`, `role` — the state
///   the list shows, so a row is readable without a second request.
/// - `open_reports`, `strike_count` — why a moderator would look at this row at all.
///
/// The last IP is deliberately left out: the list returns it for one account a moderator
/// is already examining, but a file of every address on the instance is a fingerprinting
/// surface nobody asked to sort by. `disabled` is left out too because it is exactly
/// `!approved`, and two columns that must agree are two columns that can disagree.
///
/// # Bounding
///
/// Rows are read one page at a time and each page is streamed and dropped, so a two
/// hundred thousand row export costs one page of memory rather than the whole table. No
/// row cap is applied, and therefore none needs announcing in the response: the file is
/// complete or the transfer fails.
async fn export_csv(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<AccountsQuery>,
) -> ApiResult<Response> {
    auth.require_admin("admin:read")?;
    let local = match query.origin.as_deref() {
        Some("local") => Some(true),
        Some("remote") => Some(false),
        _ => None,
    };
    let cursor = AccountsCsvCursor {
        pool: state.store().pool().clone(),
        local,
        status: query.status,
        username: query.username,
        display_name: query.display_name,
        email: query.email,
        by_domain: query.by_domain,
        staff: query.staff,
        offset: 0,
        header_sent: false,
        done: false,
    };
    let stream = futures_util::stream::unfold(cursor, |mut cursor| async move {
        if !cursor.header_sent {
            cursor.header_sent = true;
            let header = "id,username,domain,email,created_at,approved,silenced,suspended,\
                          sensitive,role,open_reports,strike_count\r\n";
            return Some((
                Ok::<Bytes, std::io::Error>(Bytes::from_static(header.as_bytes())),
                cursor,
            ));
        }
        if cursor.done {
            return None;
        }
        let rows = moderation::admin_accounts(
            &cursor.pool,
            &AccountFilter {
                local: cursor.local,
                status: cursor.status.as_deref().filter(|value| *value != "all"),
                username: cursor.username.as_deref(),
                display_name: cursor.display_name.as_deref(),
                email: cursor.email.as_deref(),
                by_domain: cursor.by_domain.as_deref(),
                staff: cursor.staff,
                limit: ACCOUNTS_CSV_PAGE,
                offset: cursor.offset,
            },
        )
        .await;
        match rows {
            // A failed read has to break the transfer: a file that ends quietly would
            // look complete to whoever opens it next month.
            Err(error) => {
                tracing::error!(error = %error, "account export read failed");
                Some((
                    Err::<Bytes, std::io::Error>(std::io::Error::other(
                        "account export read failed",
                    )),
                    cursor,
                ))
            }
            Ok(rows) if rows.is_empty() => None,
            Ok(rows) => {
                let read = i64::try_from(rows.len()).unwrap_or(i64::MAX);
                if read < ACCOUNTS_CSV_PAGE {
                    cursor.done = true;
                }
                cursor.offset += read;
                let mut chunk = String::new();
                for row in &rows {
                    chunk.push_str(&account_csv_row(row));
                }
                Some((Ok::<Bytes, std::io::Error>(Bytes::from(chunk)), cursor))
            }
        }
    });
    csv_response("accounts.csv", stream)
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/accounts", get(list))
        .route("/api/v1/admin/accounts/export.csv", get(export_csv))
        .route("/api/v1/admin/accounts/bulk", post(bulk_action))
        .route("/api/v2/admin/accounts", get(pending))
        .route("/api/v1/admin/accounts/{id}", get(detail).delete(purge))
        .route("/api/v1/admin/accounts/{id}/action", post(action))
        .route("/api/v1/admin/accounts/{id}/approve", post(approve))
        .route("/api/v1/admin/accounts/{id}/reject", post(reject))
        .route("/api/v1/admin/accounts/{id}/warn", post(warn))
        .route("/api/v1/admin/accounts/{id}/staff", post(staff))
        .route("/api/v1/admin/accounts/{id}/role", put(set_role))
        .route("/api/v1/admin/accounts/{id}/notes", post(add_note))
        .route(
            "/api/v1/admin/accounts/{id}/notes/{note_id}",
            delete(delete_note),
        )
}
