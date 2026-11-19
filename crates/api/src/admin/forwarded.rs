//! Telling a peer that its own user broke our rules.
//!
//! Inbound `Flag` activities were already accepted; this is the outbound half. A report
//! about a remote account used to end in a local decision, which the peer could never see
//! and therefore could never act on. Forwarding turns that decision into a signed `Flag`
//! delivered to the reported account's inbox through the normal delivery queue.
//!
//! Anonymity: the activity carries the report's comment, the text of the rules it cites and
//! the moderator's note. It never carries the reporter's account id, handle or actor URI.
//! Mastodon's convention is the same — the forwarded report speaks with the moderator's
//! voice — so the local actor that signs and names itself is the moderator who made the
//! decision, not the person who filed the report. Keeping the reporter out of the payload
//! is what lets a person report a powerful account without being named to it.
//!
//! Object shape: Mastodon sends `Flag` with an array naming the account and its posts. The
//! SDK's generic parser only takes one id or one document, so inbound handling already has
//! `flag_activity` for the array form; we emit exactly that array, and our own parser reads
//! it back symmetrically.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use nodus_server_core::Id;
use nodus_server_store::accounts::{self, AccountRow};
use nodus_server_store::forwarded::{self, ForwardRow};
use nodus_server_store::rules as store_rules;
use nodus_server_store::{delivery, moderation, pauses, statuses};

use super::{audit_write_detail, offset, page};
use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::outbox::actor_of;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct ForwardDto {
    pub id: String,
    pub report_id: String,
    pub target_domain: String,
    pub activity_uri: String,
    pub state: String,
    pub attempts: i32,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<ForwardRow> for ForwardDto {
    fn from(row: ForwardRow) -> Self {
        Self {
            id: row.id,
            report_id: row.report_id,
            target_domain: row.target_domain,
            activity_uri: row.activity_uri,
            state: row.state,
            attempts: row.attempts,
            last_error: row.last_error,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct ForwardBody {
    /// The moderator's note. Mastodon calls the same field "forward" and the note on the
    /// report is what travels; the reporter's identity does not.
    #[serde(default)]
    pub note: String,
}

/// The domain a reported account lives on, or `None` for a local account.
fn remote_domain(target: &AccountRow) -> Option<String> {
    if target.local {
        return None;
    }
    target
        .domain
        .as_deref()
        .map(str::trim)
        .filter(|domain| !domain.is_empty())
        .map(str::to_lowercase)
}

/// Refuses a target that must never be contacted, in an order that leaks nothing.
///
/// The report was already checked to exist by the caller, because a bad id is a 404 about
/// the report, not about the domain. After that: a local account is refused before any
/// domain policy is read, so a local id can never be used to probe whether a domain is
/// blocked. A blocked domain is checked before a paused one because the block is final.
/// Both are checked before the inbox is read, so a refusal never echoes the account's
/// remote addresses back to the caller.
async fn sendable_domain(state: &AppState, target: &AccountRow) -> ApiResult<(String, String)> {
    let Some(domain) = remote_domain(target) else {
        return Err(ApiError::unprocessable(
            "only a remote account can be forwarded to its own instance; \
             a local account is moderated here",
        ));
    };
    if moderation::blocked_domain(state.store().pool(), &domain)
        .await?
        .is_some()
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "that domain is blocked; a blocked domain is never contacted",
        ));
    }
    if pauses::in_force(state.store().pool(), &domain).await? {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "that domain is paused; nothing is delivered while the pause is in force",
        ));
    }
    let inbox = delivery::inbox_of(state.store().pool(), &target.id)
        .await?
        .ok_or_else(|| {
            ApiError::unprocessable("that account has no inbox, so there is nowhere to send")
        })?;
    Ok((domain, inbox))
}

/// Builds the `content` a peer's moderators read.
///
/// Deliberately built from the report's comment, the cited rule texts and the moderator's
/// note only. No reporter field is inserted here, and none may be added without breaking
/// the promise above.
async fn forward_content(
    state: &AppState,
    report: &moderation::ReportRow,
    note: &str,
) -> ApiResult<String> {
    let cited = store_rules::by_ids(state.store().pool(), &report.rule_ids).await?;
    let mut parts = Vec::new();
    if !report.comment.trim().is_empty() {
        parts.push(report.comment.trim().to_owned());
    }
    let mut rules = Vec::new();
    for id in &report.rule_ids {
        if let Some(rule) = cited.iter().find(|rule| &rule.id == id) {
            rules.push(format!("- {}", rule.text));
        }
    }
    if !rules.is_empty() {
        parts.push(format!("Rules cited:\n{}", rules.join("\n")));
    }
    if !note.trim().is_empty() {
        parts.push(format!("Moderator note: {}", note.trim()));
    }
    Ok(parts.join("\n\n"))
}

/// The signed `Flag`, in the shape our inbound parser also understands.
///
/// `object` is an array — account first, then the reported posts — which is what Mastodon
/// emits and what `activitypub::flag_activity` accepts as its fallback. `actor` is the
/// moderator who made the decision; it matches the key the delivery queue signs with.
fn flag_activity(
    state: &AppState,
    moderator: &AccountRow,
    target: &AccountRow,
    posts: &[String],
    content: &str,
    activity_uri: &str,
) -> ApiResult<Value> {
    let actor = actor_of(state, &moderator.username, moderator.uri.as_deref());
    let target_uri = target.uri.clone().ok_or_else(|| {
        ApiError::unprocessable("that account has no actor URI, so a peer cannot resolve it")
    })?;
    let mut object = Vec::with_capacity(posts.len() + 1);
    object.push(Value::String(target_uri.clone()));
    object.extend(posts.iter().cloned().map(Value::String));
    Ok(json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": activity_uri,
        "type": "Flag",
        // Signed by, and naming, the moderator who decided to forward. The reporter is
        // not present anywhere in this document.
        "actor": actor,
        "object": object,
        "content": content,
        "to": [target_uri],
        "published": Utc::now().to_rfc3339(),
    }))
}

/// Forwards one report, or returns the forward that already exists.
///
/// Returns `(created, row)`: `created` is false on an idempotent replay, which the HTTP
/// route turns into a 200 rather than a 202. The report id is re-read here instead of
/// trusting a caller-supplied row, so the resolve path and the dedicated route agree.
pub(super) async fn forward_report(
    state: &AppState,
    auth: &Auth,
    report_id: &str,
    note: &str,
) -> ApiResult<(bool, ForwardRow)> {
    let pool = state.store().pool();
    let report = moderation::report(pool, report_id)
        .await?
        .ok_or_else(|| ApiError::not_found("that report does not exist"))?;

    // Idempotency comes before every policy check. The first forward already happened;
    // re-asking is about that row, not about the target's current state, and returning it
    // is the only answer that does not queue a second Flag.
    if let Some(row) = forwarded::by_report(pool, &report.id).await? {
        return Ok((false, row));
    }

    let target = accounts::by_id(pool, &report.target_account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("the reported account no longer exists"))?;
    let (domain, inbox) = sendable_domain(state, &target).await?;

    // The queue signs with this account's key, so a forward without one would sit in the
    // queue forever. Refuse now, where the moderator can be told, rather than silently.
    if delivery::signing_key(pool, &auth.0.account.id)
        .await?
        .is_none()
    {
        return Err(ApiError::unprocessable(
            "your account has no federation signing key yet",
        ));
    }

    let mut posts = Vec::new();
    for id in &report.status_ids {
        if let Some(status) = statuses::by_id(pool, id).await? {
            if status.account_id == target.id {
                if let Some(uri) = status.uri {
                    posts.push(uri);
                }
            }
        }
    }
    let content = forward_content(state, &report, note).await?;
    let actor = actor_of(
        state,
        &auth.0.account.username,
        auth.0.account.uri.as_deref(),
    );
    let activity_uri = format!("{actor}#flags/{}", Id::new());
    let activity = flag_activity(
        state,
        &auth.0.account,
        &target,
        &posts,
        &content,
        &activity_uri,
    )?;

    // Reserve the row before queueing: the unique report id is what makes two concurrent
    // requests produce one Flag. A loser re-reads the winner's row and returns it.
    let Some(row) = forwarded::create(pool, &report.id, &domain, &activity_uri).await? else {
        let row = forwarded::by_report(pool, &report.id)
            .await?
            .ok_or_else(|| ApiError::not_found("that report does not exist"))?;
        return Ok((false, row));
    };

    match delivery::enqueue(pool, &auth.0.account.id, &activity, &[inbox]).await {
        Ok(0) => {
            // The queue filters suspended inboxes and blocked/paused hosts. We checked the
            // two policy cases above, so this is a per-account suspension; say so without
            // naming anything the peer would not already know.
            forwarded::delete(pool, &row.id).await?;
            Err(ApiError::new(
                StatusCode::CONFLICT,
                "delivery to that account is currently suppressed",
            ))
        }
        Ok(_) => {
            audit_write_detail(
                state,
                auth,
                "forward_report",
                "report",
                &report.id,
                json!({ "domain": domain, "activity": activity_uri }),
            )
            .await?;
            Ok((true, row))
        }
        Err(error) => {
            forwarded::delete(pool, &row.id).await?;
            Err(error.into())
        }
    }
}

/// `POST /api/v1/admin/reports/{id}/forward` — send the report to the peer.
async fn create_forward(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    body: Option<Json<ForwardBody>>,
) -> ApiResult<(StatusCode, Json<ForwardDto>)> {
    auth.require_admin("admin:write")?;
    let note = body.map(|Json(body)| body.note).unwrap_or_default();
    let (created, row) = forward_report(&state, &auth, &id, note.trim()).await?;
    let status = if created {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(row.into())))
}

/// `GET /api/v1/admin/reports/{id}/forward` — what we sent, and what happened.
async fn show_forward(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<ForwardDto>> {
    auth.require_admin("admin:read")?;
    let row = forwarded::by_report(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that report was never forwarded"))?;
    Ok(Json(row.into()))
}

#[derive(Debug, Deserialize)]
pub struct ForwardedQuery {
    state: Option<String>,
    domain: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

/// `GET /api/v1/admin/federation/forwarded` — every report we sent to a peer.
async fn list_forwarded(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<ForwardedQuery>,
) -> ApiResult<Json<Vec<ForwardDto>>> {
    auth.require_admin("admin:read")?;
    let wanted = query.state.as_deref().filter(|value| !value.is_empty());
    if let Some(value) = wanted {
        if !forwarded::STATES.contains(&value) {
            return Err(ApiError::unprocessable(
                "state is pending, delivered, failed or gave_up",
            ));
        }
    }
    let domain = query
        .domain
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_lowercase);
    let rows = forwarded::list(
        state.store().pool(),
        wanted,
        domain.as_deref(),
        page(query.limit),
        offset(query.offset),
    )
    .await?;
    Ok(Json(rows.into_iter().map(ForwardDto::from).collect()))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/admin/reports/{id}/forward",
            get(show_forward).post(create_forward),
        )
        .route("/api/v1/admin/federation/forwarded", get(list_forwarded))
}
