//! The Nodus performance surface: capabilities and hash-chain sync.
//!
//! Everything here is additive. A Mastodon client never calls it; a client that
//! negotiated `nodus-1` uses it to replace a timeline refresh with a diff.

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use nodus_server_core::id::Id;
use nodus_server_core::pagination::PageParams;
use nodus_server_sdk::nodus::{
    BatchCall, BatchResponse, BatchResult, SyncDiff, SyncEvent, SyncRoot, Verb, CONTRACT_VERSION,
};
use nodus_server_store::{accounts, events, statuses};

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// The Nodus routes, without a state attached.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/nodus/capabilities", get(capabilities))
        .route("/api/v1/nodus/batch", post(batch))
        .route("/api/v1/nodus/events", get(events_gone))
        .route("/api/v1/nodus/sync/root", get(root))
        .route("/api/v1/nodus/sync/diff", post(diff))
        .route("/api/v1/nodus/account/role", get(account_role))
        .merge(crate::client_metadata::router())
}

#[derive(Debug, serde::Serialize)]
struct AccountRoleDto {
    /// `none`, `moderator` or `admin`.
    role: String,
    /// What this particular token may do, which can be narrower than the role: an
    /// administrator whose token only asked for `read` cannot write with it either.
    scopes: Vec<String>,
}

/// Which door this account walks through, so a console can offer the right one before it
/// tries an admin route at all.
///
/// Any signed-in account may ask: a plain user is told `none` and to ask an administrator,
/// rather than being walked into a permission error that only a database edit could fix.
async fn account_role(auth: Auth) -> Json<AccountRoleDto> {
    Json(AccountRoleDto {
        role: auth.0.account.staff_role.clone(),
        scopes: auth.0.scopes.clone(),
    })
}

/// Rejects a collection the caller may not read, before any row is touched.
///
/// Authored for the sync routes, which used to branch on the answer; `snapshot` was the
/// reader that needed the distinction and it is gone, so this now only authorises.
fn authorize_collection(collection: &str, viewer_id: &str) -> ApiResult<()> {
    if collection.trim().is_empty() {
        return Err(ApiError::unprocessable("collection is required"));
    }
    if collection == "timeline:local" {
        return Ok(());
    }
    if let Some(actor) = collection.strip_prefix("timeline:") {
        if actor.is_empty() {
            return Err(ApiError::unprocessable("unknown collection"));
        }
        if actor != viewer_id {
            return Err(ApiError::forbidden(
                "cannot access another account's collection",
            ));
        }
        return Ok(());
    }
    Err(ApiError::unprocessable("unknown collection"))
}

/// `GET /api/v1/nodus/events` — retired, and answered rather than removed.
///
/// It was the nodus-1 SSE tail of the same `events` table `/api/v1/streaming` now tails,
/// and nothing under `web/`, `sdk/` or `server-sdk/` ever subscribed to it. It is a `410`
/// rather than a deleted route because an SSE client cannot tell a `404` from a dropped
/// connection: it reconnects on both, forever. A `410` with the replacement in the body is
/// the one answer that stops the loop and tells the next reader where the surface went.
async fn events_gone() -> ApiError {
    ApiError::new(
        axum::http::StatusCode::GONE,
        "this endpoint was replaced by /api/v1/streaming",
    )
}

/// The capability vocabulary, as `GET /api/v1/meta` publishes it.
///
/// This document is a view of that one list, not a second one: `features` here is
/// [`crate::meta::features`] called with the same switch as `/api/v1/meta`, so
/// `/api/v1/nodus/capabilities` is a subset of the same set with the same meaning — in
/// practice, equal to it. The earlier
/// `["batch", "events", "state_sync"]` was a second vocabulary for the same idea:
/// `state_sync` named nothing a client could call, and none of the three told a console
/// anything `/api/v1/meta` did not. Only `contract` is this document's own; it says which
/// dialect answered, not what the instance can do. `tests/capabilities.rs` asserts that the
/// two lists are the same set.
#[derive(Debug, serde::Serialize)]
struct CapabilitiesDto {
    contract: String,
    features: Vec<String>,
}

async fn capabilities(State(state): State<AppState>) -> Json<CapabilitiesDto> {
    Json(CapabilitiesDto {
        contract: CONTRACT.to_owned(),
        features: crate::meta::features(state.drive_share()),
    })
}

async fn batch(
    State(state): State<AppState>,
    auth: Auth,
    Json(calls): Json<Vec<BatchCall>>,
) -> ApiResult<Json<BatchResponse>> {
    if calls.len() > 20 {
        return Err(ApiError::unprocessable("at most 20 calls per batch"));
    }
    let mut results = Vec::with_capacity(calls.len());
    for call in calls {
        let (value, error) = match call.call {
            Verb::Account { id } => match accounts::by_id(state.store().pool(), &id).await? {
                Some(account) => (
                    Some(
                        serde_json::to_value(crate::dto::AccountDto::from_row(
                            &account,
                            state.instance(),
                        ))
                        .map_err(|error| serialise_error(&error))?,
                    ),
                    None,
                ),
                None => (None, Some("account not found".to_owned())),
            },
            Verb::Status { id } => match statuses::by_id(state.store().pool(), &id).await? {
                Some(row) if crate::statuses::can_view(&state, Some(&auth), &row).await? => {
                    match accounts::by_id(state.store().pool(), &row.account_id).await? {
                        Some(account) => (
                            Some(
                                serde_json::to_value(crate::dto::StatusDto::from_row(
                                    &row,
                                    &account,
                                    state.instance(),
                                ))
                                .map_err(|error| serialise_error(&error))?,
                            ),
                            None,
                        ),
                        None => (None, Some("status author not found".to_owned())),
                    }
                }
                _ => (None, Some("status not found".to_owned())),
            },
            Verb::Timeline {
                name,
                max_id,
                limit,
            } => {
                let mut params = PageParams::new();
                params.limit = limit;
                if let Some(max_id) = max_id.as_deref() {
                    params.max_id = Some(
                        max_id
                            .parse::<Id>()
                            .map_err(|_| ApiError::unprocessable("max_id is not an id"))?,
                    );
                }
                let local = !name.contains("global") && !name.contains("federated");
                let page = statuses::public_page(state.store().pool(), params, local).await?;
                let mut items = Vec::with_capacity(page.items.len());
                for row in &page.items {
                    if let Some(account) =
                        accounts::by_id(state.store().pool(), &row.account_id).await?
                    {
                        items.push(
                            serde_json::to_value(crate::dto::StatusDto::from_row(
                                row,
                                &account,
                                state.instance(),
                            ))
                            .map_err(|error| serialise_error(&error))?,
                        );
                    }
                }
                (Some(serde_json::Value::Array(items)), None)
            }
            Verb::Context { .. } => (
                None,
                Some("context is not implemented in batch yet".to_owned()),
            ),
        };
        results.push(BatchResult {
            id: call.id,
            value,
            error,
        });
    }
    Ok(Json(BatchResponse { results }))
}

fn serialise_error(error: &serde_json::Error) -> ApiError {
    ApiError::new(
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        error.to_string(),
    )
}

#[derive(Debug, Deserialize)]
struct RootQuery {
    collection: String,
}

async fn root(
    State(state): State<AppState>,
    auth: Auth,
    axum::extract::Query(query): axum::extract::Query<RootQuery>,
) -> ApiResult<Json<SyncRoot>> {
    authorize_collection(&query.collection, &auth.0.account.id)?;
    let hash = events::root(state.store().pool(), &query.collection)
        .await?
        .unwrap_or_default();
    let count = events::count(state.store().pool(), &query.collection).await?;
    Ok(Json(SyncRoot {
        collection: query.collection,
        hash,
        count: u64::try_from(count).unwrap_or_default(),
    }))
}

#[derive(Debug, Deserialize)]
struct DiffBody {
    collection: String,
    since: String,
    #[serde(default)]
    limit: Option<u32>,
}

async fn diff(
    State(state): State<AppState>,
    auth: Auth,
    Json(body): Json<DiffBody>,
) -> ApiResult<Json<SyncDiff>> {
    if body.collection.trim().is_empty() || body.since.trim().is_empty() {
        return Err(ApiError::unprocessable("collection and since are required"));
    }
    authorize_collection(&body.collection, &auth.0.account.id)?;
    let to = events::root(state.store().pool(), &body.collection)
        .await?
        .unwrap_or_default();
    if body.since == to {
        return Ok(Json(SyncDiff {
            collection: body.collection,
            from: body.since,
            to,
            events: Vec::new(),
        }));
    }
    if !events::knows(state.store().pool(), &body.collection, &body.since).await? {
        return Err(ApiError::new(
            axum::http::StatusCode::CONFLICT,
            "history diverged; fetch the timeline and re-root",
        ));
    }
    let limit = i64::from(body.limit.unwrap_or(500).clamp(1, 500));
    let rows = events::after(state.store().pool(), &body.collection, &body.since, limit).await?;
    let events = rows
        .into_iter()
        .map(|row| SyncEvent {
            id: row.id,
            kind: row.kind,
            payload: row.payload,
        })
        .collect();
    Ok(Json(SyncDiff {
        collection: body.collection,
        from: body.since,
        to,
        events,
    }))
}

/// A stable contract string for tests and clients that only want the version.
pub const CONTRACT: &str = CONTRACT_VERSION;
