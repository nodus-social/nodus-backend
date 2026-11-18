//! The Nodus performance surface: capabilities and hash-chain sync.
//!
//! Everything here is additive. A Mastodon client never calls it; a client that
//! negotiated `nodus-1` uses it to replace a timeline refresh with a diff.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use nodus_server_core::id::Id;
use nodus_server_core::pagination::PageParams;
use nodus_server_sdk::nodus::{
    BatchCall, BatchResponse, BatchResult, Capabilities, SyncDiff, SyncEvent, SyncRoot, Verb,
    CONTRACT_VERSION,
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
        .route("/api/v1/nodus/events", get(events_stream))
        .route("/api/v1/nodus/sync/root", get(root))
        .route("/api/v1/nodus/sync/diff", post(diff))
        .route("/api/v1/nodus/sync/snapshot", get(snapshot))
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

enum AuthorizedCollection<'a> {
    Local,
    Home(&'a str),
}

fn authorize_collection<'a>(
    collection: &'a str,
    viewer_id: &str,
) -> ApiResult<AuthorizedCollection<'a>> {
    if collection.trim().is_empty() {
        return Err(ApiError::unprocessable("collection is required"));
    }
    if collection == "timeline:local" {
        return Ok(AuthorizedCollection::Local);
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
        return Ok(AuthorizedCollection::Home(actor));
    }
    Err(ApiError::unprocessable("unknown collection"))
}

#[derive(Debug, Deserialize)]
struct EventsQuery {
    collection: String,
    #[serde(default)]
    last_event_id: Option<String>,
}

async fn events_stream(
    State(state): State<AppState>,
    auth: Auth,
    axum::extract::Query(query): axum::extract::Query<EventsQuery>,
) -> ApiResult<Sse<impl futures_core::Stream<Item = Result<SseEvent, Infallible>>>> {
    authorize_collection(&query.collection, &auth.0.account.id)?;
    let pool = state.store().pool().clone();
    let collection = query.collection;
    let mut last = match query.last_event_id {
        Some(value) => value,
        None => events::root(&pool, &collection).await?.unwrap_or_default(),
    };
    let (sender, receiver) = tokio::sync::mpsc::channel(64);
    tokio::spawn(async move {
        loop {
            match events::after(&pool, &collection, &last, 100).await {
                Ok(rows) => {
                    for row in rows {
                        last.clone_from(&row.hash);
                        let data = serde_json::to_string(&row.payload).unwrap_or_default();
                        let event = SseEvent::default().id(row.hash).event(row.kind).data(data);
                        if sender.send(Ok(event)).await.is_err() {
                            return;
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "nodus event poll failed");
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    Ok(
        Sse::new(tokio_stream::wrappers::ReceiverStream::new(receiver))
            .keep_alive(KeepAlive::new().interval(Duration::from_secs(15))),
    )
}

async fn capabilities() -> Json<Capabilities> {
    Json(Capabilities::default())
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
struct SnapshotQuery {
    collection: String,
    #[serde(default)]
    max_id: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
}

async fn snapshot(
    State(state): State<AppState>,
    auth: Auth,
    axum::extract::Query(query): axum::extract::Query<SnapshotQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let collection = authorize_collection(&query.collection, &auth.0.account.id)?;
    let root = events::root(state.store().pool(), &query.collection)
        .await?
        .unwrap_or_default();
    let mut params = PageParams::new();
    params.limit = query.limit;
    if let Some(max_id) = query.max_id.as_deref() {
        params.max_id = Some(
            max_id
                .parse::<Id>()
                .map_err(|_| ApiError::unprocessable("max_id is not an id"))?,
        );
    }
    let page = match collection {
        AuthorizedCollection::Local => {
            statuses::public_page(state.store().pool(), params, true).await?
        }
        AuthorizedCollection::Home(actor) => {
            statuses::home_page(state.store().pool(), actor, params).await?
        }
    };
    let mut items = Vec::with_capacity(page.items.len());
    for row in &page.items {
        if let Some(account) = accounts::by_id(state.store().pool(), &row.account_id).await? {
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
    Ok(Json(serde_json::json!({
        "collection": query.collection,
        "root": root,
        "items": items,
        "next": page.next_max_id,
    })))
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
            "history diverged; reset from a snapshot",
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
