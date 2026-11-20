//! `GET /api/v1/streaming`: Mastodon's live event stream over Server-Sent Events.
//!
//! The streams are fed by `nodus_server_store::live`, which publishes at the write site
//! (notification insert, status create/delete, mute/block) rather than polling. This
//! module turns those ids into Mastodon's JSON and writes the SSE wire format.
//!
//! The token may arrive in `Authorization: Bearer` *or* in `access_token`, and the query
//! parameter is deliberate rather than a fallback: `EventSource` cannot set headers, so
//! every Mastodon client that streams puts the token there. It is resolved before the
//! response body is built, so an anonymous caller gets a JSON `401` and never an open
//! stream that dies on its first event.

use std::convert::Infallible;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Query, State};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use futures_util::{stream, StreamExt};
use serde::Deserialize;
use tokio::sync::watch;
use tokio::time::{self, Instant};
use tracing::warn;

use nodus_server_store::live::{self, LiveEvent, Subscription};

use crate::auth::{authenticate, Auth};
use crate::conversations::ConversationDto;
use crate::dto::AccountDto;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::statuses;

/// The keepalive interval, in seconds, from `NODUS_STREAM_KEEPALIVE_SECS` (default 15).
///
/// Configurable so the test can watch one arrive in a second instead of sleeping through
/// the production interval.
fn keepalive_period() -> Duration {
    let seconds = std::env::var("NODUS_STREAM_KEEPALIVE_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .unwrap_or(15);
    Duration::from_secs(seconds)
}

/// Which of Mastodon's streams the caller asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Everything about this account: its notifications, its posts, its deletes, its
    /// direct conversations, and its filter changes.
    User,
    /// Only the account's notifications.
    Notification,
    /// Only additions to (and deletions from) the account's home timeline.
    Home,
}

impl Kind {
    fn parse(raw: Option<&str>) -> Result<Self, ApiError> {
        match raw.unwrap_or("user") {
            "user" => Ok(Self::User),
            "user:notification" => Ok(Self::Notification),
            "user:home" => Ok(Self::Home),
            other => Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("Unknown stream: {other}"),
            )),
        }
    }

    fn wants(self, event: &LiveEvent) -> bool {
        match self {
            Self::User => true,
            Self::Notification => matches!(event, LiveEvent::Notification { .. }),
            Self::Home => {
                matches!(event, LiveEvent::Update { .. } | LiveEvent::Delete { .. })
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct StreamQuery {
    stream: Option<String>,
    /// The deliberate EventSource-compatible token location; see the module docs.
    access_token: Option<String>,
}

/// `GET /api/v1/streaming?stream=user`
pub async fn stream(
    State(state): State<AppState>,
    Query(query): Query<StreamQuery>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let kind = Kind::parse(query.stream.as_deref())?;
    // Authentication happens here, before the response exists: a caller without a token
    // gets a JSON `401`, never a `200` whose body then closes.
    let token = query
        .access_token
        .as_deref()
        .or_else(|| header_token(&headers))
        .ok_or_else(|| ApiError::unauthorized("The access token is invalid"))?;
    let auth = Auth(authenticate(&state, token).await?);
    // A stream is read-only, so any read grant is enough; requiring the bare `read` scope
    // would reject the granular tokens this instance issues (`read:notifications`,
    // `read:statuses`).
    if !["read", "read:notifications", "read:statuses"]
        .iter()
        .any(|scope| auth.0.allows(scope))
    {
        return Err(ApiError::forbidden("This action requires the read scope"));
    }

    let subscription = live::subscribe_account(&auth.0.account.id);
    let live = Live {
        state,
        auth,
        kind,
        subscription,
        shutdown: live::shutdown(),
        ticker: time::interval_at(Instant::now() + keepalive_period(), keepalive_period()),
        lagged_logged: false,
    };

    // The comment line opens the connection visibly: `curl -N` prints it at once, which is
    // the quickest way to tell a working stream from a buffering proxy.
    let opening = stream::iter(std::iter::once(Ok::<Bytes, Infallible>(
        Bytes::from_static(b": nodus live stream\n\n"),
    )));
    let body = Body::from_stream(opening.chain(stream::unfold(live, next)));

    let mut response = Response::new(body);
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
    // Caddy and nginx honour this: without it a proxy may hold the response until its
    // buffer fills, and the deploy check is exactly "does a byte arrive before the end".
    headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
    Ok(response)
}

/// The bearer value from `Authorization`, if the client chose that route.
fn header_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?;
    (!token.is_empty()).then_some(token)
}

/// Everything one open stream owns between events.
struct Live {
    state: AppState,
    auth: Auth,
    kind: Kind,
    subscription: Subscription,
    shutdown: Option<watch::Receiver<bool>>,
    ticker: time::Interval,
    lagged_logged: bool,
}

impl Live {
    fn shutting_down(&self) -> bool {
        self.shutdown
            .as_ref()
            .is_some_and(|shutdown| *shutdown.borrow())
    }
}

/// One SSE frame per tick of the body stream.
async fn next(mut live: Live) -> Option<(Result<Bytes, Infallible>, Live)> {
    loop {
        if live.shutting_down() {
            // Dropping `Live` drops the subscription, which is how the hub learns the
            // connection is gone.
            return None;
        }
        tokio::select! {
            biased;
            () = wait_for_shutdown(&mut live.shutdown) => return None,
            event = live.subscription.recv() => match event {
                Ok(event) => {
                    if live.kind.wants(&event) {
                        // The row vanished (deleted between publish and read) or the
                        // read failed: skip the event, never kill the stream for it.
                        if let Some(frame) = render(&live.state, &live.auth, &event).await {
                            return Some((Ok(frame), live));
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(dropped)) => {
                    if !live.lagged_logged {
                        live.lagged_logged = true;
                        warn!(
                            dropped,
                            account = %live.auth.0.account.id,
                            "live stream fell behind; oldest events dropped"
                        );
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            },
            _ = live.ticker.tick() => {
                return Some((
                    Ok(Bytes::from_static(b":keepalive\n\n")),
                    live,
                ));
            }
        }
    }
}

/// Resolves once the process is shutting down; pending forever when no signal is installed.
async fn wait_for_shutdown(shutdown: &mut Option<watch::Receiver<bool>>) {
    match shutdown {
        Some(rx) => {
            // `changed` resolves on the next value or when the sender is dropped; either
            // is a reason to stop.
            let _ = rx.changed().await;
        }
        None => std::future::pending().await,
    }
}

/// One Mastodon event frame, or `None` when the referenced row is gone.
async fn render(state: &AppState, auth: &Auth, event: &LiveEvent) -> Option<Bytes> {
    match event {
        LiveEvent::Notification { notification_id } => {
            let row = nodus_server_store::social::notification_by_id(
                state.store().pool(),
                &auth.0.account.id,
                notification_id,
            )
            .await
            .ok()
            .flatten()?;
            let dto = crate::notifications::dto(state, &row, Some(auth))
                .await
                .ok()?;
            Some(frame("notification", &serde_json::to_string(&dto).ok()?))
        }
        LiveEvent::Update { status_id } => {
            let status = nodus_server_store::statuses::by_id(state.store().pool(), status_id)
                .await
                .ok()
                .flatten()?;
            let dto = statuses::dto(state, &status, Some(auth)).await.ok()?;
            Some(frame("update", &serde_json::to_string(&dto).ok()?))
        }
        LiveEvent::Delete { status_id } => {
            Some(frame("delete", &serde_json::to_string(status_id).ok()?))
        }
        LiveEvent::Conversation { status_id } => conversation(state, auth, status_id).await,
        LiveEvent::FiltersChanged => Some(frame("filters_changed", "{}")),
    }
}

/// A direct message arrived: send the conversation it belongs to, as Mastodon's
/// `conversation` event, so a client can insert it without refetching the list.
async fn conversation(state: &AppState, auth: &Auth, status_id: &str) -> Option<Bytes> {
    let pool = state.store().pool();
    let root = nodus_server_store::conversations::root_of(pool, status_id)
        .await
        .ok()
        .flatten()?;
    let status = nodus_server_store::statuses::by_id(pool, status_id)
        .await
        .ok()
        .flatten()?;
    let roots = std::slice::from_ref(&root);
    let mut accounts = Vec::new();
    for (_, account_id) in
        nodus_server_store::conversations::participants(pool, &auth.0.account.id, roots)
            .await
            .ok()?
    {
        if let Some(account) = nodus_server_store::accounts::by_id(pool, &account_id)
            .await
            .ok()
            .flatten()
        {
            accounts.push(AccountDto::from_row(&account, state.instance()));
        }
    }
    let muted = nodus_server_store::conversations::muted_roots(pool, &auth.0.account.id, roots)
        .await
        .is_ok_and(|muted| muted.contains(&root));
    let dto = ConversationDto {
        id: root,
        unread: status.account_id != auth.0.account.id,
        muted,
        accounts,
        last_status: statuses::dto(state, &status, Some(auth)).await.ok(),
    };
    Some(frame("conversation", &serde_json::to_string(&dto).ok()?))
}

/// Mastodon's exact SSE shape: one `event:` line, one `data:` line, a blank line.
fn frame(event: &str, data: &str) -> Bytes {
    Bytes::from(format!("event: {event}\ndata: {data}\n\n"))
}

/// The router fragment, mounted by `crate::router`.
pub fn router() -> axum::Router<AppState> {
    axum::Router::new().route("/api/v1/streaming", axum::routing::get(stream))
}
