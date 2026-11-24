//! Relays: the instance's own subscriptions to relays that carry the wider fediverse.
//!
//! A relay is not an account, so nothing here takes an account id except the queue's: the
//! `Follow` is delivered by the queue, which signs with a local account's key, and the staff
//! member who subscribed is that account. Once the relay answers `Accept` or `Reject`, the
//! inbox moves the row's state and the console shows "waiting for the relay" no longer.

use axum::extract::{Path, State};
use axum::routing::{delete, get};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use nodus_server_store::relay::{self, NewRelay, RelayRow};

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::outbox;
use crate::state::AppState;

use super::Body;

/// The relay as the console reads it.
#[derive(Debug, Serialize)]
pub struct RelayDto {
    pub id: String,
    pub inbox_url: String,
    pub state: String,
    pub follow_activity_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<RelayRow> for RelayDto {
    fn from(row: RelayRow) -> Self {
        Self {
            id: row.id,
            inbox_url: row.actor_uri,
            state: row.state,
            follow_activity_id: row.follow_activity_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// The one field subscribing accepts, in either a form or a JSON body.
#[derive(Debug, Deserialize)]
pub struct RelayForm {
    inbox_url: String,
}

async fn relays(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<RelayDto>>> {
    auth.require_admin("admin:read")?;
    let rows = relay::list(state.store().pool()).await?;
    Ok(Json(rows.into_iter().map(RelayDto::from).collect()))
}

async fn subscribe(
    State(state): State<AppState>,
    auth: Auth,
    Body(form): Body<RelayForm>,
) -> ApiResult<Json<RelayDto>> {
    auth.require_admin("admin:write")?;
    let inbox = form.inbox_url.trim();
    let parsed = url::Url::parse(inbox).map_err(|_| {
        ApiError::unprocessable(
            "a relay inbox is a full https URL, like https://relay.example/inbox",
        )
    })?;
    if parsed.scheme() != "https" || parsed.host_str().is_none() {
        return Err(ApiError::unprocessable(
            "a relay inbox is an https URL with a host",
        ));
    }
    let account = &auth.0.account;
    let actor = outbox::actor_of(&state, &account.username, account.uri.as_deref());
    let follow = outbox::relay_follow(&actor, inbox);
    let Some(follow_id) = follow.get("id").and_then(serde_json::Value::as_str) else {
        return Err(ApiError::new(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "the relay follow could not be identified",
        ));
    };
    let Some(row) = relay::create(
        state.store().pool(),
        &NewRelay {
            actor_uri: inbox,
            follow_activity_id: follow_id,
        },
    )
    .await?
    else {
        return Err(ApiError::unprocessable(
            "this relay is already subscribed; unsubscribe it first",
        ));
    };
    if let Err(error) = outbox::queue_relay(&state, &account.id, &follow, inbox).await {
        // The row exists only to explain a queued Follow; a Follow that never reached the
        // queue would leave a subscription that can never be answered or withdrawn.
        let _ = relay::delete(state.store().pool(), &row.id).await;
        return Err(error);
    }
    super::audit_write_detail(
        &state,
        &auth,
        "subscribe_relay",
        "relay",
        &row.id,
        serde_json::json!({ "inbox_url": row.actor_uri }),
    )
    .await?;
    Ok(Json(RelayDto::from(row)))
}

async fn unsubscribe(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<RelayDto>> {
    auth.require_admin("admin:write")?;
    let Some(row) = relay::by_id(state.store().pool(), &id).await? else {
        return Err(ApiError::not_found("that relay is not subscribed"));
    };
    let account = &auth.0.account;
    if let Some(follow_id) = row.follow_activity_id.as_deref() {
        let actor = outbox::actor_of(&state, &account.username, account.uri.as_deref());
        let undo = outbox::relay_undo(&actor, &row.actor_uri, follow_id);
        outbox::queue_relay(&state, &account.id, &undo, &row.actor_uri).await?;
    }
    relay::delete(state.store().pool(), &id).await?;
    super::audit_write_detail(
        &state,
        &auth,
        "unsubscribe_relay",
        "relay",
        &row.id,
        serde_json::json!({ "inbox_url": row.actor_uri, "state": row.state }),
    )
    .await?;
    Ok(Json(RelayDto::from(row)))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/relays", get(relays).post(subscribe))
        .route("/api/v1/admin/relays/{id}", delete(unsubscribe))
}
