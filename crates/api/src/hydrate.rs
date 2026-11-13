//! On-demand hydration of remote profiles and posts into the local store.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::Json;
use axum::Router;
use serde::Deserialize;
use serde_json::json;

use nodus_server_sdk::activitypub::ActivityPub;
use nodus_server_store::accounts::{self, AccountRow};

use crate::activitypub::{ensure_remote_actor, ingest_note};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
struct AccountQuery {
    acct: String,
    #[serde(default = "default_limit")]
    limit: usize,
}

#[derive(Debug, Deserialize)]
struct StatusQuery {
    url: String,
}

fn default_limit() -> usize {
    20
}

async fn account(
    State(state): State<AppState>,
    Query(query): Query<AccountQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let acct = query.acct.trim().trim_start_matches('@');
    if acct.is_empty() || query.limit == 0 || query.limit > 40 {
        return Err(ApiError::unprocessable(
            "acct must be a handle and limit must be within 1..=40",
        ));
    }
    let (_, domain) = acct
        .split_once('@')
        .unwrap_or((acct, &state.instance().domain));
    let local = domain.eq_ignore_ascii_case(&state.instance().domain);
    let account = if local {
        let username = acct.split('@').next().unwrap_or(acct);
        accounts::local_by_username(state.store().pool(), username)
            .await?
            .ok_or_else(|| ApiError::not_found("account does not exist"))?
    } else {
        let client = ActivityPub::new();
        let url = client
            .webfinger(acct)
            .await
            .map_err(|error| ApiError::unprocessable(error.to_string()))?;
        let actor = ensure_remote_actor(&state, &url).await?;
        hydrate_outbox(&state, &client, &actor, query.limit).await?;
        actor
    };
    Ok(Json(
        json!({ "account": dto(&account, &state), "hydrated": true }),
    ))
}

async fn status(
    State(state): State<AppState>,
    Query(query): Query<StatusQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let client = ActivityPub::new();
    let note = client
        .note(&query.url)
        .await
        .map_err(|error| ApiError::unprocessable(error.to_string()))?;
    let actor_url = note
        .attributed_to
        .as_deref()
        .ok_or_else(|| ApiError::unprocessable("note has no attributedTo"))?;
    let account = ensure_remote_actor(&state, actor_url).await?;
    ingest_note(&state, &account, &note.to_json()).await?;
    let status = nodus_server_store::statuses::by_uri(state.store().pool(), &note.id)
        .await?
        .ok_or_else(|| ApiError::not_found("status was not stored"))?;
    Ok(Json(json!({
        "account": dto(&account, &state),
        "status": {
            "id": status.id,
            "url": status.uri,
            "content_html": status.content_html,
            "published": status.created_at,
        }
    })))
}

async fn hydrate_outbox(
    state: &AppState,
    client: &ActivityPub,
    account: &AccountRow,
    limit: usize,
) -> ApiResult<usize> {
    let uri = account
        .uri
        .as_deref()
        .ok_or_else(|| ApiError::unprocessable("account has no canonical URI"))?;
    let actor = client
        .actor_url(uri)
        .await
        .map_err(|error| ApiError::unprocessable(error.to_string()))?;
    let page = client
        .outbox(&actor)
        .await
        .map_err(|error| ApiError::unprocessable(error.to_string()))?;
    let mut stored = 0;
    for item in page.items.into_iter().take(limit) {
        let note = item.get("object").unwrap_or(&item);
        if note.get("type").and_then(serde_json::Value::as_str) != Some("Note") {
            continue;
        }
        if ingest_note(state, account, note).await.is_ok() {
            stored += 1;
        }
    }
    Ok(stored)
}

fn dto(account: &AccountRow, state: &AppState) -> crate::dto::AccountDto {
    crate::dto::AccountDto::from_row(account, state.instance())
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/hydrate/account", get(account))
        .route("/api/v1/hydrate/status", get(status))
}
