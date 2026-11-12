//! Misskey's MiAuth flow.
//!
//! A MiAuth client opens `/miauth/{session}`, the signed-in user approves, and
//! the client calls `/api/miauth/{session}/check` to receive a bearer token.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;

use nodus_auth::domain::{opaque_token, token_hash};
use nodus_auth::store::{AuthStore, PgAuthStore};
use nodus_server_core::id::Id;
use nodus_server_store::accounts;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/miauth/{session}", get(start).post(approve))
        .route("/api/miauth/{session}/check", post(check))
}

#[derive(Debug, Deserialize)]
struct StartQuery {
    name: String,
    #[serde(default)]
    callback: Option<String>,
    #[serde(default)]
    permission: Option<String>,
}

async fn start(
    State(state): State<AppState>,
    Path(session): Path<String>,
    Query(query): Query<StartQuery>,
    headers: HeaderMap,
) -> Response {
    let scopes: Vec<String> = query
        .permission
        .as_deref()
        .unwrap_or("read write follow")
        .split(',')
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect();
    let _ = sqlx::query(
        "INSERT INTO miauth_session (id, app_name, callback, scopes) VALUES ($1,$2,$3,$4) \
         ON CONFLICT (id) DO UPDATE SET app_name=EXCLUDED.app_name, callback=EXCLUDED.callback, scopes=EXCLUDED.scopes",
    )
    .bind(&session)
    .bind(&query.name)
    .bind(&query.callback)
    .bind(&scopes)
    .execute(state.store().pool())
    .await;
    if session_account(&state, &headers).await.is_none() {
        return (StatusCode::UNAUTHORIZED, Html("<p>Sign in first.</p>")).into_response();
    }
    let permission = scopes.join(",");
    let html = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Authorize {name}</title>\
         <form method=\"post\" action=\"/miauth/{session}\">\
         <h1>Authorize {name}</h1><p>Scopes: {permission}</p>\
         <input type=\"hidden\" name=\"name\" value=\"{name}\">\
         <button type=\"submit\">Approve</button></form>",
        name = escape(&query.name),
        session = escape(&session),
        permission = escape(&permission),
    );
    Html(html).into_response()
}

#[derive(Debug, Deserialize)]
struct ApproveForm {
    name: String,
}

async fn approve(
    State(state): State<AppState>,
    Path(session): Path<String>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<ApproveForm>,
) -> Response {
    let Some(account) = session_account(&state, &headers).await else {
        return (StatusCode::UNAUTHORIZED, Html("<p>Sign in first.</p>")).into_response();
    };
    let row: Option<(Vec<String>,)> =
        sqlx::query_as("SELECT scopes FROM miauth_session WHERE id=$1 AND expires_at > now()")
            .bind(&session)
            .fetch_optional(state.store().pool())
            .await
            .ok()
            .flatten();
    let Some((scopes,)) = row else {
        return (StatusCode::NOT_FOUND, Html("<p>Unknown session.</p>")).into_response();
    };
    let token = opaque_token();
    let hash = token_hash(&token);
    let app_id = "misskey-miauth";
    let _ = sqlx::query(
        "INSERT INTO oauth_app (id,client_id,client_secret_hash,name,redirect_uris,scopes) \
         VALUES ($1,$1,'unused','MiAuth','{}',$2) ON CONFLICT (id) DO NOTHING",
    )
    .bind(app_id)
    .bind(&scopes)
    .execute(state.store().pool())
    .await;
    let _ = sqlx::query(
        "INSERT INTO oauth_token (id,app_id,account_id,token_hash,scopes) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(Id::new().to_string())
    .bind(app_id)
    .bind(&account.account_id)
    .bind(&hash)
    .bind(&scopes)
    .execute(state.store().pool())
    .await;
    let _ = sqlx::query("UPDATE miauth_session SET account_id=$2, token=$3 WHERE id=$1")
        .bind(&session)
        .bind(&account.account_id)
        .bind(&token)
        .execute(state.store().pool())
        .await;
    let html = format!(
        "<p>Approved {}. You can return to the app.</p>",
        escape(&form.name)
    );
    Html(html).into_response()
}

async fn check(State(state): State<AppState>, Path(session): Path<String>) -> Response {
    let row: Option<(Option<String>, Option<String>, DateTime<Utc>)> =
        sqlx::query_as("SELECT token, account_id, expires_at FROM miauth_session WHERE id=$1")
            .bind(&session)
            .fetch_optional(state.store().pool())
            .await
            .ok()
            .flatten();
    let Some((token, account_id, expires_at)) = row else {
        return Json(json!({"ok": false, "error": "unknown session"})).into_response();
    };
    if token.is_none() || expires_at < Utc::now() {
        return Json(json!({"ok": false})).into_response();
    }
    let user = match account_id.as_deref() {
        Some(id) => accounts::by_id(state.store().pool(), id)
            .await
            .ok()
            .flatten()
            .map(|account| crate::dto::AccountDto::from_row(&account, state.instance())),
        None => None,
    };
    Json(json!({"ok": true, "token": token, "user": user})).into_response()
}

async fn session_account(
    state: &AppState,
    headers: &HeaderMap,
) -> Option<nodus_auth::store::SessionAccount> {
    let jar = CookieJar::from_headers(headers);
    let cookie = jar.get(nodus_auth::SESSION_COOKIE)?;
    let store = PgAuthStore::new(state.store().pool().clone());
    store
        .session_account(&token_hash(cookie.value()))
        .await
        .ok()
        .flatten()
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
