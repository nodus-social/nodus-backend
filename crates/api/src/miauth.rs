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
use chrono::Utc;
use leptos::prelude::*;
use serde::Deserialize;
use serde_json::json;

use nodus_auth::domain::{is_admin_scope, is_safe_http_url, opaque_token, token_hash};
use nodus_auth::store::{AuthStore, PgAuthStore};
use nodus_auth::{ensure_csrf, has_valid_csrf, SESSION_COOKIE};
use nodus_server_store::miauth::{ApproveStatus, SessionCheck};
use nodus_server_store::{accounts, miauth};

use crate::error::ApiError;
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
    let Some(account) = session_account(&state, &headers).await else {
        return (StatusCode::UNAUTHORIZED, Html("<p>Sign in first.</p>")).into_response();
    };
    let scopes: Vec<String> = query
        .permission
        .as_deref()
        .unwrap_or("read,write,follow")
        .split(',')
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect();
    if scopes.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Html("<p>At least one permission is required.</p>"),
        )
            .into_response();
    }
    if !account.admin && scopes.iter().any(|scope| is_admin_scope(scope)) {
        return (
            StatusCode::FORBIDDEN,
            Html("<p>Administrator access is required for admin permissions.</p>"),
        )
            .into_response();
    }
    if let Some(callback) = query
        .callback
        .as_deref()
        .map(str::trim)
        .filter(|cb| !cb.is_empty())
    {
        if !is_safe_http_url(callback) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Html("<p>Invalid callback URL.</p>"),
            )
                .into_response();
        }
    }
    match miauth::create_session(
        state.store().pool(),
        &session,
        &query.name,
        query.callback.as_deref(),
        &scopes,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::CONFLICT,
                Html("<p>MiAuth session already exists.</p>"),
            )
                .into_response();
        }
        Err(error) => return ApiError::from(error).into_response(),
    }
    let jar = CookieJar::from_headers(&headers);
    let session_secret = jar
        .get(SESSION_COOKIE)
        .map(|cookie| cookie.value().to_owned());
    let (jar, csrf_token) = ensure_csrf(
        jar,
        session_secret.as_deref(),
        state.instance().base_url.starts_with("https://"),
    );
    let permission = scopes.join(",");
    let action = format!("/miauth/{session}");
    let name = query.name;
    let title = format!("Authorize {name}");
    let scopes = format!("Scopes: {permission}");
    let body = Owner::new().with(|| {
        view! {
            <html>
                <head>
                    <meta charset="utf-8" />
                    <title>{title.clone()}</title>
                </head>
                <body>
                    <form method="post" action=action>
                        <h1>{title}</h1>
                        <p>{scopes}</p>
                        <input type="hidden" name="name" value=name />
                        <input type="hidden" name="csrf_token" value=csrf_token />
                        <button type="submit">"Approve"</button>
                    </form>
                </body>
            </html>
        }
        .to_html()
    });
    (jar, Html(format!("<!DOCTYPE html>{body}"))).into_response()
}

#[derive(Debug, Deserialize)]
struct ApproveForm {
    name: String,
    #[serde(default)]
    csrf_token: String,
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
    let jar = CookieJar::from_headers(&headers);
    let session_secret = jar
        .get(SESSION_COOKIE)
        .map(axum_extra::extract::cookie::Cookie::value);
    if !has_valid_csrf(&jar, Some(form.csrf_token.as_str()), session_secret) {
        return (StatusCode::FORBIDDEN, Html("<p>Invalid CSRF token.</p>")).into_response();
    }
    let token = opaque_token();
    let hash = token_hash(&token);
    let status = match miauth::approve_session(
        state.store().pool(),
        &session,
        &account.account_id,
        account.admin,
        &token,
        &hash,
    )
    .await
    {
        Ok(status) => status,
        Err(error) => return ApiError::from(error).into_response(),
    };
    match status {
        ApproveStatus::Approved => {}
        ApproveStatus::NotFound => {
            return (StatusCode::NOT_FOUND, Html("<p>Unknown session.</p>")).into_response();
        }
        ApproveStatus::AdminRequired => {
            return (
                StatusCode::FORBIDDEN,
                Html("<p>Administrator access is required for admin permissions.</p>"),
            )
                .into_response();
        }
    }
    let html = format!(
        "<p>Approved {}. You can return to the app.</p>",
        escape(&form.name)
    );
    Html(html).into_response()
}

async fn check(State(state): State<AppState>, Path(session): Path<String>) -> Response {
    let check_result = match miauth::consume_session(state.store().pool(), &session).await {
        Ok(result) => result,
        Err(error) => return ApiError::from(error).into_response(),
    };
    let session_row = match check_result {
        SessionCheck::Ready(row) => row,
        SessionCheck::Pending => return Json(json!({"ok": false})).into_response(),
        SessionCheck::Unknown => {
            return Json(json!({"ok": false, "error": "unknown session"})).into_response();
        }
    };
    if session_row.token.is_none() || session_row.expires_at < Utc::now() {
        return Json(json!({"ok": false})).into_response();
    }
    let user = match session_row.account_id.as_deref() {
        Some(id) => accounts::by_id(state.store().pool(), id)
            .await
            .ok()
            .flatten()
            .map(|account| crate::dto::AccountDto::from_row(&account, state.instance())),
        None => None,
    };
    Json(json!({"ok": true, "token": session_row.token, "user": user})).into_response()
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
