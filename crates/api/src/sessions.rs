//! The credential list behind the settings page: browsers signed in with the login
//! cookie, and applications holding an OAuth token.
//!
//! "Current" is never a flag the client sends. A browser session is current when the
//! presented login cookie hashes to its stored token; an application is current when the
//! presented bearer token does.

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get};
use axum::{Json, Router};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use nodus_server_store::apps;
use nodus_server_store::sessions;

use crate::auth::{token_digest, Auth};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/auth/sessions",
            get(list_sessions).delete(revoke_sessions),
        )
        .route("/api/v1/auth/sessions/{id}", delete(revoke_session))
        .route("/api/v1/oauth/authorizations", get(list_authorizations))
        .route(
            "/api/v1/oauth/authorizations/{id}",
            delete(revoke_authorization),
        )
}

#[derive(Debug, Serialize)]
struct SessionDto {
    id: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    user_agent: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    current: bool,
}

/// The digest of the login cookie on this request, if it carries one.
fn cookie_digest(headers: &HeaderMap) -> Option<String> {
    CookieJar::from_headers(headers)
        .get(nodus_auth::SESSION_COOKIE)
        .map(|cookie| token_digest(cookie.value()))
}

/// The session the caller is speaking through, or `401` when the request carries no
/// login cookie of this account.
///
/// A settings page always has one: it was reached through the login that minted it. An
/// app token alone cannot name a browser session, so it is told what is missing instead
/// of being shown a list with every row marked "not current".
fn current_session<'a>(
    rows: &'a [sessions::SessionRow],
    digest: Option<&str>,
) -> ApiResult<&'a sessions::SessionRow> {
    digest
        .and_then(|digest| rows.iter().find(|row| row.token_hash == digest))
        .ok_or_else(|| {
            ApiError::unauthorized(
                "This request carries no browser session for this account; open the settings page in the browser you want to manage",
            )
        })
}

async fn list_sessions(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<SessionDto>>> {
    auth.require_scope("read:accounts")?;
    let rows = sessions::list(state.store().pool(), &auth.0.account.id).await?;
    let current = current_session(&rows, cookie_digest(&headers).as_deref())?
        .id
        .clone();
    Ok(Json(
        rows.into_iter()
            .map(|row| SessionDto {
                current: row.id == current,
                id: row.id,
                created_at: row.created_at,
                last_used_at: row.last_used_at,
                user_agent: row.user_agent,
                ip: row.ip,
            })
            .collect(),
    ))
}

async fn revoke_session(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<axum::http::StatusCode> {
    auth.require_scope("write:accounts")?;
    if sessions::revoke(state.store().pool(), &auth.0.account.id, &id).await? {
        Ok(axum::http::StatusCode::NO_CONTENT)
    } else {
        // Another account's id and an id that is already gone answer the same way, which
        // is also what makes a repeated DELETE harmless.
        Err(ApiError::not_found("No such session"))
    }
}

#[derive(Debug, Deserialize)]
struct RevokeSessionsQuery {
    /// `others` (the default) keeps the caller's session; `all` must be said explicitly.
    #[serde(default)]
    scope: Option<String>,
}

async fn revoke_sessions(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Query(query): Query<RevokeSessionsQuery>,
) -> ApiResult<axum::http::StatusCode> {
    auth.require_scope("write:accounts")?;
    match query.scope.as_deref() {
        None | Some("others") => {
            let rows = sessions::list(state.store().pool(), &auth.0.account.id).await?;
            let current = current_session(&rows, cookie_digest(&headers).as_deref())?;
            sessions::revoke_others(state.store().pool(), &auth.0.account.id, &current.id).await?;
            Ok(axum::http::StatusCode::NO_CONTENT)
        }
        Some("all") => {
            sessions::revoke_all(state.store().pool(), &auth.0.account.id).await?;
            Ok(axum::http::StatusCode::NO_CONTENT)
        }
        Some(_) => Err(ApiError::unprocessable("scope is either 'others' or 'all'")),
    }
}

#[derive(Debug, Serialize)]
struct AppDto {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    website: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuthorizationDto {
    id: String,
    app: AppDto,
    scopes: Vec<String>,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    current: bool,
}

async fn list_authorizations(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<AuthorizationDto>>> {
    auth.require_scope("read:accounts")?;
    let digest = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(token_digest);
    let rows = apps::list_authorizations(state.store().pool(), &auth.0.account.id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| AuthorizationDto {
                current: digest.as_deref() == Some(row.token_hash.as_str()),
                id: row.id,
                app: AppDto {
                    name: row.app_name,
                    website: row.app_website,
                },
                scopes: row.scopes,
                created_at: row.created_at,
                last_used_at: row.last_used_at,
            })
            .collect(),
    ))
}

async fn revoke_authorization(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<axum::http::StatusCode> {
    auth.require_scope("write:accounts")?;
    if apps::revoke_authorization(state.store().pool(), &auth.0.account.id, &id).await? {
        Ok(axum::http::StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("No such authorization"))
    }
}
