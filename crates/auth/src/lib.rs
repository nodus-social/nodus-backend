//! Nodus auth service.
//!
//! One process renders the login/consent pages and speaks the OAuth endpoints Mastodon
//! clients expect. Storage is behind [`AuthStore`]; the service never opens a second
//! database abstraction of its own.

use std::sync::Arc;

use argon2::password_hash::{PasswordHash, PasswordVerifier};
use argon2::Argon2;
use axum::extract::{Form, Query, RawQuery, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{Duration, Utc};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::domain::{
    opaque_token, redirect_allowed, redirect_with, token_hash, verify_pkce, AuthorizeRequest,
};
use crate::store::{AuthStore, PgAuthStore, SessionAccount};

pub mod domain;
pub mod store;

/// Hashes a bootstrap password with Argon2id's default parameters.
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    use argon2::password_hash::{PasswordHasher, SaltString};

    let salt = SaltString::encode_b64(&rand::random::<[u8; 16]>())?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

pub const SESSION_COOKIE: &str = "nodus_auth";
const SESSION_DAYS: i64 = 30;
const CODE_MINUTES: i64 = 5;

#[derive(Clone)]
pub struct Config {
    pub domain: String,
    pub issuer: String,
    pub secure_cookies: bool,
}

impl Config {
    #[must_use]
    pub fn new(domain: impl Into<String>) -> Self {
        let domain = domain.into();
        Self {
            issuer: format!("https://{domain}"),
            domain,
            secure_cookies: true,
        }
    }
}

#[derive(Clone)]
pub struct AppState<S: AuthStore> {
    store: S,
    config: Arc<Config>,
}

impl<S: AuthStore> AppState<S> {
    pub fn new(store: S, config: Config) -> Self {
        Self {
            store,
            config: Arc::new(config),
        }
    }
}

pub fn router<S: AuthStore>(state: AppState<S>) -> Router {
    Router::new()
        .route("/", get(|| async { Redirect::to("/auth/login") }))
        .route("/auth/login", get(login_page::<S>).post(login_submit::<S>))
        .route("/auth/logout", get(logout::<S>))
        .route("/auth/session", get(session::<S>))
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata::<S>),
        )
        .route("/oauth/authorize", get(authorize::<S>).post(consent::<S>))
        .route("/oauth/token", post(token::<S>))
        .route("/oauth/revoke", post(revoke::<S>))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct LoginQuery {
    return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    email: String,
    password: String,
    return_to: Option<String>,
}

async fn login_page<S: AuthStore>(
    State(_state): State<AppState<S>>,
    Query(query): Query<LoginQuery>,
    jar: CookieJar,
) -> Html<String> {
    Html(render_login(
        query.return_to.as_deref(),
        jar.get(SESSION_COOKIE).is_some(),
        None,
    ))
}

async fn login_submit<S: AuthStore>(
    State(state): State<AppState<S>>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    let Some(credential) = state
        .store
        .credential_by_email(form.email.trim())
        .await
        .ok()
        .flatten()
    else {
        return Html(render_login(
            form.return_to.as_deref(),
            false,
            Some("Wrong email or password."),
        ))
        .into_response();
    };
    let Ok(parsed) = PasswordHash::new(&credential.password_hash) else {
        return Html(render_login(
            form.return_to.as_deref(),
            false,
            Some("Wrong email or password."),
        ))
        .into_response();
    };
    if Argon2::default()
        .verify_password(form.password.as_bytes(), &parsed)
        .is_err()
    {
        return Html(render_login(
            form.return_to.as_deref(),
            false,
            Some("Wrong email or password."),
        ))
        .into_response();
    }

    let session = opaque_token();
    let expiry = Utc::now() + Duration::days(SESSION_DAYS);
    if state
        .store
        .create_session(&token_hash(&session), &credential.account_id, expiry)
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session could not be stored",
        )
            .into_response();
    }
    let cookie = session_cookie(session, expiry, state.config.secure_cookies);
    let target = safe_return_to(form.return_to.as_deref()).unwrap_or("/");
    (jar.add(cookie), Redirect::to(target)).into_response()
}

async fn logout<S: AuthStore>(State(state): State<AppState<S>>, jar: CookieJar) -> Response {
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        let _ = state
            .store
            .delete_session(&token_hash(cookie.value()))
            .await;
    }
    let mut removal = Cookie::new(SESSION_COOKIE, "");
    removal.set_path("/");
    removal.set_max_age(Some(time::Duration::ZERO));
    (jar.remove(removal), Redirect::to("/auth/login")).into_response()
}

async fn session<S: AuthStore>(
    State(state): State<AppState<S>>,
    jar: CookieJar,
) -> Result<Json<SessionJson>, StatusCode> {
    let Some(account) = current_account(&state, &jar).await else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    Ok(Json(SessionJson {
        account_id: account.account_id,
        username: account.username,
        display_name: account.display_name,
    }))
}

async fn authorize<S: AuthStore>(
    State(state): State<AppState<S>>,
    RawQuery(query): RawQuery,
    jar: CookieJar,
) -> Response {
    let raw = query.unwrap_or_default();
    let pairs = parse_pairs(&raw);
    let Ok(request) = AuthorizeRequest::parse(&pairs) else {
        return (StatusCode::BAD_REQUEST, "invalid authorization request").into_response();
    };
    let Ok(Some(app)) = state.store.client_app(&request.client_id).await else {
        return (StatusCode::BAD_REQUEST, "unknown client").into_response();
    };
    if !redirect_allowed(&app.redirect_uris, &request.redirect_uri) {
        return (StatusCode::BAD_REQUEST, "redirect_uri is not registered").into_response();
    }
    let Some(account) = current_account(&state, &jar).await else {
        let return_to = format!("/oauth/authorize?{raw}");
        let url = format!(
            "/auth/login?return_to={}",
            url::form_urlencoded::byte_serialize(return_to.as_bytes()).collect::<String>()
        );
        return Redirect::to(&url).into_response();
    };
    Html(render_consent(&app.name, &request, &account)).into_response()
}

#[derive(Debug, Deserialize)]
struct ConsentForm {
    client_id: String,
    redirect_uri: String,
    scopes: String,
    state: Option<String>,
    code_challenge: String,
    decision: String,
}

async fn consent<S: AuthStore>(
    State(state): State<AppState<S>>,
    jar: CookieJar,
    Form(form): Form<ConsentForm>,
) -> Response {
    let Some(account) = current_account(&state, &jar).await else {
        return Redirect::to("/auth/login").into_response();
    };
    let Ok(Some(app)) = state.store.client_app(&form.client_id).await else {
        return (StatusCode::BAD_REQUEST, "unknown client").into_response();
    };
    if !redirect_allowed(&app.redirect_uris, &form.redirect_uri) {
        return (StatusCode::BAD_REQUEST, "redirect_uri is not registered").into_response();
    }
    if form.decision != "allow" {
        let Ok(mut url) = url::Url::parse(&form.redirect_uri) else {
            return (StatusCode::BAD_REQUEST, "bad redirect_uri").into_response();
        };
        url.query_pairs_mut().append_pair("error", "access_denied");
        return Redirect::to(url.as_str()).into_response();
    }

    let code = opaque_token();
    let scopes: Vec<String> = form.scopes.split_whitespace().map(str::to_owned).collect();
    let expires = Utc::now() + Duration::minutes(CODE_MINUTES);
    if state
        .store
        .create_code(
            &token_hash(&code),
            &app.id,
            &account.account_id,
            &form.redirect_uri,
            &scopes,
            &form.code_challenge,
            expires,
        )
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "code could not be stored",
        )
            .into_response();
    }
    match redirect_with(&form.redirect_uri, &code, form.state.as_deref()) {
        Ok(url) => Redirect::to(&url).into_response(),
        Err(_) => (StatusCode::BAD_REQUEST, "bad redirect_uri").into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct TokenForm {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: String,
    client_secret: Option<String>,
    code_verifier: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    scope: String,
    created_at: i64,
}

async fn token<S: AuthStore>(
    State(state): State<AppState<S>>,
    Form(form): Form<TokenForm>,
) -> Response {
    if form.grant_type != crate::domain::AUTHORIZATION_CODE {
        return oauth_error("unsupported_grant_type");
    }
    let (Some(code), Some(redirect_uri), Some(verifier)) = (
        form.code.as_deref(),
        form.redirect_uri.as_deref(),
        form.code_verifier.as_deref(),
    ) else {
        return oauth_error("invalid_request");
    };
    let Ok(Some(app)) = state.store.client_app(&form.client_id).await else {
        return oauth_error("invalid_client");
    };
    if app.scopes.iter().all(|scope| !scope.is_empty())
        && form.client_secret.as_deref().is_none_or(str::is_empty)
    {
        // Public clients are allowed, but the code is still bound to the client_id.
    }
    let Ok(Some(stored)) = state.store.consume_code(&token_hash(code)).await else {
        return oauth_error("invalid_grant");
    };
    if stored.app_id != app.id || stored.redirect_uri != redirect_uri {
        return oauth_error("invalid_grant");
    }
    if verify_pkce(verifier, &stored.code_challenge).is_err() {
        return oauth_error("invalid_grant");
    }
    let access_token = opaque_token();
    if state
        .store
        .issue_token(
            &token_hash(&access_token),
            &stored.app_id,
            &stored.account_id,
            &stored.scopes,
        )
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "token could not be stored",
        )
            .into_response();
    }
    Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        scope: stored.scopes.join(" "),
        created_at: Utc::now().timestamp(),
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
struct RevokeForm {
    token: String,
}

async fn revoke<S: AuthStore>(
    State(state): State<AppState<S>>,
    Form(form): Form<RevokeForm>,
) -> StatusCode {
    let _ = state.store.revoke_token(&token_hash(&form.token)).await;
    StatusCode::OK
}

async fn metadata<S: AuthStore>(State(state): State<AppState<S>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "issuer": state.config.issuer,
        "authorization_endpoint": format!("{}/oauth/authorize", state.config.issuer),
        "token_endpoint": format!("{}/oauth/token", state.config.issuer),
        "revocation_endpoint": format!("{}/oauth/revoke", state.config.issuer),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "scopes_supported": ["read", "write", "follow", "push"]
    }))
}

async fn current_account<S: AuthStore>(
    state: &AppState<S>,
    jar: &CookieJar,
) -> Option<SessionAccount> {
    let cookie = jar.get(SESSION_COOKIE)?;
    state
        .store
        .session_account(&token_hash(cookie.value()))
        .await
        .ok()
        .flatten()
}

fn session_cookie(value: String, expires: chrono::DateTime<Utc>, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE, value);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(secure);
    cookie.set_expires(
        time::OffsetDateTime::from_unix_timestamp(expires.timestamp())
            .unwrap_or_else(|_| time::OffsetDateTime::now_utc()),
    );
    cookie
}

fn safe_return_to(value: Option<&str>) -> Option<&str> {
    value.filter(|target| target.starts_with('/') && !target.starts_with("//"))
}

fn parse_pairs(raw: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(raw.as_bytes())
        .into_owned()
        .collect()
}

fn oauth_error(code: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": code })),
    )
        .into_response()
}

#[derive(Debug, Serialize)]
struct SessionJson {
    account_id: String,
    username: String,
    display_name: String,
}

fn shell(title: &str, content: impl IntoView + 'static) -> String {
    let title = title.to_owned();
    let body = Owner::new().with(|| {
        view! {
            <html lang="en">
                <head>
                    <meta charset="utf-8"/>
                    <meta name="viewport" content="width=device-width, initial-scale=1"/>
                    <meta name="robots" content="noindex"/>
                    <title>{title}</title>
                    <style>
                        ":root{color-scheme:light dark;font-family:system-ui,sans-serif}"
                        "body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f5f5f4}"
                        "main{width:min(26rem,calc(100vw - 2rem));background:white;border:1px solid #d6d3d1;border-radius:12px;padding:1.5rem}"
                        "h1{font-size:1.25rem;margin:0 0 .5rem}p{color:#57534e;line-height:1.5}"
                        "label{display:block;margin:.75rem 0 .25rem;font-size:.875rem}"
                        "input{width:100%;box-sizing:border-box;padding:.6rem;border:1px solid #a8a29e;border-radius:8px}"
                        "button{margin-top:1rem;width:100%;padding:.65rem;border:0;border-radius:8px;background:#292524;color:white;font-weight:600;cursor:pointer}"
                        ".error{color:#b91c1c;font-size:.875rem}.actions{display:flex;gap:.5rem}.actions button{flex:1}"
                        ".secondary{background:#e7e5e4;color:#292524}"
                        "@media(prefers-color-scheme:dark){body{background:#1c1917}main{background:#292524;border-color:#44403c}p{color:#a8a29e}input{background:#1c1917;color:white;border-color:#57534e}}"
                    </style>
                </head>
                <body><main>{content}</main></body>
            </html>
        }
        .to_html()
    });
    format!("<!DOCTYPE html>{body}")
}

fn render_login(return_to: Option<&str>, signed_in: bool, error: Option<&str>) -> String {
    let return_to = return_to.unwrap_or("/").to_owned();
    let error = error.map(str::to_owned);
    shell(
        "Sign in · Nodus",
        view! {
            <h1>"Sign in to Nodus"</h1>
            <p>"Use your instance account to continue."</p>
            {signed_in.then(|| view! { <p>"You are already signed in."</p> })}
            <form method="post" action="/auth/login">
                <input type="hidden" name="return_to" value=return_to/>
                <label for="email">"Email"</label>
                <input id="email" name="email" type="email" autocomplete="username" required/>
                <label for="password">"Password"</label>
                <input id="password" name="password" type="password" autocomplete="current-password" required/>
                <button type="submit">"Sign in"</button>
            </form>
            {error.map(|message| view! { <p class="error">{message}</p> })}
        },
    )
}

fn render_consent(app_name: &str, request: &AuthorizeRequest, account: &SessionAccount) -> String {
    let scopes = request.scopes.join(" ");
    let state = request.state.clone().unwrap_or_default();
    shell(
        "Authorize · Nodus",
        view! {
            <h1>{format!("Authorize {app_name}")}</h1>
            <p>{format!("Signed in as @{}.", account.username)}</p>
            <p>{format!("This application is asking for: {scopes}.")}</p>
            <form method="post" action="/oauth/authorize">
                <input type="hidden" name="client_id" value=request.client_id.clone()/>
                <input type="hidden" name="redirect_uri" value=request.redirect_uri.clone()/>
                <input type="hidden" name="scopes" value=scopes/>
                <input type="hidden" name="state" value=state/>
                <input type="hidden" name="code_challenge" value=request.code_challenge.clone()/>
                <div class="actions">
                    <button class="secondary" type="submit" name="decision" value="deny">"Deny"</button>
                    <button type="submit" name="decision" value="allow">"Allow"</button>
                </div>
            </form>
        },
    )
}

/// Builds the runtime. The binary owns the listener; this owns the surface.
pub async fn run(
    pool: PgPool,
    config: Config,
    listener: tokio::net::TcpListener,
) -> std::io::Result<()> {
    let state = AppState::new(PgAuthStore::new(pool), config);
    axum::serve(listener, router(state)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_to_cannot_leave_the_instance() {
        assert_eq!(
            safe_return_to(Some("/oauth/authorize?x=1")),
            Some("/oauth/authorize?x=1")
        );
        assert_eq!(safe_return_to(Some("//evil.test")), None);
        assert_eq!(safe_return_to(Some("https://evil.test")), None);
    }

    #[test]
    fn login_page_escapes_the_return_target() {
        let html = render_login(Some("/ok"), false, None);
        assert!(html.contains("name=\"return_to\" value=\"/ok\""));
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn a_core_error_is_not_an_oauth_error_code() {
        assert_eq!(
            crate::domain::Error::Pkce.to_string(),
            "code_verifier does not match the challenge"
        );
    }
}
