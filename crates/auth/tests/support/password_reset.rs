//! Fixtures for the password-reset tests: an app with mail configured, a reader who
//! already has a password, and the link the outbox was asked to deliver.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use nodus_auth::store::PgAuthStore;
use nodus_auth::{hash_password, AppState, EmailConfirmation};
use sqlx::PgPool;
use tower::ServiceExt;

use crate::support::config;

pub fn app(pool: &PgPool) -> axum::Router {
    let state = AppState::new(PgAuthStore::new(pool.clone()), config()).with_email_confirmation(
        EmailConfirmation {
            base_url: "https://social.test".to_owned(),
        },
    );
    nodus_auth::router(state)
}

pub async fn body(response: axum::response::Response) -> (StatusCode, Vec<u8>) {
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    (status, bytes.to_vec())
}

/// Reads the CSRF cookie and hidden field a page hands a browser.
pub async fn csrf(app: &axum::Router, uri: &str) -> (String, String) {
    let request = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("build request");
    let response = app.clone().oneshot(request).await.expect("send request");
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| value.strip_prefix("nodus_csrf="))
        .map(|value| value.split(';').next().unwrap_or_default().to_owned())
        .expect("csrf cookie");
    let (_, page) = body(response).await;
    let page = String::from_utf8_lossy(&page);
    let token = page
        .split("name=\"csrf_token\"")
        .nth(1)
        .and_then(|rest| rest.split("value=\"").nth(1))
        .and_then(|rest| rest.split('"').next())
        .expect("csrf field")
        .to_owned();
    (cookie, token)
}

pub async fn post_form_full(
    app: &axum::Router,
    uri: &str,
    cookie: &str,
    form: &[(&str, &str)],
) -> (StatusCode, Vec<u8>, Option<String>) {
    let encoded = form
        .iter()
        .fold(
            url::form_urlencoded::Serializer::new(String::new()),
            |serializer, (name, value)| {
                let mut serializer = serializer;
                serializer.append_pair(name, value);
                serializer
            },
        )
        .finish();
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::COOKIE, format!("nodus_csrf={cookie}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(encoded))
        .expect("build request");
    let response = app.clone().oneshot(request).await.expect("send request");
    let session = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| value.strip_prefix("nodus_auth="))
        .map(|value| value.split(';').next().unwrap_or_default().to_owned());
    let (status, page) = body(response).await;
    (status, page, session)
}

pub async fn post_form(
    app: &axum::Router,
    uri: &str,
    cookie: &str,
    form: &[(&str, &str)],
) -> (StatusCode, Vec<u8>) {
    let (status, page, _) = post_form_full(app, uri, cookie, form).await;
    (status, page)
}

pub async fn create_account(pool: &PgPool, username: &str, email: &str, password: &str) -> String {
    let id = ulid::Ulid::new().to_string();
    let hash = hash_password(password).expect("hash password");
    sqlx::query(
        "INSERT INTO account (id, username, display_name, local, approved) \
         VALUES ($1, $2, $2, true, true)",
    )
    .bind(&id)
    .bind(username)
    .execute(pool)
    .await
    .expect("insert account");
    sqlx::query(
        "INSERT INTO account_credential (account_id, email, password_hash, confirmed_at) \
         VALUES ($1, $2, $3, now())",
    )
    .bind(&id)
    .bind(email)
    .bind(hash)
    .execute(pool)
    .await
    .expect("insert credential");
    id
}

pub async fn create_session(pool: &PgPool, account_id: &str, token: &str) {
    sqlx::query(
        "INSERT INTO auth_session (id, account_id, token_hash, expires_at, user_agent, last_used_at) \
         VALUES ($1, $2, $3, now() + interval '1 day', 'test', now())",
    )
    .bind(ulid::Ulid::new().to_string())
    .bind(account_id)
    .bind(nodus_auth::domain::token_hash(token))
    .execute(pool)
    .await
    .expect("insert session");
}

pub async fn request_reset(app: &axum::Router, email: &str) -> (StatusCode, Vec<u8>) {
    let (cookie, csrf) = csrf(app, "/auth/password/reset").await;
    post_form(
        app,
        "/auth/password/reset",
        &cookie,
        &[("csrf_token", &csrf), ("email", email)],
    )
    .await
}

pub async fn queued_token(pool: &PgPool) -> String {
    let text: String =
        sqlx::query_scalar("SELECT body_text FROM email_outbox ORDER BY created_at DESC LIMIT 1")
            .fetch_one(pool)
            .await
            .expect("read reset mail");
    text.split("/auth/password/reset/")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .expect("reset link")
        .to_owned()
}
