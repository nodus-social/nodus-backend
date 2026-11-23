//! Integration tests for the second factor on the local password login.
//!
//! These drive the real router and a real Postgres, because the properties that matter —
//! no session before the challenge is answered, a code working once, a recovery code
//! working once — are interactions between cookies, rows and time, not pure functions.
//! Skipped when `DATABASE_URL` is unset, like the other auth tests.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::Router;
use chrono::Utc;
use http_body_util::BodyExt;
use nodus_auth::store::{AuthStore, PgAuthStore};
use nodus_auth::totp;
use nodus_auth::{AppState, Config};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tower::ServiceExt;

const PASSWORD: &str = "correct-horse-battery-staple";
const EMAIL: &str = "otp@social.test";

fn config() -> Config {
    Config {
        domain: "social.test".to_owned(),
        issuer: "https://social.test".to_owned(),
        secure_cookies: false,
        registrations_open: true,
    }
}

async fn isolated_pool() -> Option<(PgPool, String)> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect to postgres");
    let schema = format!("pgtest_otp_{}", ulid::Ulid::new()).to_lowercase();
    sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
        .execute(&admin)
        .await
        .expect("create isolated test schema");
    let separator = if url.contains('?') { '&' } else { '?' };
    let schema_url = format!("{url}{separator}options=-csearch_path%3D{schema}%2Cpublic");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&schema_url)
        .await
        .expect("connect isolated pool");
    sqlx::migrate!("../store/migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    Some((pool, schema))
}

async fn run_db_test<F, Fut>(body: F)
where
    F: FnOnce(PgPool) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some((pool, schema)) = isolated_pool().await else {
        return;
    };
    let cleanup = pool.clone();
    let handle = tokio::spawn(async move { body(pool).await });
    let outcome = handle.await;
    let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
        .execute(&cleanup)
        .await;
    if let Err(error) = outcome {
        std::panic::resume_unwind(error.into_panic());
    }
}

async fn create_account(pool: &PgPool) -> String {
    let id = ulid::Ulid::new().to_string().to_lowercase();
    sqlx::query(
        "INSERT INTO account (id, username, display_name, local, approved) \
         VALUES ($1, 'otpuser', 'otpuser', true, true)",
    )
    .bind(&id)
    .execute(pool)
    .await
    .expect("insert account");
    sqlx::query(
        "INSERT INTO account_credential (account_id, email, password_hash, confirmed_at) \
         VALUES ($1, $2, $3, now())",
    )
    .bind(&id)
    .bind(EMAIL)
    .bind(nodus_auth::hash_password(PASSWORD).expect("hash"))
    .execute(pool)
    .await
    .expect("insert credential");
    id
}

async fn activate(pool: &PgPool, account_id: &str, secret: &str, recovery: &[&str]) {
    let store = PgAuthStore::new(pool.clone());
    let step = i64::try_from(totp::step_at(Utc::now().timestamp())).expect("step");
    let hashes: Vec<String> = recovery
        .iter()
        .map(|code| totp::recovery_code_hash(code))
        .collect();
    store
        .start_totp_enrolment(account_id, secret)
        .await
        .expect("enrol");
    store
        .confirm_totp(account_id, step, &hashes)
        .await
        .expect("confirm");
}

fn csrf() -> (String, String) {
    let nonce = "test-nonce".to_owned();
    let token = nodus_auth::domain::csrf_token(&nonce, None);
    (format!("nodus_csrf={nonce}"), token)
}

fn form(pairs: &[(&str, &str)]) -> Body {
    let encoded: String = pairs
        .iter()
        .map(|(key, value)| {
            format!(
                "{key}={}",
                url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    Body::from(encoded)
}

fn post(uri: &str, cookies: &str, pairs: &[(&str, &str)]) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookies)
        .body(form(pairs))
        .expect("request")
}

fn get(uri: &str, cookies: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::COOKIE, cookies)
        .body(Body::empty())
        .expect("request")
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (
        status,
        headers,
        String::from_utf8_lossy(&body).into_owned(),
    )
}

/// The named cookie's value, if the response set it.
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| {
            let (key, rest) = value.split_once('=')?;
            (key.trim() == name).then(|| rest.split(';').next().unwrap_or_default().to_owned())
        })
}

fn current_code(secret: &str, offset: i64) -> String {
    let step = i64::try_from(totp::step_at(Utc::now().timestamp())).expect("step") + offset;
    totp::code_at(secret, u64::try_from(step).expect("step"))
        .expect("code")
}

/// Signs in with the password and returns the challenge cookie.
async fn login(app: &Router) -> (StatusCode, Option<String>) {
    let (csrf_cookie, csrf_token) = csrf();
    let response = send(
        app,
        post(
            "/auth/login",
            &csrf_cookie,
            &[
                ("email", EMAIL),
                ("password", PASSWORD),
                ("csrf_token", &csrf_token),
            ],
        ),
    )
    .await;
    (response.0, cookie(&response.1, "nodus_2fa"))
}

async fn answer_challenge(app: &Router, challenge: &str, code: &str) -> (StatusCode, HeaderMap) {
    let (csrf_cookie, csrf_token) = csrf();
    let cookies = format!("nodus_2fa={challenge}; {csrf_cookie}");
    let response = send(
        app,
        post(
            "/auth/2fa",
            &cookies,
            &[("code", code), ("csrf_token", &csrf_token)],
        ),
    )
    .await;
    (response.0, response.1)
}

#[tokio::test]
async fn a_confirmed_factor_stops_the_password_from_issuing_a_session() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(
            PgAuthStore::new(pool.clone()),
            config(),
        ));
        let account_id = create_account(&pool).await;
        activate(&pool, &account_id, &totp::generate_secret(), &[]).await;

        let (status, challenge) = login(&app).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert!(challenge.is_some(), "a challenge cookie must be set");
        assert!(
            challenge.as_deref().is_some_and(|value| !value.is_empty()),
            "the challenge cookie must not be empty"
        );
    })
    .await;
}

#[tokio::test]
async fn a_wrong_code_is_refused_and_issues_no_session() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(
            PgAuthStore::new(pool.clone()),
            config(),
        ));
        let account_id = create_account(&pool).await;
        let secret = totp::generate_secret();
        activate(&pool, &account_id, &secret, &[]).await;
        let (_, challenge) = login(&app).await;
        let challenge = challenge.expect("challenge");

        let (status, headers) = answer_challenge(&app, &challenge, "000000").await;
        assert_eq!(status, StatusCode::OK, "the form is re-rendered");
        assert!(cookie(&headers, "nodus_auth").is_none());
    })
    .await;
}

#[tokio::test]
async fn a_code_already_spent_in_its_window_is_replayed_nowhere() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(
            PgAuthStore::new(pool.clone()),
            config(),
        ));
        let account_id = create_account(&pool).await;
        let secret = totp::generate_secret();
        activate(&pool, &account_id, &secret, &[]).await;
        let code = current_code(&secret, 1);

        let (_, first) = login(&app).await;
        let (status, headers) = answer_challenge(&app, &first.expect("challenge"), &code).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert!(cookie(&headers, "nodus_auth").is_some(), "first use succeeds");

        // A fresh challenge, the same window: the step is already spent.
        let (_, second) = login(&app).await;
        let (status, headers) = answer_challenge(&app, &second.expect("challenge"), &code).await;
        assert_eq!(status, StatusCode::OK);
        assert!(cookie(&headers, "nodus_auth").is_none(), "replay is refused");
    })
    .await;
}

#[tokio::test]
async fn a_recovery_code_works_exactly_once() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(
            PgAuthStore::new(pool.clone()),
            config(),
        ));
        let account_id = create_account(&pool).await;
        let recovery = "abcd-efgh-ijkl-mnop";
        activate(
            &pool,
            &account_id,
            &totp::generate_secret(),
            &[recovery],
        )
        .await;

        let (_, first) = login(&app).await;
        let (status, headers) = answer_challenge(&app, &first.expect("challenge"), recovery).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "an unused recovery code works");
        assert!(cookie(&headers, "nodus_auth").is_some());

        let (_, second) = login(&app).await;
        let (status, headers) = answer_challenge(&app, &second.expect("challenge"), recovery).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            cookie(&headers, "nodus_auth").is_none(),
            "a spent recovery code is dead"
        );
    })
    .await;
}

#[tokio::test]
async fn regenerating_recovery_codes_invalidates_the_old_set() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(
            PgAuthStore::new(pool.clone()),
            config(),
        ));
        let account_id = create_account(&pool).await;
        let old = "abcd-efgh-ijkl-mnop";
        activate(&pool, &account_id, &totp::generate_secret(), &[old]).await;

        // Sign in with the old code to obtain a session that may regenerate.
        let (_, challenge) = login(&app).await;
        let (_, headers) = answer_challenge(&app, &challenge.expect("challenge"), old).await;
        let session = cookie(&headers, "nodus_auth").expect("session cookie");

        let (csrf_cookie, csrf_token) = csrf();
        let cookies = format!("nodus_auth={session}; {csrf_cookie}");
        let response = send(
            &app,
            post(
                "/auth/2fa/recovery",
                &cookies,
                &[("csrf_token", &csrf_token), ("code", "")],
            ),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
        assert!(
            response.2.matches("<code>").count() >= totp::RECOVERY_CODES,
            "the new set is shown once"
        );

        let (_, challenge) = login(&app).await;
        let (status, headers) = answer_challenge(&app, &challenge.expect("challenge"), old).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            cookie(&headers, "nodus_auth").is_none(),
            "the replaced code must not work"
        );
    })
    .await;
}

#[tokio::test]
async fn enrolment_needs_a_code_before_it_gates_anything() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(
            PgAuthStore::new(pool.clone()),
            config(),
        ));
        create_account(&pool).await;

        // Without a factor the password alone signs in.
        let (_, challenge) = login(&app).await;
        assert!(challenge.is_none(), "nothing to challenge yet");

        let (csrf_cookie, _csrf_token) = csrf();
        let (status, headers, body) = send(
            &app,
            get("/auth/2fa/enroll", &csrf_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "enrolment needs a session");
        assert!(headers.get(header::LOCATION).is_some());
        assert!(!body.contains("otpauth://"));

        let (csrf_cookie, csrf_token) = csrf();
        let response = send(
            &app,
            post(
                "/auth/login",
                &csrf_cookie,
                &[
                    ("email", EMAIL),
                    ("password", PASSWORD),
                    ("csrf_token", &csrf_token),
                ],
            ),
        )
        .await;
        let session = cookie(&response.1, "nodus_auth").expect("session cookie");

        let cookies = format!("nodus_auth={session}; {csrf_cookie}");
        let (status, _, body) = send(&app, get("/auth/2fa/enroll", &cookies)).await;
        assert_eq!(status, StatusCode::OK);
        let uri = body
            .split("otpauth://totp/")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("provisioning URI");
        let secret = uri
            .split("secret=")
            .nth(1)
            .and_then(|rest| rest.split('&').next())
            .expect("secret");

        // A wrong code must leave the factor unconfirmed and the login password-only.
        let response = send(
            &app,
            post(
                "/auth/2fa/enroll",
                &cookies,
                &[("code", "000000"), ("csrf_token", &csrf_token)],
            ),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
        assert!(response.2.contains("did not match"));
        let (_, challenge) = login(&app).await;
        assert!(challenge.is_none(), "an unconfirmed factor gates nothing");

        // The right code confirms it and hands over the recovery set exactly once.
        let code = current_code(secret, 1);
        let response = send(
            &app,
            post(
                "/auth/2fa/enroll",
                &cookies,
                &[("code", &code), ("csrf_token", &csrf_token)],
            ),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
        assert!(response.2.contains("recovery codes"));
        assert!(
            response.2.matches("<code>").count() >= totp::RECOVERY_CODES,
            "ten codes are shown at enrolment"
        );
        let (_, challenge) = login(&app).await;
        assert!(challenge.is_some(), "now the password stops at the challenge");
    })
    .await;
}
