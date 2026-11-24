//! Integration tests for the JSON representation of the second factor.
//!
//! The JSON routes are the same state machine as the HTML pages behind a different
//! representation, so the properties worth proving are the ones that span both: a
//! recovery code is spent once no matter which surface spent it, a wrong disable code
//! leaves the factor untouched, and a browser still receives HTML.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::Router;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use nodus_auth::store::{AuthStore, PgAuthStore};
use nodus_auth::totp;
use nodus_auth::{AppState, Config};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tower::ServiceExt;

const PASSWORD: &str = "correct-horse-battery-staple";
const EMAIL: &str = "otp-json@social.test";
const RECOVERY_ONE: &str = "abcd-efgh-ijkl-mnop";
const RECOVERY_TWO: &str = "qrst-uvwx-yz01-2345";

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
    let schema = format!("pgtest_otp_json_{}", ulid::Ulid::new()).to_lowercase();
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
         VALUES ($1, 'otpjsonuser', 'otpjsonuser', true, true)",
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

/// Creates a session out of band, for tests that need a settings surface without
/// replaying the password and challenge flows first.
async fn session_for(pool: &PgPool, account_id: &str) -> String {
    let token = format!("json-test-session-{}", ulid::Ulid::new()).to_lowercase();
    PgAuthStore::new(pool.clone())
        .create_session(
            &nodus_auth::domain::token_hash(&token),
            account_id,
            Utc::now() + Duration::days(1),
            "json-test",
            None,
        )
        .await
        .expect("create session");
    token
}

/// Confirms a factor directly. `floor_offset` is relative to the current step, so `-2`
/// leaves room for a current code to pass the replay floor.
async fn activate(
    pool: &PgPool,
    account_id: &str,
    secret: &str,
    recovery: &[&str],
    floor_offset: i64,
) {
    let store = PgAuthStore::new(pool.clone());
    let step = i64::try_from(totp::step_at(Utc::now().timestamp())).expect("step") + floor_offset;
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

fn post_form(uri: &str, cookies: &str, pairs: &[(&str, &str)]) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookies)
        .body(form(pairs))
        .expect("request")
}

fn post_json(uri: &str, cookies: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .header(header::COOKIE, cookies)
        .body(Body::from(serde_json::to_vec(body).expect("json")))
        .expect("request")
}

fn get_html(uri: &str, cookies: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::ACCEPT, "text/html,application/xhtml+xml")
        .header(header::COOKIE, cookies)
        .body(Body::empty())
        .expect("request")
}

fn get_json(uri: &str, cookies: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::ACCEPT, "application/json")
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
    (status, headers, String::from_utf8_lossy(&body).into_owned())
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
    totp::code_at(secret, u64::try_from(step).expect("step")).expect("code")
}

fn state(body: &str) -> Value {
    serde_json::from_str(body).expect("json body")
}

/// Signs in with the password and returns the challenge cookie.
async fn login(app: &Router) -> (StatusCode, Option<String>) {
    let (csrf_cookie, csrf_token) = csrf();
    let response = send(
        app,
        post_form(
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
        post_form(
            "/auth/2fa",
            &cookies,
            &[("code", code), ("csrf_token", &csrf_token)],
        ),
    )
    .await;
    (response.0, response.1)
}

#[tokio::test]
async fn state_read_reflects_enable_then_disable() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
        let account_id = create_account(&pool).await;
        let session = session_for(&pool, &account_id).await;
        let (csrf_cookie, csrf_token) = csrf();
        let cookies = format!("nodus_auth={session}; {csrf_cookie}");

        let (status, _, body) = send(&app, get_json("/auth/2fa", &cookies)).await;
        assert_eq!(status, StatusCode::OK);
        let before = state(&body);
        assert_eq!(before["enabled"], false);
        assert_eq!(before["recovery_codes_remaining"], 0);
        assert!(
            before["attempts_remaining"].is_null(),
            "no sign-in challenge means no attempt budget to report"
        );

        let response = send(
            &app,
            post_json(
                "/auth/2fa/enroll",
                &cookies,
                &json!({ "csrf_token": csrf_token }),
            ),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
        let enrolment = state(&response.2);
        let secret = enrolment["secret"].as_str().expect("secret").to_owned();
        assert!(
            enrolment["otpauth_url"]
                .as_str()
                .is_some_and(|url| url.starts_with("otpauth://totp/")),
            "the JSON enrolment carries a provisioning URI"
        );
        assert_eq!(
            enrolment["recovery_codes"],
            json!([]),
            "codes appear only when the factor is confirmed"
        );

        let response = send(
            &app,
            post_json(
                "/auth/2fa/enable",
                &cookies,
                &json!({ "csrf_token": csrf_token, "code": current_code(&secret, 1) }),
            ),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
        let confirmed = state(&response.2);
        let codes = confirmed["recovery_codes"]
            .as_array()
            .expect("recovery codes")
            .clone();
        assert_eq!(codes.len(), totp::RECOVERY_CODES);
        assert_eq!(confirmed["secret"], secret.as_str());

        let (status, _, body) = send(&app, get_json("/auth/2fa", &cookies)).await;
        assert_eq!(status, StatusCode::OK);
        let enabled = state(&body);
        assert_eq!(enabled["enabled"], true);
        assert_eq!(enabled["recovery_codes_remaining"], totp::RECOVERY_CODES);
        assert!(enabled["attempts_remaining"].is_null());

        let recovery = codes[0].as_str().expect("code");
        let response = send(
            &app,
            post_json(
                "/auth/2fa/disable",
                &cookies,
                &json!({ "csrf_token": csrf_token, "code": recovery }),
            ),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
        let disabled = state(&response.2);
        assert_eq!(disabled["enabled"], false);
        assert_eq!(disabled["recovery_codes_remaining"], 0);

        let (status, _, body) = send(&app, get_json("/auth/2fa", &cookies)).await;
        assert_eq!(status, StatusCode::OK);
        let after = state(&body);
        assert_eq!(after["enabled"], false);
        assert_eq!(after["recovery_codes_remaining"], 0);
        assert!(after["attempts_remaining"].is_null());
    })
    .await;
}

#[tokio::test]
async fn enrolling_with_a_code_returns_the_recovery_set_once() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
        let account_id = create_account(&pool).await;
        let session = session_for(&pool, &account_id).await;
        let (csrf_cookie, csrf_token) = csrf();
        let cookies = format!("nodus_auth={session}; {csrf_cookie}");

        let response = send(
            &app,
            post_json(
                "/auth/2fa/enroll",
                &cookies,
                &json!({ "csrf_token": csrf_token }),
            ),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
        let secret = state(&response.2)["secret"]
            .as_str()
            .expect("secret")
            .to_owned();

        let response = send(
            &app,
            post_json(
                "/auth/2fa/enroll",
                &cookies,
                &json!({ "csrf_token": csrf_token, "code": current_code(&secret, 1) }),
            ),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
        let confirmed = state(&response.2);
        assert_eq!(confirmed["secret"], secret.as_str());
        assert_eq!(
            confirmed["recovery_codes"].as_array().expect("codes").len(),
            totp::RECOVERY_CODES
        );

        let (_, _, body) = send(&app, get_json("/auth/2fa", &cookies)).await;
        assert_eq!(state(&body)["enabled"], true);
    })
    .await;
}

#[tokio::test]
async fn a_wrong_disable_code_leaves_the_factor_and_its_codes_intact() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
        let account_id = create_account(&pool).await;
        activate(
            &pool,
            &account_id,
            &totp::generate_secret(),
            &[RECOVERY_ONE, RECOVERY_TWO],
            -2,
        )
        .await;
        let session = session_for(&pool, &account_id).await;
        let (csrf_cookie, csrf_token) = csrf();
        let cookies = format!("nodus_auth={session}; {csrf_cookie}");

        let response = send(
            &app,
            post_json(
                "/auth/2fa/disable",
                &cookies,
                &json!({ "csrf_token": csrf_token, "code": "000000" }),
            ),
        )
        .await;
        assert_eq!(response.0, StatusCode::BAD_REQUEST);
        assert_eq!(state(&response.2)["error"], "invalid_code");

        let (_, _, body) = send(&app, get_json("/auth/2fa", &cookies)).await;
        let after = state(&body);
        assert_eq!(after["enabled"], true, "a wrong code must not disable");
        assert_eq!(after["recovery_codes_remaining"], 2);

        let stored: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM account_recovery_code WHERE account_id = $1 AND used_at IS NULL",
        )
        .bind(&account_id)
        .fetch_one(&pool)
        .await
        .expect("count codes");
        assert_eq!(stored, 2, "every recovery code must survive the miss");
    })
    .await;
}

#[tokio::test]
async fn a_recovery_code_spent_by_the_form_is_refused_by_json_disable() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
        let account_id = create_account(&pool).await;
        activate(
            &pool,
            &account_id,
            &totp::generate_secret(),
            &[RECOVERY_ONE, RECOVERY_TWO],
            -2,
        )
        .await;

        let (_, challenge) = login(&app).await;
        let (status, headers) =
            answer_challenge(&app, &challenge.expect("challenge"), RECOVERY_ONE).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let session = cookie(&headers, "nodus_auth").expect("session");
        let (csrf_cookie, csrf_token) = csrf();
        let cookies = format!("nodus_auth={session}; {csrf_cookie}");

        let (_, _, body) = send(&app, get_json("/auth/2fa", &cookies)).await;
        assert_eq!(state(&body)["recovery_codes_remaining"], 1);

        let response = send(
            &app,
            post_json(
                "/auth/2fa/disable",
                &cookies,
                &json!({ "csrf_token": csrf_token, "code": RECOVERY_ONE }),
            ),
        )
        .await;
        assert_eq!(response.0, StatusCode::BAD_REQUEST);
        let (_, _, body) = send(&app, get_json("/auth/2fa", &cookies)).await;
        assert_eq!(state(&body)["enabled"], true);

        // The other code is untouched and still disables.
        let response = send(
            &app,
            post_json(
                "/auth/2fa/disable",
                &cookies,
                &json!({ "csrf_token": csrf_token, "code": RECOVERY_TWO }),
            ),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(state(&response.2)["enabled"], false);
    })
    .await;
}

#[tokio::test]
async fn a_recovery_code_spent_by_json_is_refused_by_the_form() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
        let account_id = create_account(&pool).await;
        activate(
            &pool,
            &account_id,
            &totp::generate_secret(),
            &[RECOVERY_ONE, RECOVERY_TWO],
            -2,
        )
        .await;

        let (_, challenge) = login(&app).await;
        let (csrf_cookie, csrf_token) = csrf();
        let cookies = format!("nodus_2fa={}; {csrf_cookie}", challenge.expect("challenge"));
        let response = send(
            &app,
            post_json(
                "/auth/2fa",
                &cookies,
                &json!({ "csrf_token": csrf_token, "code": RECOVERY_ONE }),
            ),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(state(&response.2)["ok"], true);
        assert!(cookie(&response.1, "nodus_auth").is_some());

        let (_, fresh) = login(&app).await;
        let fresh = fresh.expect("challenge");
        let (status, headers) = answer_challenge(&app, &fresh, RECOVERY_ONE).await;
        assert_eq!(status, StatusCode::OK, "the spent code re-renders the form");
        assert!(cookie(&headers, "nodus_auth").is_none());

        let (status, headers) = answer_challenge(&app, &fresh, RECOVERY_TWO).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert!(cookie(&headers, "nodus_auth").is_some());
    })
    .await;
}

#[tokio::test]
async fn the_state_read_reports_the_live_challenge_budget() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
        let account_id = create_account(&pool).await;
        activate(&pool, &account_id, &totp::generate_secret(), &[], -2).await;
        let (_, challenge) = login(&app).await;
        let challenge = challenge.expect("challenge");

        let (status, _, body) = send(
            &app,
            get_json("/auth/2fa", &format!("nodus_2fa={challenge}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let before = state(&body);
        assert_eq!(before["enabled"], true);
        assert_eq!(before["attempts_remaining"], 5);

        let (csrf_cookie, csrf_token) = csrf();
        let cookies = format!("nodus_2fa={challenge}; {csrf_cookie}");
        let response = send(
            &app,
            post_json(
                "/auth/2fa",
                &cookies,
                &json!({ "csrf_token": csrf_token, "code": "000000" }),
            ),
        )
        .await;
        assert_eq!(response.0, StatusCode::UNAUTHORIZED);
        let refused = state(&response.2);
        assert_eq!(refused["error"], "invalid_code");
        assert_eq!(refused["attempts_remaining"], 4);

        let (_, _, body) = send(
            &app,
            get_json("/auth/2fa", &format!("nodus_2fa={challenge}")),
        )
        .await;
        assert_eq!(state(&body)["attempts_remaining"], 4);
    })
    .await;
}

#[tokio::test]
async fn html_clients_still_receive_html() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
        let account_id = create_account(&pool).await;
        let session = session_for(&pool, &account_id).await;
        let (csrf_cookie, _csrf_token) = csrf();
        let cookies = format!("nodus_auth={session}; {csrf_cookie}");

        let response = send(&app, get_html("/auth/2fa/enroll", &cookies)).await;
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(
            response
                .1
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        assert!(response.2.contains("otpauth://totp/"));

        activate(&pool, &account_id, &totp::generate_secret(), &[], -2).await;
        let (_, challenge) = login(&app).await;
        let response = send(
            &app,
            get_html(
                "/auth/2fa",
                &format!("nodus_2fa={}", challenge.expect("challenge")),
            ),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(
            response
                .1
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        assert!(response.2.contains("Two-factor"));
    })
    .await;
}
