//! Integration tests for the second factor on the local password login.
//!
//! These drive the real router and a real Postgres, because the properties that matter —
//! no session before the challenge is answered, a code working once, a recovery code
//! working once — are interactions between cookies, rows and time, not pure functions.
//! Skipped when `DATABASE_URL` is unset, like the other auth tests.

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::Router;
use chrono::{DateTime, Utc};
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

/// The challenge's spent-attempt count and deadline, or `None` once the row is gone.
async fn challenge_row(pool: &PgPool, account_id: &str) -> Option<(i32, DateTime<Utc>)> {
    sqlx::query_as("SELECT attempts, expires_at FROM auth_2fa_challenge WHERE account_id = $1")
        .bind(account_id)
        .fetch_optional(pool)
        .await
        .expect("challenge row")
}

fn redirect_target(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
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
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
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
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
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
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
        let account_id = create_account(&pool).await;
        let secret = totp::generate_secret();
        activate(&pool, &account_id, &secret, &[]).await;
        let code = current_code(&secret, 1);

        let (_, first) = login(&app).await;
        let (status, headers) = answer_challenge(&app, &first.expect("challenge"), &code).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert!(
            cookie(&headers, "nodus_auth").is_some(),
            "first use succeeds"
        );

        // A fresh challenge, the same window: the step is already spent.
        let (_, second) = login(&app).await;
        let (status, headers) = answer_challenge(&app, &second.expect("challenge"), &code).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            cookie(&headers, "nodus_auth").is_none(),
            "replay is refused"
        );
    })
    .await;
}

#[tokio::test]
async fn a_recovery_code_works_exactly_once() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
        let account_id = create_account(&pool).await;
        let recovery = "abcd-efgh-ijkl-mnop";
        activate(&pool, &account_id, &totp::generate_secret(), &[recovery]).await;

        let (_, first) = login(&app).await;
        let (status, headers) = answer_challenge(&app, &first.expect("challenge"), recovery).await;
        assert_eq!(
            status,
            StatusCode::SEE_OTHER,
            "an unused recovery code works"
        );
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
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
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
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
        create_account(&pool).await;

        // Without a factor the password alone signs in.
        let (_, challenge) = login(&app).await;
        assert!(challenge.is_none(), "nothing to challenge yet");

        let (csrf_cookie, _csrf_token) = csrf();
        let (status, headers, body) = send(&app, get("/auth/2fa/enroll", &csrf_cookie)).await;
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
        assert!(
            challenge.is_some(),
            "now the password stops at the challenge"
        );
    })
    .await;
}

#[tokio::test]
async fn a_fourth_attempt_with_the_right_code_still_signs_in() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
        let account_id = create_account(&pool).await;
        let secret = totp::generate_secret();
        activate(&pool, &account_id, &secret, &[]).await;
        let (_, challenge) = login(&app).await;
        let challenge = challenge.expect("challenge");

        for attempt in 1..=3 {
            let (status, headers) = answer_challenge(&app, &challenge, "000000").await;
            assert_eq!(status, StatusCode::OK, "miss {attempt} re-renders the form");
            assert!(cookie(&headers, "nodus_auth").is_none());
        }
        assert_eq!(
            challenge_row(&pool, &account_id).await.map(|row| row.0),
            Some(3)
        );

        // The fourth answer is right and the budget is nowhere near spent.
        let (status, headers) = answer_challenge(&app, &challenge, &current_code(&secret, 1)).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert!(cookie(&headers, "nodus_auth").is_some());
        assert!(
            challenge_row(&pool, &account_id).await.is_none(),
            "a success consumes the challenge"
        );
    })
    .await;
}

#[tokio::test]
async fn the_sixth_attempt_finds_no_challenge_and_issues_no_session() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
        let account_id = create_account(&pool).await;
        let secret = totp::generate_secret();
        activate(&pool, &account_id, &secret, &[]).await;
        let (_, challenge) = login(&app).await;
        let challenge = challenge.expect("challenge");

        for attempt in 1..=4 {
            let (status, headers) = answer_challenge(&app, &challenge, "000000").await;
            assert_eq!(status, StatusCode::OK, "miss {attempt} keeps the form");
            assert!(cookie(&headers, "nodus_auth").is_none());
        }

        // The fifth miss spends the budget and sends the user back to the password.
        let (status, headers) = answer_challenge(&app, &challenge, "000000").await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(redirect_target(&headers).as_deref(), Some("/auth/login"));
        assert!(cookie(&headers, "nodus_auth").is_none());
        assert!(
            challenge_row(&pool, &account_id).await.is_none(),
            "the row is deleted at the limit"
        );

        // The sixth answer is correct but the cookie now names nothing.
        let (status, headers) = answer_challenge(&app, &challenge, &current_code(&secret, 1)).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(redirect_target(&headers).as_deref(), Some("/auth/login"));
        assert!(cookie(&headers, "nodus_auth").is_none());

        // Only a fresh password challenge starts over, and it begins with a full budget.
        let (status, fresh) = login(&app).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let (status, headers) = answer_challenge(
            &app,
            &fresh.expect("fresh challenge"),
            &current_code(&secret, 1),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert!(cookie(&headers, "nodus_auth").is_some());
    })
    .await;
}

#[tokio::test]
async fn a_wrong_code_neither_extends_the_window_nor_refreshes_the_cookie() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
        let account_id = create_account(&pool).await;
        activate(&pool, &account_id, &totp::generate_secret(), &[]).await;
        let (_, challenge) = login(&app).await;
        let challenge = challenge.expect("challenge");
        let (_, before) = challenge_row(&pool, &account_id)
            .await
            .expect("challenge row");

        let (status, headers) = answer_challenge(&app, &challenge, "000000").await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            cookie(&headers, "nodus_2fa").is_none(),
            "a miss must not reissue the challenge cookie"
        );

        let (attempts, after) = challenge_row(&pool, &account_id)
            .await
            .expect("challenge row");
        assert_eq!(attempts, 1);
        assert_eq!(after, before, "a miss must not move the deadline");
    })
    .await;
}

#[tokio::test]
async fn recovery_guesses_draw_on_the_same_budget() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
        let account_id = create_account(&pool).await;
        let recovery = "abcd-efgh-ijkl-mnop";
        activate(&pool, &account_id, &totp::generate_secret(), &[recovery]).await;
        let (_, challenge) = login(&app).await;
        let challenge = challenge.expect("challenge");

        // Three digit-pad misses and one recovery-shaped miss leave one attempt in the
        // budget; the next recovery-shaped guess spends it, so both share one counter.
        for code in ["000000", "000000", "000000", "zzzz-zzzz-zzzz-zzzz"] {
            let (status, headers) = answer_challenge(&app, &challenge, code).await;
            assert_eq!(status, StatusCode::OK);
            assert!(cookie(&headers, "nodus_auth").is_none());
        }
        let (status, headers) = answer_challenge(&app, &challenge, "zzzz-zzzz-zzzz-zzzz").await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(redirect_target(&headers).as_deref(), Some("/auth/login"));
        assert!(challenge_row(&pool, &account_id).await.is_none());

        // The one valid recovery code arrives too late and mints no session.
        let (status, headers) = answer_challenge(&app, &challenge, recovery).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert!(cookie(&headers, "nodus_auth").is_none());

        // It was the budget, not the code: a fresh challenge accepts it.
        let (_, fresh) = login(&app).await;
        let (status, headers) = answer_challenge(&app, &fresh.expect("challenge"), recovery).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert!(cookie(&headers, "nodus_auth").is_some());
    })
    .await;
}

#[tokio::test]
async fn concurrent_wrong_answers_cannot_exceed_the_limit() {
    run_db_test(|pool| async move {
        let account_id = create_account(&pool).await;
        // No router and no real token: the property under test is that the read-check-bump
        // cannot lose an update when many answers land on one challenge at once.
        let store = PgAuthStore::new(pool.clone());
        let token_hash = "race-token-hash";
        store
            .create_2fa_challenge(
                token_hash,
                &account_id,
                Utc::now() + chrono::Duration::minutes(5),
            )
            .await
            .expect("challenge");

        let mut tasks = Vec::new();
        for _ in 0..20 {
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                store
                    .record_failed_2fa_attempt(token_hash, nodus_auth::CHALLENGE_ATTEMPTS)
                    .await
                    .expect("record")
            }));
        }
        let mut survived = 0_usize;
        for task in tasks {
            if task.await.expect("task") {
                survived += 1;
            }
        }
        // Exactly limit-1 answers may come back `true`: the last slot deletes the row. A
        // lost-update race would let several tasks read the same count and all pass.
        let expected = usize::try_from(nodus_auth::CHALLENGE_ATTEMPTS - 1).expect("limit");
        assert_eq!(
            survived, expected,
            "concurrent guesses overspent the budget"
        );
        assert!(
            challenge_row(&pool, &account_id).await.is_none(),
            "the row is deleted exactly once"
        );
    })
    .await;
}
