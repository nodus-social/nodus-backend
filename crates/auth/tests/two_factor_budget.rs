//! The account-scoped attempt budget for disabling the second factor.
//!
//! Disabling is session-authenticated, so the sign-in challenge budget does not apply and
//! a stolen session could otherwise loop over a six-digit code. These tests drive the
//! lock through the row's `locked_until` instead of sleeping, and prove the counter is
//! reserved under a row lock rather than read-then-written.

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
const EMAIL: &str = "otp-budget@social.test";

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
    let schema = format!("pgtest_otp_budget_{}", ulid::Ulid::new()).to_lowercase();
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
         VALUES ($1, 'otpbudgetuser', 'otpbudgetuser', true, true)",
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

async fn session_for(pool: &PgPool, account_id: &str) -> String {
    let token = format!("budget-test-session-{}", ulid::Ulid::new()).to_lowercase();
    PgAuthStore::new(pool.clone())
        .create_session(
            &nodus_auth::domain::token_hash(&token),
            account_id,
            Utc::now() + Duration::days(1),
            "budget-test",
            None,
        )
        .await
        .expect("create session");
    token
}

/// Confirms a factor directly, with a replay floor below the current step so a current
/// code is accepted on the disable route.
async fn activate(pool: &PgPool, account_id: &str, secret: &str, floor_offset: i64) {
    let store = PgAuthStore::new(pool.clone());
    let step = i64::try_from(totp::step_at(Utc::now().timestamp())).expect("step") + floor_offset;
    store
        .start_totp_enrolment(account_id, secret)
        .await
        .expect("enrol");
    store
        .confirm_totp(account_id, step, &[])
        .await
        .expect("confirm");
}

fn csrf() -> (String, String) {
    let nonce = "test-nonce".to_owned();
    let token = nodus_auth::domain::csrf_token(&nonce, None);
    (format!("nodus_csrf={nonce}"), token)
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

fn current_code(secret: &str, offset: i64) -> String {
    let step = i64::try_from(totp::step_at(Utc::now().timestamp())).expect("step") + offset;
    totp::code_at(secret, u64::try_from(step).expect("step")).expect("code")
}

fn state(body: &str) -> Value {
    serde_json::from_str(body).expect("json body")
}

async fn disable(app: &Router, cookies: &str, code: &str) -> (StatusCode, HeaderMap, String) {
    send(
        app,
        post_json(
            "/auth/2fa/disable",
            cookies,
            &json!({ "csrf_token": csrf().1, "code": code }),
        ),
    )
    .await
}

async fn attempt_row(
    pool: &PgPool,
    account_id: &str,
) -> Option<(i32, Option<chrono::DateTime<Utc>>)> {
    sqlx::query_as(
        "SELECT failed_attempts, locked_until FROM account_2fa_disable_attempt \
         WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await
    .expect("read attempt row")
}

#[tokio::test]
async fn five_wrong_codes_then_a_correct_one_is_refused_with_429() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
        let account_id = create_account(&pool).await;
        let secret = totp::generate_secret();
        activate(&pool, &account_id, &secret, -2).await;
        let session = session_for(&pool, &account_id).await;
        let cookies = format!("nodus_auth={session}; {}", csrf().0);

        for attempt in 1..=5 {
            let (status, _, _) = disable(&app, &cookies, "000000").await;
            if attempt < 5 {
                assert_eq!(
                    status,
                    StatusCode::BAD_REQUEST,
                    "miss {attempt} is a plain refusal"
                );
            }
        }

        // The lock is set by the fifth miss; a correct code submitted afterwards must not
        // be looked at, or the lock would only slow an attacker down by one guess.
        let (status, headers, body) = disable(&app, &cookies, &current_code(&secret, 0)).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            state(&body)["message"],
            "Too many codes tried. Try again in 15 minutes."
        );
        assert!(
            headers
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<i64>().ok())
                .is_some_and(|seconds| seconds > 0 && seconds <= 15 * 60),
            "Retry-After names the remaining window"
        );

        let (_, _, body) = send(
            &app,
            Request::builder()
                .method("GET")
                .uri("/auth/2fa")
                .header(header::ACCEPT, "application/json")
                .header(header::COOKIE, &cookies)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(
            state(&body)["enabled"],
            true,
            "the factor survives the lock"
        );
        let (attempts, locked_until) = attempt_row(&pool, &account_id).await.expect("row");
        assert_eq!(attempts, 5);
        assert!(locked_until.is_some());
    })
    .await;
}

#[tokio::test]
async fn a_lapsed_lock_lets_the_correct_code_through() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
        let account_id = create_account(&pool).await;
        let secret = totp::generate_secret();
        activate(&pool, &account_id, &secret, -2).await;
        let session = session_for(&pool, &account_id).await;
        let cookies = format!("nodus_auth={session}; {}", csrf().0);

        for _ in 0..5 {
            let _ = disable(&app, &cookies, "000000").await;
        }
        // Drive time instead of sleeping: the lock deadline is the only clock the route
        // consults, so moving it into the past is exactly what fifteen minutes does.
        sqlx::query(
            "UPDATE account_2fa_disable_attempt SET locked_until = now() - interval '1 second' \
             WHERE account_id = $1",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .expect("lapse the lock");

        let (status, _, body) = disable(&app, &cookies, &current_code(&secret, 0)).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(state(&body)["enabled"], false);
        assert!(
            attempt_row(&pool, &account_id).await.is_none(),
            "a completed disable clears the budget"
        );
    })
    .await;
}

#[tokio::test]
async fn a_successful_disable_clears_the_budget() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
        let account_id = create_account(&pool).await;
        let secret = totp::generate_secret();
        activate(&pool, &account_id, &secret, -2).await;
        let session = session_for(&pool, &account_id).await;
        let cookies = format!("nodus_auth={session}; {}", csrf().0);

        for _ in 0..4 {
            let (status, _, _) = disable(&app, &cookies, "000000").await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        assert_eq!(attempt_row(&pool, &account_id).await.expect("row").0, 4);

        let (status, _, _) = disable(&app, &cookies, &current_code(&secret, 0)).await;
        assert_eq!(status, StatusCode::OK);

        // Re-enrol the factor; the next miss must be the first of a new run, not the fifth
        // of the old one.
        let fresh = totp::generate_secret();
        activate(&pool, &account_id, &fresh, -2).await;
        let (status, _, _) = disable(&app, &cookies, "000000").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(attempt_row(&pool, &account_id).await.expect("row").0, 1);
    })
    .await;
}

#[tokio::test]
async fn concurrent_wrong_codes_cannot_both_observe_four() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
        let account_id = create_account(&pool).await;
        activate(&pool, &account_id, &totp::generate_secret(), -2).await;
        let session = session_for(&pool, &account_id).await;
        let cookies = format!("nodus_auth={session}; {}", csrf().0);
        sqlx::query(
            "INSERT INTO account_2fa_disable_attempt \
                 (account_id, failed_attempts, first_attempt_at) \
             VALUES ($1, 4, now())",
        )
        .bind(&account_id)
        .execute(&pool)
        .await
        .expect("seed four misses");

        let first = disable(&app, &cookies, "000000");
        let second = disable(&app, &cookies, "000001");
        let (left, right) = tokio::join!(first, second);

        // Two guesses that both read "4" would both be answered 400 and would push the
        // counter to six. With the count reserved under the row lock, the fifth miss is
        // the lock and the second request sees it.
        assert_eq!(left.0, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(right.0, StatusCode::TOO_MANY_REQUESTS);
        let (attempts, locked_until) = attempt_row(&pool, &account_id).await.expect("row");
        assert_eq!(attempts, 5, "the limit is reached once, not once per racer");
        assert!(locked_until.is_some());
    })
    .await;
}

#[tokio::test]
async fn enrolling_over_a_confirmed_factor_is_refused() {
    run_db_test(|pool| async move {
        let app = nodus_auth::router(AppState::new(PgAuthStore::new(pool.clone()), config()));
        let account_id = create_account(&pool).await;
        activate(&pool, &account_id, &totp::generate_secret(), -2).await;
        let session = session_for(&pool, &account_id).await;
        let cookies = format!("nodus_auth={session}; {}", csrf().0);

        // Re-enrolling over a confirmed factor would replace the secret without proving
        // the old one, which is a disable by another name.
        let (status, _, body) = send(
            &app,
            post_json(
                "/auth/2fa/enroll",
                &cookies,
                &json!({ "csrf_token": csrf().1 }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(state(&body)["error"], "two_factor_already_enabled");
    })
    .await;
}
