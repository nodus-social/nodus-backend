//! `GET /api/v1/streaming`: authentication before the first byte, one live
//! notification in Mastodon's wire shape, the keepalive, and the connection closing.
//!
//! Like the other database tests, the whole file is skipped when `DATABASE_URL` is unset.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use std::time::Duration;
use tower::ServiceExt;

use nodus_server_api::{root_router, AppState, InstanceConfig};
use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount};
use nodus_server_store::{social, Store};

fn instance_config() -> InstanceConfig {
    InstanceConfig {
        domain: "social.test".to_owned(),
        base_url: "https://social.test".to_owned(),
        title: "Nodus test".to_owned(),
        description: "A test instance".to_owned(),
        contact_email: None,
        api_version: "4.3.0".to_owned(),
        version: "0.1.0".to_owned(),
        registrations_open: false,
    }
}

/// Runs `body` against a schema of its own, then drops the schema.
async fn run_db_test<F, Fut>(body: F)
where
    F: FnOnce(Store, Router) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some(url) = std::env::var("DATABASE_URL").ok() else {
        return;
    };
    let admin = Store::connect(&url, 1).await.expect("connect to postgres");
    let schema = format!("pgtest_{}", Id::new()).to_lowercase();
    sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
        .execute(admin.pool())
        .await
        .expect("create isolated test schema");
    let sep = if url.contains('?') { '&' } else { '?' };
    let schema_url = format!("{url}{sep}options=-csearch_path%3D{schema}%2Cpublic");
    let store = Store::connect(&schema_url, 5)
        .await
        .expect("connect isolated store");
    store.migrate().await.expect("run migrations");
    let app = root_router(AppState::new(store.clone(), instance_config()));

    let outcome = tokio::spawn(async move { body(store, app).await }).await;
    let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
        .execute(admin.pool())
        .await;
    if let Err(err) = outcome {
        std::panic::resume_unwind(err.into_panic());
    }
}

async fn create_account(pool: &PgPool, label: &str) -> String {
    let username = format!("pgtest_{label}_{}", Id::new()).to_lowercase();
    accounts::insert(
        pool,
        &NewAccount {
            username: &username,
            display_name: &username,
            note: "",
            bot: false,
            locked: false,
        },
    )
    .await
    .expect("insert account")
    .id
}

async fn create_token(pool: &PgPool, account_id: &str, scopes: &[&str]) -> String {
    let app_id = Id::new().to_string();
    let client_id = format!("pgtest-client-{app_id}");
    let owned: Vec<String> = scopes.iter().map(|s| (*s).to_owned()).collect();
    nodus_server_store::apps::register(
        pool,
        &app_id,
        &client_id,
        "unused",
        "pgtest",
        None,
        &["urn:ietf:wg:oauth:2.0:oob".to_owned()],
        &owned,
    )
    .await
    .expect("register app");

    let token = format!("pgtest-token-{}", Id::new());
    let digest = format!(
        "{:x}",
        <sha2::Sha256 as sha2::Digest>::digest(token.as_bytes())
    );
    sqlx::query(
        "INSERT INTO oauth_token (id, app_id, account_id, token_hash, scopes) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Id::new().to_string())
    .bind(&app_id)
    .bind(account_id)
    .bind(&digest)
    .bind(&owned)
    .execute(pool)
    .await
    .expect("insert oauth token");
    token
}

/// The next body chunk, or `None` when the stream ended; panics on the timeout so a
/// stalled stream fails the test instead of hanging it.
async fn next_chunk(body: &mut Body, within: Duration, what: &str) -> String {
    let frame = tokio::time::timeout(within, body.frame())
        .await
        .unwrap_or_else(|_| panic!("no {what} within {within:?}"))
        .expect("stream ended unexpectedly")
        .expect("body frame");
    let data = frame.into_data().expect("data frame");
    String::from_utf8_lossy(&data).into_owned()
}

#[tokio::test]
async fn an_anonymous_stream_is_a_json_401_before_any_stream_bytes() {
    run_db_test(|_store, app| async move {
        let request = Request::builder()
            .uri("/api/v1/streaming?stream=user")
            .body(Body::empty())
            .expect("request");
        let response = app.oneshot(request).await.expect("router response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json"),
            "a stream must be refused before it opens, not after"
        );
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("401 body")
            .to_bytes();
        let value: Value = serde_json::from_slice(&bytes).expect("JSON error body");
        assert_eq!(value["error"], "The access token is invalid");
    })
    .await;
}

#[tokio::test]
async fn a_notification_arrives_as_one_mastodon_event_and_the_stream_closes() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let sender = create_account(&pool, "sender").await;
        let token = create_token(&pool, &reader, &["read:notifications"]).await;
        let baseline = nodus_server_store::live::live_streams();

        // The query-parameter token is the path an `EventSource` takes: no headers.
        let request = Request::builder()
            .uri(format!(
                "/api/v1/streaming?stream=user&access_token={token}"
            ))
            .body(Body::empty())
            .expect("request");
        let response = app.oneshot(request).await.expect("router response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/event-stream")
        );
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );
        assert_eq!(
            response
                .headers()
                .get("x-accel-buffering")
                .and_then(|value| value.to_str().ok()),
            Some("no")
        );

        let mut body = response.into_body();
        let opening = next_chunk(&mut body, Duration::from_secs(2), "opening comment").await;
        assert!(opening.starts_with(':'), "got {opening:?}");
        assert_eq!(nodus_server_store::live::live_streams(), baseline + 1);

        // The write path the rest of the server already uses: no second producer.
        social::notify(&pool, &reader, "follow", &sender, None)
            .await
            .expect("write notification");

        let mut seen = String::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !seen.contains("event: notification") {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let chunk = next_chunk(&mut body, left, "notification event").await;
            seen.push_str(&chunk);
        }
        let data = seen
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .expect("data line");
        let value: Value = serde_json::from_str(data).expect("notification JSON");
        assert_eq!(value["type"], "follow");
        assert_eq!(value["account"]["id"], sender);

        // Dropping the client half is the disconnect: the stream's subscription goes with
        // it, so the live count falls back rather than leaking one per closed tab.
        drop(body);
        let mut closed = false;
        for _ in 0..50 {
            if nodus_server_store::live::live_streams() == baseline {
                closed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(closed, "live stream count did not return to baseline");
    })
    .await;
}

#[tokio::test]
async fn a_keepalive_comment_arrives_on_the_configured_interval() {
    // One second instead of the production fifteen, so CI proves the frame without
    // sleeping through it. The handler reads the variable per request.
    std::env::set_var("NODUS_STREAM_KEEPALIVE_SECS", "1");
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "keepalive").await;
        let token = create_token(&pool, &reader, &["read"]).await;
        let request = Request::builder()
            .uri(format!(
                "/api/v1/streaming?stream=user&access_token={token}"
            ))
            .body(Body::empty())
            .expect("request");
        let response = app.oneshot(request).await.expect("router response");
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        let opening = next_chunk(&mut body, Duration::from_secs(2), "opening comment").await;
        assert!(opening.starts_with(':'), "got {opening:?}");
        let keepalive = next_chunk(&mut body, Duration::from_secs(5), "keepalive").await;
        assert_eq!(keepalive, ":keepalive\n\n");
    })
    .await;
    std::env::remove_var("NODUS_STREAM_KEEPALIVE_SECS");
}

#[tokio::test]
async fn an_unknown_stream_name_is_a_400_not_an_open_stream() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "unknown").await;
        let token = create_token(&pool, &reader, &["read"]).await;
        let request = Request::builder()
            .uri(format!(
                "/api/v1/streaming?stream=public&access_token={token}"
            ))
            .body(Body::empty())
            .expect("request");
        let response = app.oneshot(request).await.expect("router response");
        // `public` is deliberately not served in this slice; the caller learns that here
        // rather than through a stream that connects and stays silent forever.
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
    })
    .await;
}
