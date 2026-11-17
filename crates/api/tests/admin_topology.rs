//! What the process view answers to someone who is not staff, and how it behaves when a
//! service never answers.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

use nodus_server_api::{root_router, AppState, InstanceConfig};
use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount};
use nodus_server_store::{apps, Store};

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

/// A socket that accepts a connection and then says nothing, and the registry that points
/// at it.
///
/// The registry is read once per process, so the address is chosen before the first request
/// in either test. The listener is leaked on purpose: dropping it would turn the "silent"
/// node into a refused connection, which is a different path.
fn silent_node() -> &'static str {
    static NODE: OnceLock<String> = OnceLock::new();
    NODE.get_or_init(|| {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind silent node");
        let address = listener.local_addr().expect("silent node address");
        std::mem::forget(listener);
        let target = format!("quiet=tcp://{address}");
        std::env::set_var("NODUS_TELEMETRY", &target);
        target
    })
}

async fn connect_isolated_store() -> Option<(Store, Store, String)> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let admin = Store::connect(&url, 1).await.expect("connect to postgres");
    let schema = format!("pgtest_{}", Id::new());
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
    Some((admin, store, schema))
}

async fn run_db_test<F, Fut>(body: F)
where
    F: FnOnce(Store, AppState) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some((admin, store, schema)) = connect_isolated_store().await else {
        return;
    };
    let state = AppState::new(store.clone(), instance_config());
    let handle = tokio::spawn(async move { body(store, state).await });
    let outcome = handle.await;

    let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
        .execute(admin.pool())
        .await;

    if let Err(err) = outcome {
        std::panic::resume_unwind(err.into_panic());
    }
}

async fn create_account(pool: &PgPool, label: &str) -> String {
    let username = format!("pgtest_{label}_{}", Id::new());
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

async fn create_token(pool: &PgPool, account_id: &str) -> String {
    let app_id = Id::new().to_string();
    let client_id = format!("pgtest-client-{app_id}");
    apps::register(
        pool,
        &app_id,
        &client_id,
        "unused",
        "pgtest",
        None,
        &["urn:ietf:wg:oauth:2.0:oob".to_owned()],
        &["read".to_owned(), "admin:read".to_owned()],
    )
    .await
    .expect("register app");

    let token = format!("pgtest-token-{}", Id::new());
    let digest = format!("{:x}", Sha256::digest(token.as_bytes()));
    sqlx::query(
        "INSERT INTO oauth_token (id, app_id, account_id, token_hash, scopes) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Id::new().to_string())
    .bind(&app_id)
    .bind(account_id)
    .bind(&digest)
    .bind(&["read".to_owned(), "admin:read".to_owned()][..])
    .execute(pool)
    .await
    .expect("insert oauth token");

    token
}

async fn read(state: &AppState, token: &str, path: &str) -> (StatusCode, serde_json::Value) {
    let response = root_router(state.clone())
        .oneshot(
            Request::builder()
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send request");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
        .await
        .expect("read body");
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, body)
}

#[tokio::test]
async fn the_process_view_is_closed_to_anyone_who_is_not_staff() {
    silent_node();
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let reader = create_account(pool, "reader").await;
        let reader_token = create_token(pool, &reader).await;

        let (status, body) = read(&state, &reader_token, "/api/v1/admin/topology").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
        assert_eq!(body["error"], "Administrator access is required");

        let (status, body) = read(&state, &reader_token, "/api/v1/admin/topology/quiet/logs").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "Administrator access is required");

        let staff = create_account(pool, "staff").await;
        sqlx::query("UPDATE account SET admin = true, approved = true WHERE id = $1")
            .bind(&staff)
            .execute(pool)
            .await
            .expect("make the account staff");
        let staff_token = create_token(pool, &staff).await;

        let (status, body) = read(&state, &staff_token, "/api/v1/admin/topology").await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["nodes"][0]["name"], "quiet");
    })
    .await;
}

#[tokio::test]
async fn a_service_that_never_answers_is_marked_dead_within_the_budget() {
    silent_node();
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let staff = create_account(pool, "staff").await;
        sqlx::query("UPDATE account SET admin = true, approved = true WHERE id = $1")
            .bind(&staff)
            .execute(pool)
            .await
            .expect("make the account staff");
        let token = create_token(pool, &staff).await;

        let started = Instant::now();
        let (status, body) = read(&state, &token, "/api/v1/admin/topology").await;
        let elapsed = started.elapsed();

        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert!(
            elapsed < Duration::from_secs(2),
            "the view took {elapsed:?}, so a silent service stalled it"
        );
        let node = &body["nodes"][0];
        assert_eq!(node["status"], "dead", "body: {body}");
        assert!(
            node["latency_ms"].as_u64().expect("latency") >= 250,
            "a dead node reports how long it waited: {body}"
        );
        assert_eq!(node["last_error"], "no answer within 250 ms");
        assert_eq!(node["endpoint"], "tcp", "a raw address is not published");
    })
    .await;
}
