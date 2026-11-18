//! What staff can see and undo about the remote blocks that silence deliveries.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

use nodus_server_api::{root_router, AppState, InstanceConfig};
use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount};
use nodus_server_store::blocks;
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

async fn create_account(pool: &PgPool, label: &str, admin: bool) -> String {
    let username = format!("pgtest_{label}_{}", Id::new());
    let row = accounts::insert(
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
    .expect("insert account");
    if admin {
        sqlx::query("UPDATE account SET admin = true, approved = true WHERE id = $1")
            .bind(&row.id)
            .execute(pool)
            .await
            .expect("make the account staff");
    }
    row.id
}

async fn create_token(pool: &PgPool, account_id: &str, scopes: &[&str]) -> String {
    let app_id = Id::new().to_string();
    let client_id = format!("pgtest-client-{app_id}");
    let scopes: Vec<String> = scopes.iter().map(|scope| (*scope).to_owned()).collect();
    apps::register(
        pool,
        &app_id,
        &client_id,
        "unused",
        "pgtest",
        None,
        &["urn:ietf:wg:oauth:2.0:oob".to_owned()],
        &scopes,
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
    .bind(&scopes[..])
    .execute(pool)
    .await
    .expect("insert oauth token");

    token
}

async fn send(
    state: &AppState,
    method: Method,
    path: &str,
    token: &str,
    content_type: Option<&str>,
    body: &str,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"));
    if let Some(content_type) = content_type {
        request = request.header("content-type", content_type);
    }
    let response = root_router(state.clone())
        .oneshot(
            request
                .body(Body::from(body.to_owned()))
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
async fn staff_list_blocks_and_clear_a_host_by_json_or_query() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let staff = create_account(pool, "staff", true).await;
        let token = create_token(pool, &staff, &["read", "admin:read", "admin:write"]).await;

        blocks::record_remote_block(pool, "https://quiet.test/users/a")
            .await
            .expect("record block");
        blocks::record_remote_block(pool, "https://other.test/users/b")
            .await
            .expect("record another block");

        let (status, body) = send(
            &state,
            Method::GET,
            "/api/v1/admin/federation/remote-blocks",
            &token,
            None,
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let listed = body["blocks"].as_array().expect("blocks array");
        assert_eq!(listed.len(), 2);
        assert!(
            listed
                .iter()
                .any(|block| block["actor"] == "https://quiet.test/users/a"
                    && block["host"] == "quiet.test"
                    && block["created_at"].is_string()),
            "body: {body}"
        );

        let (status, _) = send(
            &state,
            Method::DELETE,
            "/api/v1/admin/federation/remote-blocks",
            &token,
            Some("application/json"),
            r#"{"host":"quiet.test"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(
            blocks::blocked_hosts(pool).await.expect("blocked hosts"),
            vec!["other.test".to_owned()]
        );

        let (status, _) = send(
            &state,
            Method::DELETE,
            "/api/v1/admin/federation/remote-blocks?host=other.test",
            &token,
            None,
            "",
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(blocks::blocked_hosts(pool)
            .await
            .expect("blocked hosts")
            .is_empty());

        let (status, body) = send(
            &state,
            Method::DELETE,
            "/api/v1/admin/federation/remote-blocks?host=other.test",
            &token,
            None,
            "",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");

        let (status, body) = send(
            &state,
            Method::DELETE,
            "/api/v1/admin/federation/remote-blocks",
            &token,
            Some("application/json"),
            "{}",
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
    })
    .await;
}

#[tokio::test]
async fn a_reader_cannot_list_or_clear_remote_blocks() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let reader = create_account(pool, "reader", false).await;
        let token = create_token(pool, &reader, &["read"]).await;

        let (status, body) = send(
            &state,
            Method::GET,
            "/api/v1/admin/federation/remote-blocks",
            &token,
            None,
            "",
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");

        blocks::record_remote_block(pool, "https://quiet.test/users/a")
            .await
            .expect("record block");
        let (status, _) = send(
            &state,
            Method::DELETE,
            "/api/v1/admin/federation/remote-blocks?host=quiet.test",
            &token,
            None,
            "",
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            blocks::blocked_hosts(pool).await.expect("blocked hosts"),
            vec!["quiet.test".to_owned()]
        );
    })
    .await;
}
