//! The moderation dashboard's numbers: one query per section, honest about empty data,
//! and identical for a minute because the console polls it.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use chrono::{DateTime, Duration, Utc};
use http_body_util::BodyExt;
use serde_json::{json, Value};
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

async fn connect_isolated_store() -> Option<(Store, Store, String)> {
    let url = std::env::var("DATABASE_URL").ok()?;
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
    Some((admin, store, schema))
}

async fn run_db_test<F, Fut>(body: F)
where
    F: FnOnce(Store, Router) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some((admin, store, schema)) = connect_isolated_store().await else {
        return;
    };
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

async fn staff_account(pool: &PgPool, label: &str, role: &str) -> String {
    let id = create_account(pool, label).await;
    accounts::set_staff_role(pool, &id, role)
        .await
        .expect("set staff role");
    id
}

async fn create_token(pool: &PgPool, account_id: &str, scopes: &[&str]) -> String {
    let app_id = Id::new().to_string();
    let client_id = format!("pgtest-client-{app_id}");
    let owned: Vec<String> = scopes.iter().map(|scope| (*scope).to_owned()).collect();
    apps::register(
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
    let digest = format!("{:x}", Sha256::digest(token.as_bytes()));
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

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let body = match body {
        Some(value) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(request.body(body).expect("build request"))
        .await
        .expect("route request");
    let status = response.status();
    let bytes = response.into_body().collect().await.expect("read body");
    let value = serde_json::from_slice(&bytes.to_bytes()).unwrap_or(Value::Null);
    (status, value)
}

/// A report as the queue holds it, with a timestamp the window arithmetic can predict.
async fn insert_report(
    pool: &PgPool,
    reporter: &str,
    target: &str,
    created_at: DateTime<Utc>,
) -> String {
    let id = Id::new().to_string();
    sqlx::query(
        "INSERT INTO report (id, account_id, target_account_id, category, comment, created_at, updated_at) \
         VALUES ($1, $2, $3, 'spam', 'test report', $4, $4)",
    )
    .bind(&id)
    .bind(reporter)
    .bind(target)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("insert report");
    id
}

async fn insert_resolution(pool: &PgPool, actor: &str, report_id: &str, created_at: DateTime<Utc>) {
    sqlx::query(
        "INSERT INTO audit_log (id, actor_id, action, target_type, target_id, created_at) \
         VALUES ($1, $2, 'resolve_report_with_note', 'report', $3, $4)",
    )
    .bind(Id::new().to_string())
    .bind(actor)
    .bind(report_id)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("insert resolve audit");
    sqlx::query("UPDATE report SET state = 'resolved' WHERE id = $1")
        .bind(report_id)
        .execute(pool)
        .await
        .expect("mark report resolved");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resolved_report_counts_once_with_the_action_that_resolved_it() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let staff = staff_account(pool, "moderator", "moderator").await;
        let token = create_token(pool, &staff, &["admin:read", "admin:write"]).await;
        let reporter = create_account(pool, "reporter").await;
        let target = create_account(pool, "target").await;
        let report = insert_report(pool, &reporter, &target, Utc::now()).await;

        let (code, body) = call(
            &app,
            "POST",
            &format!("/api/v1/admin/accounts/{target}/action"),
            Some(&token),
            Some(json!({
                "type": "silence",
                "text": "repeated spam",
                "report_id": report,
            })),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{body}");

        let (code, body) = call(
            &app,
            "GET",
            "/api/v1/admin/stats?range=7d",
            Some(&token),
            None,
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{body}");
        assert_eq!(body["reports"]["opened"], 1);
        assert_eq!(body["reports"]["resolved"], 1, "{body}");
        assert_eq!(body["reports"]["pending"], 0);
        assert_eq!(body["decisions_by_action"]["silence"], 1);
        assert_eq!(body["decisions_by_action"]["suspend"], 0);
        assert!(body["median_time_to_decision_seconds"].as_f64().is_some());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unresolved_report_is_only_pending_and_the_answer_is_cached() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let staff = staff_account(pool, "moderator", "moderator").await;
        let token = create_token(pool, &staff, &["admin:read"]).await;
        let reporter = create_account(pool, "reporter").await;
        let target = create_account(pool, "target").await;
        insert_report(pool, &reporter, &target, Utc::now()).await;

        let (code, body) = call(
            &app,
            "GET",
            "/api/v1/admin/stats?range=7d",
            Some(&token),
            None,
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{body}");
        assert_eq!(body["reports"]["opened"], 1);
        assert_eq!(body["reports"]["resolved"], 0);
        assert_eq!(body["reports"]["reopened"], 0);
        assert_eq!(body["reports"]["pending"], 1);
        assert_eq!(
            body["decisions_by_action"],
            json!({
                "approve": 0, "reject": 0, "silence": 0, "suspend": 0, "enable": 0,
            })
        );
        assert!(body["median_time_to_decision_seconds"].is_null(), "{body}");

        // A second report arrives; the console polling again within the minute sees the
        // same document because the answer is cached per range.
        insert_report(pool, &reporter, &target, Utc::now()).await;
        let (code, body) = call(
            &app,
            "GET",
            "/api/v1/admin/stats?range=7d",
            Some(&token),
            None,
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(
            body["reports"]["pending"], 1,
            "the 7d answer was not cached"
        );
        assert_eq!(body["reports"]["opened"], 1);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_median_is_null_without_decisions_and_uses_the_known_gaps() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let staff = staff_account(pool, "moderator", "moderator").await;
        let token = create_token(pool, &staff, &["admin:read"]).await;
        let reporter = create_account(pool, "reporter").await;
        let target = create_account(pool, "target").await;

        // Nothing has ever been decided: the median is null, not zero.
        let (code, body) = call(
            &app,
            "GET",
            "/api/v1/admin/stats?range=7d",
            Some(&token),
            None,
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{body}");
        assert!(body["median_time_to_decision_seconds"].is_null(), "{body}");

        // Two reports resolved 10s and 30s after they were opened. The 7d answer above is
        // cached, so the fresh read asks for 30d, which also covers both pairs.
        let now = Utc::now();
        let slow = insert_report(pool, &reporter, &target, now - Duration::seconds(100)).await;
        insert_resolution(pool, &staff, &slow, now - Duration::seconds(90)).await;
        let slower = insert_report(pool, &reporter, &target, now - Duration::seconds(50)).await;
        insert_resolution(pool, &staff, &slower, now - Duration::seconds(20)).await;

        let (code, body) = call(
            &app,
            "GET",
            "/api/v1/admin/stats?range=30d",
            Some(&token),
            None,
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{body}");
        assert_eq!(body["reports"]["resolved"], 2);
        let median = body["median_time_to_decision_seconds"]
            .as_f64()
            .expect("two decisions have a median");
        assert!((median - 20.0).abs() < 0.001, "median was {median}");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_only_token_is_refused() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let staff = staff_account(pool, "moderator", "moderator").await;
        let token = create_token(pool, &staff, &["read"]).await;

        let (code, body) = call(
            &app,
            "GET",
            "/api/v1/admin/stats?range=7d",
            Some(&token),
            None,
        )
        .await;
        assert_eq!(code, StatusCode::FORBIDDEN, "{body}");

        let (code, _) = call(&app, "GET", "/api/v1/admin/stats?range=7d", None, None).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
    })
    .await;
}
