//! Who may enter which door.
//!
//! The role is the grant now: a moderator and an administrator both hold
//! `admin:read`/`admin:write`, and the route decides which of them reaches it. These tests
//! pin the split where it matters — moderation work is shared, and the settings that
//! change the instance or its staff are not.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
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

/// A staff account with a token that carries the same scopes a real staff token would.
async fn staff(pool: &PgPool, label: &str, role: &str) -> (String, String) {
    let id = create_account(pool, label).await;
    accounts::set_staff_role(pool, &id, role)
        .await
        .expect("grant role");
    let token = create_token(pool, &id, &["admin:read", "admin:write"]).await;
    (id, token)
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
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

#[tokio::test(flavor = "multi_thread")]
async fn a_moderator_reaches_moderation() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, token) = staff(pool, "mod", "moderator").await;
        let target = create_account(pool, "target").await;

        let (status, _) = call(&app, "GET", "/api/v1/admin/reports", &token, None).await;
        assert_eq!(status, StatusCode::OK, "reports are moderator work");

        let (status, body) = call(
            &app,
            "POST",
            &format!("/api/v1/admin/accounts/{target}/action"),
            &token,
            Some(json!({"type": "silence", "text": "cool off"})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "silencing is moderator work: {body}"
        );

        let (status, _) = call(
            &app,
            "GET",
            &format!("/api/v1/admin/accounts/{target}"),
            &token,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "reading accounts is moderator work");

        let (status, _) = call(&app, "GET", "/api/v1/admin/alerts", &token, None).await;
        assert_eq!(status, StatusCode::OK, "the alert list is shared");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_moderator_is_refused_the_administrator_doors() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, token) = staff(pool, "mod", "moderator").await;
        let target = create_account(pool, "target").await;

        let refusals: Vec<(&str, String, Option<Value>)> = vec![
            ("GET", "/api/v1/admin/scanners".to_owned(), None),
            (
                "POST",
                "/api/v1/admin/announcements".to_owned(),
                Some(json!({"content": "hello"})),
            ),
            (
                "POST",
                "/api/v1/admin/warning_presets".to_owned(),
                Some(json!({"title": "t", "text": "x"})),
            ),
            ("GET", "/api/v1/admin/email_domain_blocks".to_owned(), None),
            (
                "POST",
                "/api/v1/admin/topology/feed/trigger".to_owned(),
                Some(json!({"work": "deliver"})),
            ),
            (
                "PUT",
                format!("/api/v1/admin/accounts/{target}/role"),
                Some(json!({"role": "admin"})),
            ),
        ];
        for (method, uri, body) in refusals {
            let (status, answer) = call(&app, method, &uri, &token, body).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{method} {uri} is administrator-only, got {answer}"
            );
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_administrator_reaches_the_same_doors() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, token) = staff(pool, "admin", "admin").await;
        let target = create_account(pool, "target").await;

        let (status, body) = call(&app, "GET", "/api/v1/admin/scanners", &token, None).await;
        assert_eq!(status, StatusCode::OK, "scanners: {body}");

        let (status, body) = call(
            &app,
            "POST",
            "/api/v1/admin/announcements",
            &token,
            Some(json!({"content": "hello"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "announcements: {body}");

        let (status, body) = call(
            &app,
            "POST",
            "/api/v1/admin/warning_presets",
            &token,
            Some(json!({"title": "t", "text": "x"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "warning presets: {body}");

        let (status, body) = call(
            &app,
            "GET",
            "/api/v1/admin/email_domain_blocks",
            &token,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "email domains: {body}");

        let (status, body) = call(
            &app,
            "PUT",
            &format!("/api/v1/admin/accounts/{target}/role"),
            &token,
            Some(json!({"role": "moderator"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "role change: {body}");
        assert_eq!(body["role"], json!("moderator"));

        // The topology trigger may fail to reach the node; what it must not do is refuse
        // the caller, which is the difference this route split is about.
        let (status, _) = call(
            &app,
            "POST",
            "/api/v1/admin/topology/feed/trigger",
            &token,
            Some(json!({"work": "deliver"})),
        )
        .await;
        assert_ne!(status, StatusCode::FORBIDDEN, "an administrator reaches it");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_role_change_mirrors_the_admin_boolean() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, token) = staff(pool, "admin", "admin").await;
        let target = create_account(pool, "target").await;

        for (role, mirrors, admin) in [
            ("moderator", true, true),
            ("admin", true, true),
            ("none", false, false),
        ] {
            let (status, body) = call(
                &app,
                "PUT",
                &format!("/api/v1/admin/accounts/{target}/role"),
                &token,
                Some(json!({"role": role})),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{role}: {body}");
            assert_eq!(body["role"], json!(role));
            assert_eq!(body["admin"], json!(mirrors), "the DTO mirrors too");

            let row: (bool, String) =
                sqlx::query_as("SELECT admin, staff_role FROM account WHERE id = $1")
                    .bind(&target)
                    .fetch_one(pool)
                    .await
                    .expect("read account");
            assert_eq!(row.0, admin, "admin mirrors {role}");
            assert_eq!(row.1, role);
        }

        let (status, _) = call(
            &app,
            "PUT",
            &format!("/api/v1/admin/accounts/{}/role", Id::new()),
            &token,
            Some(json!({"role": "admin"})),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unknown accounts are 404");

        let (status, _) = call(
            &app,
            "PUT",
            &format!("/api/v1/admin/accounts/{target}/role"),
            &token,
            Some(json!({"role": "owner"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unknown roles are refused");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_last_administrator_cannot_be_demoted() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (only_admin, token) = staff(pool, "admin", "admin").await;
        let second = create_account(pool, "second").await;

        let (status, body) = call(
            &app,
            "PUT",
            &format!("/api/v1/admin/accounts/{second}/role"),
            &token,
            Some(json!({"role": "admin"})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "appoint a second administrator: {body}"
        );

        // The token's account is now one of two, so it may step down.
        let (status, body) = call(
            &app,
            "PUT",
            &format!("/api/v1/admin/accounts/{only_admin}/role"),
            &token,
            Some(json!({"role": "moderator"})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "step down while another remains: {body}"
        );
        assert_eq!(body["role"], json!("moderator"));

        // Now `second` is the only administrator, and a moderator may not remove it.
        let (status, _) = call(
            &app,
            "PUT",
            &format!("/api/v1/admin/accounts/{second}/role"),
            &token,
            Some(json!({"role": "none"})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a moderator cannot change roles"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_last_administrator_check_holds_for_an_administrator() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (admin_id, token) = staff(pool, "admin", "admin").await;

        let (status, body) = call(
            &app,
            "PUT",
            &format!("/api/v1/admin/accounts/{admin_id}/role"),
            &token,
            Some(json!({"role": "moderator"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|text| text.contains("last administrator")),
            "the refusal says why: {body}"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn account_role_answers_for_every_signed_in_account() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let plain = create_account(pool, "plain").await;
        let plain_token = create_token(pool, &plain, &["read", "write"]).await;
        let (_, moderator_token) = staff(pool, "mod", "moderator").await;

        let (status, body) = call(
            &app,
            "GET",
            "/api/v1/nodus/account/role",
            &plain_token,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "a plain user may ask: {body}");
        assert_eq!(body["role"], json!("none"));
        assert!(
            body["scopes"]
                .as_array()
                .is_some_and(|scopes| scopes.contains(&json!("read"))),
            "the answer names the token's scopes: {body}"
        );

        let (status, body) = call(
            &app,
            "GET",
            "/api/v1/nodus/account/role",
            &moderator_token,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["role"], json!("moderator"));
        assert!(
            body["scopes"]
                .as_array()
                .is_some_and(|scopes| scopes.contains(&json!("admin:write"))),
            "{body}"
        );

        let (status, _) = call(&app, "GET", "/api/v1/nodus/account/role", "nope", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "and nobody else may");
    })
    .await;
}
