use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
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

async fn run_isolated_db_test<F, Fut>(body: F)
where
    F: FnOnce(Store, AppState) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some((admin, store, schema)) = connect_isolated_store().await else {
        return;
    };

    let state = AppState::new(store.clone(), instance_config());
    let outcome = tokio::spawn(async move { body(store, state).await }).await;

    let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
        .execute(admin.pool())
        .await;

    if let Err(err) = outcome {
        std::panic::resume_unwind(err.into_panic());
    }
}

async fn create_admin_token(pool: &PgPool) -> String {
    let suffix = Id::new().to_string();
    let username = format!("pgtest_admin_{suffix}");
    let account = accounts::insert(
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
    accounts::set_admin(pool, &account.id, true)
        .await
        .expect("promote admin");

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
        &["admin:read".to_owned(), "admin:write".to_owned()],
    )
    .await
    .expect("register app");

    let token = format!("pgtest-token-{}", Id::new());
    let token_hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    sqlx::query(
        "INSERT INTO oauth_token (id, app_id, account_id, token_hash, scopes) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Id::new().to_string())
    .bind(&app_id)
    .bind(&account.id)
    .bind(&token_hash)
    .bind(&["admin:read".to_owned(), "admin:write".to_owned()][..])
    .execute(pool)
    .await
    .expect("insert oauth token");

    token
}

async fn send_form(
    state: &AppState,
    method: &str,
    uri: &str,
    bearer: &str,
    fields: &[(&str, &str)],
) -> (StatusCode, Value) {
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields.iter().copied())
        .finish();
    let response = root_router(state.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(encoded))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let json = serde_json::from_slice(&bytes).expect("json body");
    (status, json)
}

async fn send_get(state: &AppState, uri: &str) -> (StatusCode, Value) {
    let response = root_router(state.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let json = serde_json::from_slice(&bytes).expect("json body");
    (status, json)
}

#[tokio::test]
async fn announcements_sanitize_html_on_create_and_update() {
    run_isolated_db_test(|store, state| async move {
        let token = create_admin_token(store.pool()).await;

        let xss_payload = "<p>Maintenance tonight</p><script>alert(1)</script>\
            <img src=\"x\" onerror=\"alert(2)\">\
            <a href=\"javascript:alert(3)\">bad</a>\
            <a href=\"https://example.org\" onclick=\"evil()\">good</a>";

        let (status, created) = send_form(
            &state,
            "POST",
            "/api/v1/admin/announcements",
            &token,
            &[("content", xss_payload), ("published", "true")],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let id = created["id"].as_str().expect("id").to_owned();
        let content = created["content"].as_str().expect("content");
        assert!(!content.contains("<script"), "script leaked: {content}");
        assert!(
            !content.contains("alert(1)"),
            "script text leaked: {content}"
        );
        assert!(!content.contains("<img"), "img leaked: {content}");
        assert!(!content.contains("onerror"), "onerror leaked: {content}");
        assert!(!content.contains("onclick"), "onclick leaked: {content}");
        assert!(
            !content.contains("javascript:"),
            "javascript href leaked: {content}"
        );
        assert!(
            content.contains("<p>Maintenance tonight</p>"),
            "content: {content}"
        );
        assert!(
            content.contains("https://example.org"),
            "safe link lost: {content}"
        );

        let (status, list) = send_get(&state, "/api/v1/announcements").await;
        assert_eq!(status, StatusCode::OK);
        let public_content = list[0]["content"].as_str().expect("public content");
        assert!(!public_content.contains("<script"));
        assert!(!public_content.contains("onerror"));

        let update_payload = "<strong>Updated</strong><svg onload=alert(4)>notice</svg>";
        let (status, updated) = send_form(
            &state,
            "PUT",
            &format!("/api/v1/admin/announcements/{id}"),
            &token,
            &[("content", update_payload), ("published", "true")],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let updated_content = updated["content"].as_str().expect("updated content");
        assert!(
            !updated_content.contains("<svg"),
            "svg leaked: {updated_content}"
        );
        assert!(
            !updated_content.contains("onload"),
            "onload leaked: {updated_content}"
        );
        assert!(
            updated_content.contains("<strong>Updated</strong>"),
            "updated content: {updated_content}"
        );
        assert!(
            updated_content.contains("notice"),
            "unwrapped text lost: {updated_content}"
        );
    })
    .await;
}
