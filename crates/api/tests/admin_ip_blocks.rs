//! IP blocks from the console: the shape Mastodon clients read, and the scope they need.

use axum::http::StatusCode;
use serde_json::json;

use nodus_server_store::accounts;

mod support;

use support::{create_account, create_token, json_of, run_db_test, send};

async fn staff(pool: &sqlx::PgPool, label: &str, scopes: &[&str]) -> String {
    let id = create_account(pool, label).await;
    accounts::set_staff_role(pool, &id, "admin")
        .await
        .expect("grant role");
    create_token(pool, &id, scopes).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_block_is_created_listed_edited_and_deleted() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let token = staff(pool, "ip-admin", &["admin:read", "admin:write"]).await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/admin/ip_blocks",
            Some(json!({
                "ip": "203.0.113.7",
                "severity": "no_access",
                "comment": "scraper",
                "expires_in": "3600",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create refused: {body}");
        let created = json_of(&body);
        assert_eq!(created["ip"], json!("203.0.113.0/24"));
        assert_eq!(created["severity"], json!("no_access"));
        assert_eq!(created["comment"], json!("scraper"));
        assert!(created["expires_at"].is_string(), "body: {body}");
        let id = created["id"].as_str().expect("id").to_owned();

        let (status, body) = send(&app, &token, "GET", "/api/v1/admin/ip_blocks", None).await;
        assert_eq!(status, StatusCode::OK, "list refused: {body}");
        assert_eq!(json_of(&body)[0]["id"], json!(id));

        let (status, body) = send(
            &app,
            &token,
            "PUT",
            &format!("/api/v1/admin/ip_blocks/{id}"),
            Some(json!({"severity": "sign_up_block", "comment": "spam signups"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "update refused: {body}");
        let updated = json_of(&body);
        assert_eq!(updated["severity"], json!("sign_up_block"));
        assert!(updated["expires_at"].is_null(), "body: {body}");

        let (status, body) = send(
            &app,
            &token,
            "DELETE",
            &format!("/api/v1/admin/ip_blocks/{id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "delete refused: {body}");
        let (status, body) = send(&app, &token, "GET", "/api/v1/admin/ip_blocks", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json_of(&body), json!([]));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_severity_and_a_plain_user_are_refused() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let token = staff(pool, "ip-admin", &["admin:read", "admin:write"]).await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/admin/ip_blocks",
            Some(json!({"ip": "198.51.100.1", "severity": "ban_forever"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
        assert!(body.contains("severity"), "body: {body}");

        let plain = create_account(pool, "ip-plain").await;
        let plain_token = create_token(pool, &plain, &["read", "write"]).await;
        let (status, body) = send(
            &app,
            &plain_token,
            "GET",
            "/api/v1/admin/ip_blocks",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    })
    .await;
}
