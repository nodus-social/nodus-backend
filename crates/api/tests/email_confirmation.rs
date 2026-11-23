//! The `NODUS_REQUIRE_EMAIL_CONFIRMATION` gate, against a real schema.
//!
//! The switch is read once at startup and off by default. These tests drive the two
//! surfaces it refuses — the first post and the first follow — and the default that must
//! keep both working exactly as they did before the switch existed.

mod support;

use axum::http::StatusCode;
use serde_json::json;
use sqlx::PgPool;

use nodus_server_api::{root_router, AppState};

use support::{create_account, create_token, expect_ok, instance_config, run_shared_db_test, send};

/// Inserts the credential row a registration would have written, with an address that
/// has not been confirmed.
async fn add_unconfirmed_credential(pool: &PgPool, account_id: &str, email: &str) {
    sqlx::query(
        "INSERT INTO account_credential (account_id, email, password_hash, confirmed_at) \
         VALUES ($1, $2, 'not-a-real-hash', NULL)",
    )
    .bind(account_id)
    .bind(email)
    .execute(pool)
    .await
    .expect("insert unconfirmed credential");
}

#[tokio::test]
async fn an_unconfirmed_account_cannot_post_or_follow_when_enforcement_is_on() {
    run_shared_db_test(|store| async move {
        let app = root_router(
            AppState::new(store.clone(), instance_config()).with_require_email_confirmation(true),
        );
        let account = create_account(store.pool(), "unconfirmed").await;
        add_unconfirmed_credential(store.pool(), &account, "unconfirmed@social.test").await;
        let token =
            create_token(store.pool(), &account, &["write:statuses", "write:follows"]).await;
        let target = create_account(store.pool(), "target").await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/statuses",
            Some(json!({ "status": "hello" })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body.to_lowercase().contains("confirm"), "{body}");

        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/accounts/{target}/follow"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body.to_lowercase().contains("confirm"), "{body}");
    })
    .await;
}

#[tokio::test]
async fn the_default_switch_leaves_posting_and_following_alone() {
    run_shared_db_test(|store| async move {
        let app = root_router(AppState::new(store.clone(), instance_config()));
        let account = create_account(store.pool(), "unconfirmed").await;
        add_unconfirmed_credential(store.pool(), &account, "unconfirmed@social.test").await;
        let token =
            create_token(store.pool(), &account, &["write:statuses", "write:follows"]).await;
        let target = create_account(store.pool(), "target").await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/statuses",
            Some(json!({ "status": "hello" })),
        )
        .await;
        expect_ok(status, &body, "POST /api/v1/statuses");

        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/accounts/{target}/follow"),
            None,
        )
        .await;
        expect_ok(status, &body, "POST /api/v1/accounts/{id}/follow");
    })
    .await;
}
