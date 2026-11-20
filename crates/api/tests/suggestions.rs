//! `GET /api/v2/suggestions`: who the instance offers to a reader.
//!
//! The refusals are the point. A suggestion is a recommendation, so it must not name the
//! viewer, anyone either side blocked or muted, anyone already followed, or an account
//! moderation suspended, silenced, deleted or left unapproved.

use axum::http::StatusCode;
use serde_json::Value;

use nodus_server_store::social;

mod support;

use support::{create_account, create_status, create_token, json_of, run_db_test, send, send_anon};

fn ids(body: &str) -> Vec<String> {
    json_of(body)
        .as_array()
        .expect("an array of suggestions")
        .iter()
        .map(|suggestion| {
            suggestion["account"]["id"]
                .as_str()
                .expect("suggested account id")
                .to_owned()
        })
        .collect()
}

#[tokio::test]
async fn suggestions_exclude_the_viewer_the_blocked_and_the_moderated() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let viewer = create_account(pool, "suggest_viewer").await;
        let token = create_token(pool, &viewer, &["read:accounts"]).await;

        let wanted = create_account(pool, "suggest_wanted").await;
        create_status(pool, &wanted, "hello", "public", &[], &[]).await;

        let followed = create_account(pool, "suggest_followed").await;
        create_status(pool, &followed, "hello", "public", &[], &[]).await;
        support::follow(pool, &viewer, &followed).await;

        let blocked = create_account(pool, "suggest_blocked").await;
        create_status(pool, &blocked, "hello", "public", &[], &[]).await;
        social::block(pool, &viewer, &blocked).await.expect("block");

        let blocker = create_account(pool, "suggest_blocker").await;
        create_status(pool, &blocker, "hello", "public", &[], &[]).await;
        social::block(pool, &blocker, &viewer).await.expect("block");

        let muted = create_account(pool, "suggest_muted").await;
        create_status(pool, &muted, "hello", "public", &[], &[]).await;
        social::mute(pool, &viewer, &muted, false)
            .await
            .expect("mute");

        let muter = create_account(pool, "suggest_muter").await;
        create_status(pool, &muter, "hello", "public", &[], &[]).await;
        social::mute(pool, &muter, &viewer, false)
            .await
            .expect("mute");

        let suspended = create_account(pool, "suggest_suspended").await;
        create_status(pool, &suspended, "hello", "public", &[], &[]).await;
        sqlx::query("UPDATE account SET suspended_at = now() WHERE id = $1")
            .bind(&suspended)
            .execute(pool)
            .await
            .expect("suspend");

        let unapproved = create_account(pool, "suggest_unapproved").await;
        create_status(pool, &unapproved, "hello", "public", &[], &[]).await;
        sqlx::query("UPDATE account SET approved = false WHERE id = $1")
            .bind(&unapproved)
            .execute(pool)
            .await
            .expect("unapprove");

        let remote = format!("01{}", "remote_suggestion_placeholder");
        sqlx::query(
            "INSERT INTO account (id, username, domain, display_name, note, local) \
             VALUES ($1, 'suggest_remote', 'remote.test', 'remote', '', false)",
        )
        .bind(&remote)
        .execute(pool)
        .await
        .expect("remote account");

        let (status, body) = send(&app, &token, "GET", "/api/v2/suggestions", None).await;
        assert_eq!(status, StatusCode::OK, "suggestions: {body}");
        assert_eq!(ids(&body), vec![wanted.clone()], "only the eligible local account");

        let suggestion: &Value = &json_of(&body)[0];
        assert_eq!(suggestion["source"], "recent_activity");
        assert_eq!(suggestion["sources"][0], "recent_activity");

        let (status, body) = send(&app, &token, "GET", "/api/v2/suggestions?limit=1", None).await;
        assert_eq!(status, StatusCode::OK, "limit: {body}");
        assert!(ids(&body).len() <= 1);
    })
    .await;
}

#[tokio::test]
async fn suggestions_honour_the_limit_and_refuse_anonymous_callers() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let viewer = create_account(pool, "suggest_limits").await;
        let token = create_token(pool, &viewer, &["read:accounts"]).await;
        for label in ["one", "two", "three"] {
            let id = create_account(pool, label).await;
            create_status(pool, &id, "hello", "public", &[], &[]).await;
        }

        let (status, body) = send(&app, &token, "GET", "/api/v2/suggestions?limit=2", None).await;
        assert_eq!(status, StatusCode::OK, "limit: {body}");
        assert_eq!(ids(&body).len(), 2);

        let (status, _) = send_anon(&app, "GET", "/api/v2/suggestions").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    })
    .await;
}
