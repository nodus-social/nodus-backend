//! The edit history of a post.
//!
//! Two promises are pinned here: a revision appears only when the text changed, and a
//! post the viewer cannot see is a 404 rather than an empty list — an empty history for a
//! direct message would confirm the id exists.

use axum::http::StatusCode;
use chrono::Utc;

use nodus_server_core::Id;
use nodus_server_store::statuses::{self, NewRemoteStatus};

mod support;

use support::{create_account, create_status, create_token, run_db_test, send, send_anon};

fn history_path(id: &str) -> String {
    format!("/api/v1/statuses/{id}/history")
}

#[tokio::test]
async fn history_reports_changed_edits_newest_first() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let author = create_account(pool, "history_author").await;
        let token = create_token(pool, &author, &["read:statuses"]).await;

        let uri = format!("https://remote.test/notes/{}", Id::new());
        let first = statuses::upsert_remote(
            pool,
            &NewRemoteStatus {
                id: &Id::new().to_string(),
                account_id: &author,
                uri: &uri,
                content: "first",
                content_html: "<p>first</p>",
                spoiler_text: "",
                sensitive: false,
                visibility: "public",
                in_reply_to_id: None,
                in_reply_to_account_id: None,
                created_at: Utc::now(),
            },
        )
        .await
        .expect("seed status");

        // A repeated Update with the same text is not a revision.
        statuses::upsert_remote(
            pool,
            &NewRemoteStatus {
                id: &Id::new().to_string(),
                account_id: &author,
                uri: &uri,
                content: "first",
                content_html: "<p>first</p>",
                spoiler_text: "",
                sensitive: false,
                visibility: "public",
                in_reply_to_id: None,
                in_reply_to_account_id: None,
                created_at: Utc::now(),
            },
        )
        .await
        .expect("repeat status");

        statuses::upsert_remote(
            pool,
            &NewRemoteStatus {
                id: &Id::new().to_string(),
                account_id: &author,
                uri: &uri,
                content: "second",
                content_html: "<p>second</p>",
                spoiler_text: "",
                sensitive: false,
                visibility: "public",
                in_reply_to_id: None,
                in_reply_to_account_id: None,
                created_at: Utc::now(),
            },
        )
        .await
        .expect("edit status");

        let (status, body) = send(&app, &token, "GET", &history_path(&first.id), None).await;
        assert_eq!(status, StatusCode::OK, "history: {body}");
        let entries = support::json_of(&body);
        let entries = entries.as_array().expect("history is an array");
        assert_eq!(
            entries.len(),
            1,
            "only the changed edit is recorded: {body}"
        );
        assert_eq!(entries[0]["content"], "second");
        assert_eq!(entries[0]["account"]["id"], author);
        assert!(entries[0]["created_at"].is_string());
    })
    .await;
}

#[tokio::test]
async fn history_of_an_invisible_status_is_a_404() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let author = create_account(pool, "history_private_author").await;
        let outsider = create_account(pool, "history_outsider").await;
        let token = create_token(pool, &outsider, &["read:statuses"]).await;
        let id = create_status(pool, &author, "just for me", "direct", &[], &[]).await;

        let (status, _) = send(&app, &token, "GET", &history_path(&id), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = send_anon(&app, "GET", &history_path(&id)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    })
    .await;
}
