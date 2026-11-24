//! What search must get right beyond "the row exists": relevance order, the moderation
//! gate a timeline already applies, and the boost pointer that adds no text of its own.
//!
//! Skipped when `DATABASE_URL` is unset, like the rest of the contract tests.

mod support;

use axum::http::StatusCode;
use chrono::Utc;
use serde_json::Value;
use sqlx::PgPool;

use nodus_server_store::accounts::{self, NewAccount, RemoteAccount};
use nodus_server_store::statuses::{self, NewRemoteStatus};

use support::{create_account, create_status, create_token, run_db_test, send};

/// An account with a username the search term can be written against, which the generated
/// `create_account` names cannot do.
async fn named_account(pool: &PgPool, username: &str, followers: i64) -> String {
    let row = accounts::insert(
        pool,
        &NewAccount {
            username,
            display_name: username,
            note: "",
            bot: false,
            locked: false,
        },
    )
    .await
    .expect("insert account");
    sqlx::query("UPDATE account SET followers_count = $2 WHERE id = $1")
        .bind(&row.id)
        .bind(followers)
        .execute(pool)
        .await
        .expect("set followers_count");
    row.id
}

fn account_ids(body: &Value) -> Vec<String> {
    body["accounts"]
        .as_array()
        .expect("accounts")
        .iter()
        .map(|account| account["id"].as_str().expect("account id").to_owned())
        .collect()
}

fn status_ids(body: &Value) -> Vec<String> {
    body["statuses"]
        .as_array()
        .expect("statuses")
        .iter()
        .map(|status| status["id"].as_str().expect("status id").to_owned())
        .collect()
}

/// `q=ada` while an `ada` exists must answer with `ada`, even though a more-followed
/// `adam` and `megada` both match the pattern and would win a follower-count sort.
#[tokio::test]
async fn an_exact_username_outranks_more_followed_prefix_and_substring_matches() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let token = create_token(&pool, &reader, &["read"]).await;

        let exact = named_account(&pool, "ada", 3).await;
        let prefix = named_account(&pool, "adam", 9_000).await;
        let substring = named_account(&pool, "megada", 40_000).await;

        let (code, body) = send(&app, &token, "GET", "/api/v2/search?q=ada", None).await;
        assert_eq!(code, StatusCode::OK, "body: {body}");
        let ids = account_ids(&serde_json::from_str::<Value>(&body).expect("json"));
        assert_eq!(
            ids,
            vec![exact.clone(), prefix.clone(), substring.clone()],
            "an exact username, then a prefix, then a substring, before follower count: {body}"
        );
    })
    .await;
}

/// A paused domain is hidden from the public timeline by `public_page`; search must not
/// hand the same post back, or search becomes the way around a moderation decision.
#[tokio::test]
async fn a_status_from_a_paused_domain_does_not_appear() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let token = create_token(&pool, &reader, &["read"]).await;

        let paused = accounts::upsert_remote(
            &pool,
            &RemoteAccount {
                uri: "https://paused.test/users/paused",
                username: "paused",
                domain: "paused.test",
                display_name: "paused",
                note: "",
                avatar_url: None,
                header_url: None,
                inbox_url: Some("https://paused.test/users/paused/inbox"),
                shared_inbox_url: None,
                public_key_pem: None,
                locked: false,
                bot: false,
            },
        )
        .await
        .expect("upsert remote actor")
        .id;
        statuses::upsert_remote(
            &pool,
            &NewRemoteStatus {
                id: "https://paused.test/notes/one",
                account_id: &paused,
                uri: "https://paused.test/notes/one",
                content: "quarantine quokka",
                content_html: "<p>quarantine quokka</p>",
                spoiler_text: "",
                sensitive: false,
                visibility: "public",
                in_reply_to_id: None,
                in_reply_to_account_id: None,
                created_at: Utc::now(),
            },
        )
        .await
        .expect("store remote status");
        sqlx::query("INSERT INTO domain_pause (domain, reason) VALUES ('paused.test', 'test')")
            .execute(&pool)
            .await
            .expect("pause domain");

        let (code, body) = send(
            &app,
            &token,
            "GET",
            "/api/v2/search?q=quokka&type=statuses",
            None,
        )
        .await;
        assert_eq!(code, StatusCode::OK, "body: {body}");
        let found = serde_json::from_str::<Value>(&body).expect("json");
        assert!(
            status_ids(&found).is_empty(),
            "a paused domain must not be searchable: {body}"
        );
    })
    .await;
}

/// A boost carries no text, so it can never be the answer to a text query; the original
/// must keep its one slot rather than being outnumbered by pointers at it.
#[tokio::test]
async fn a_reblog_does_not_occupy_a_result_slot() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let token = create_token(&pool, &reader, &["read"]).await;

        let author = create_account(&pool, "author").await;
        let booster = create_account(&pool, "booster").await;
        let original = create_status(&pool, &author, "quokka spotting", "public", &[], &[]).await;
        let boost = statuses::reblog(&pool, &booster, &original)
            .await
            .expect("reblog")
            .expect("boostable");
        assert_ne!(boost.id, original, "the boost is a row of its own");

        let (code, body) = send(
            &app,
            &token,
            "GET",
            "/api/v2/search?q=quokka&type=statuses",
            None,
        )
        .await;
        assert_eq!(code, StatusCode::OK, "body: {body}");
        let found = serde_json::from_str::<Value>(&body).expect("json");
        assert_eq!(
            status_ids(&found),
            vec![original],
            "the boost must not be a search result: {body}"
        );
    })
    .await;
}
