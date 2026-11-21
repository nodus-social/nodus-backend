//! `statuses_count` on a remote account.
//!
//! The profile's Posts tab and the counter beside it answer the same question, so they must
//! be derived from the same set: the live statuses this instance holds for that author.
//! Before this test existed, a delivered post appeared in
//! `/api/v1/accounts/{id}/statuses` while the account said `statuses_count: 0`.
//!
//! The counter is a stored column, exactly as it is for a local author, and the remote
//! insert/retract paths maintain it the way `statuses::create` and `statuses::delete_owned`
//! do: one `UPDATE account` in the transaction that writes the row. Counting per request
//! instead would read the whole status table for every profile view, and the local column
//! would still exist, so the two readers would disagree.

mod support;

use chrono::Utc;
use sqlx::PgPool;
use support::{json_of, run_db_test, send_anon};

use nodus_server_store::accounts::{self, RemoteAccount};
use nodus_server_store::pauses::{self, NewDomainPause};
use nodus_server_store::statuses::{self, NewRemoteStatus};

async fn seed_remote(pool: &PgPool, domain: &str, key: &str) -> String {
    let uri = format!("https://{domain}/{key}");
    accounts::upsert_remote(
        pool,
        &RemoteAccount {
            uri: &uri,
            username: key,
            domain,
            display_name: key,
            note: "",
            avatar_url: None,
            header_url: None,
            inbox_url: Some(&format!("{uri}/inbox")),
            shared_inbox_url: None,
            public_key_pem: None,
            locked: false,
            bot: false,
        },
    )
    .await
    .expect("seed remote actor")
    .id
}

async fn deliver(pool: &PgPool, account_id: &str, uri: &str, text: &str) {
    statuses::upsert_remote(
        pool,
        &NewRemoteStatus {
            id: uri,
            account_id,
            uri,
            content: text,
            content_html: &format!("<p>{text}</p>"),
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
}

async fn count(pool: &PgPool, account_id: &str) -> i64 {
    nodus_server_store::Store::from_pool(pool.clone())
        .account(account_id)
        .await
        .expect("read account")
        .expect("account exists")
        .statuses_count
}

async fn listed(app: &axum::Router, account_id: &str) -> Vec<String> {
    let (status, body) = send_anon(
        app,
        "GET",
        &format!("/api/v1/accounts/{account_id}/statuses"),
    )
    .await;
    let items = json_of(&body);
    items.as_array().map_or_else(
        || panic!("statuses list was not an array ({status}): {body}"),
        |rows| {
            rows.iter()
                .filter_map(|row| row.get("id").and_then(|id| id.as_str()).map(str::to_owned))
                .collect()
        },
    )
}

#[tokio::test]
async fn a_delivered_status_increments_the_authors_count() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let author = seed_remote(pool, "remote.test", "alice").await;
        deliver(pool, &author, "https://remote.test/alice/1", "first").await;

        assert_eq!(count(pool, &author).await, 1);
        let (status, body) = send_anon(&app, "GET", &format!("/api/v1/accounts/{author}")).await;
        assert_eq!(status.as_u16(), 200, "account read: {body}");
        assert_eq!(json_of(&body)["statuses_count"], 1);
        assert_eq!(listed(&app, &author).await.len(), 1);
    })
    .await;
}

#[tokio::test]
async fn a_second_delivery_from_the_same_author_increments_again() {
    run_db_test(|store, _app| async move {
        let pool = store.pool();
        let author = seed_remote(pool, "remote.test", "alice").await;
        deliver(pool, &author, "https://remote.test/alice/1", "first").await;
        deliver(pool, &author, "https://remote.test/alice/2", "second").await;

        assert_eq!(count(pool, &author).await, 2);
    })
    .await;
}

#[tokio::test]
async fn a_repeated_delivery_of_one_status_does_not_increment_twice() {
    run_db_test(|store, _app| async move {
        let pool = store.pool();
        let author = seed_remote(pool, "remote.test", "alice").await;
        deliver(pool, &author, "https://remote.test/alice/1", "first").await;
        deliver(pool, &author, "https://remote.test/alice/1", "edited").await;

        assert_eq!(count(pool, &author).await, 1);
    })
    .await;
}

#[tokio::test]
async fn a_delete_decrements_the_count() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let author = seed_remote(pool, "remote.test", "alice").await;
        deliver(pool, &author, "https://remote.test/alice/1", "first").await;
        deliver(pool, &author, "https://remote.test/alice/2", "second").await;

        let removed = statuses::delete_remote(pool, "https://remote.test/alice/1", &author)
            .await
            .expect("delete remote status");
        assert!(removed, "the tombstoned status was live");

        assert_eq!(count(pool, &author).await, 1);
        assert_eq!(listed(&app, &author).await.len(), 1);
        // A repeated Delete is idempotent and must not count down twice.
        let removed = statuses::delete_remote(pool, "https://remote.test/alice/1", &author)
            .await
            .expect("repeat delete");
        assert!(!removed, "the tombstone was already there");
        assert_eq!(count(pool, &author).await, 1);
    })
    .await;
}

#[tokio::test]
async fn deleting_the_actor_zeroes_the_count() {
    run_db_test(|store, _app| async move {
        let pool = store.pool();
        let author = seed_remote(pool, "remote.test", "alice").await;
        deliver(pool, &author, "https://remote.test/alice/1", "first").await;
        deliver(pool, &author, "https://remote.test/alice/2", "second").await;

        let removed = statuses::delete_remote_actor(pool, &author)
            .await
            .expect("delete the actor's statuses");
        assert_eq!(removed, 2);

        assert_eq!(count(pool, &author).await, 0);
    })
    .await;
}

/// A paused domain is stored hidden: `account_page` filters it, `by_id` does not. The
/// counter follows the local path, which also counts what the list filters (a local
/// followers-only post counts but the outbox hides it). So the number is not silently
/// rewritten by a moderation action that can be lifted again — the row is still ours.
#[tokio::test]
async fn a_paused_domain_post_is_counted_and_hidden_from_the_list() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let author = seed_remote(pool, "paused.test", "alice").await;
        pauses::upsert(
            pool,
            &NewDomainPause {
                domain: "paused.test",
                reason: "test",
                expires_at: None,
                created_by: None,
            },
        )
        .await
        .expect("pause the domain");
        deliver(pool, &author, "https://paused.test/alice/1", "hidden").await;

        assert_eq!(count(pool, &author).await, 1);
        assert!(listed(&app, &author).await.is_empty(), "a pause hides rows");
    })
    .await;
}
