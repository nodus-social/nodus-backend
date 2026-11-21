//! Two API processes over one Valkey.
//!
//! The home timeline is a sorted set per account. Every replica writes the same keys, so a
//! post fanned out by one replica is readable by the other without a database query, and a
//! removal made by one replica has to reach the other. The cached set alone already makes
//! that removal visible (they share the key); the invalidation channel is what covers the
//! window where a replica's own copy is the only one it trusts. Both halves are proved
//! here: [`a_delete_on_one_replica_clears_the_other_replicas_cached_range`] is the
//! end-to-end replica story, and
//! [`a_published_removal_clears_a_replica_that_did_not_write_it`] isolates the channel, so
//! a broken subscriber cannot hide behind the shared sorted set.
//!
//! The Valkey half is skipped when `NODUS_TEST_VALKEY_URL` is unset, exactly like
//! `home_timeline.rs`. The down-at-boot case needs no broker: it points at a closed port.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;

use nodus_server_api::home::{
    spawn_subscriber, HomeCache, HomeShards, ValkeyHomeCache, DEFAULT_CAP,
};
use nodus_server_api::{root_router, AppState};
use nodus_server_store::invalidate::{
    InvalidationKey, InvalidationKind, InvalidationSink, ValkeyInvalidator, DEFAULT_CHANNEL,
};
use nodus_server_store::Store;

use support::{
    create_account, create_token, expect_ok, follow, instance_config, json_of, run_shared_db_test,
    send,
};

/// The server the Valkey half runs against.
///
/// The process reads `NODUS_VALKEY_URL`; tests read `NODUS_TEST_VALKEY_URL` so a developer's
/// production URL can never decide what a test writes into.
fn valkey_url() -> Option<String> {
    std::env::var("NODUS_TEST_VALKEY_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
}

fn skip(case: &str) {
    eprintln!("skipping the valkey half of {case}: NODUS_TEST_VALKEY_URL is unset");
}

/// One API process: its own shards, its own subscriber, its own publisher, over `url`.
///
/// Two calls are two replicas in the sense that matters: neither shares an `Arc` with the
/// other, and only the channel connects them.
fn replica(store: &Store, url: &str, channel: &str) -> (AppState, Arc<HomeShards>) {
    let cache: Arc<dyn HomeCache> = Arc::new(
        ValkeyHomeCache::open(url)
            .unwrap_or_else(|error| panic!("NODUS_TEST_VALKEY_URL {url} is unusable: {error}")),
    );
    let home = Arc::new(HomeShards::new(vec![cache], DEFAULT_CAP).with_subscription(url, channel));
    spawn_subscriber(&home);
    let sink: Arc<dyn InvalidationSink> = Arc::new(ValkeyInvalidator::spawn(url, channel));
    let state =
        AppState::with_federation_and_sink(store.clone(), instance_config(), None, Some(sink))
            .with_home(Some(home.clone()));
    (state, home)
}

async fn post(app: &Router, token: &str, text: &str) -> String {
    let (status, body) = send(
        app,
        token,
        "POST",
        "/api/v1/statuses",
        Some(serde_json::json!({ "status": text, "visibility": "public" })),
    )
    .await;
    let body = expect_ok(status, &body, "POST /api/v1/statuses");
    json_of(&body)["id"].as_str().expect("id").to_owned()
}

async fn delete(app: &Router, token: &str, id: &str) {
    let (status, body) = send(
        app,
        token,
        "DELETE",
        &format!("/api/v1/statuses/{id}"),
        None,
    )
    .await;
    expect_ok(status, &body, "DELETE /api/v1/statuses/{id}");
}

async fn home_ids(app: &Router, token: &str) -> Vec<String> {
    let (status, body) = send(app, token, "GET", "/api/v1/timelines/home", None).await;
    let body = expect_ok(status, &body, "/api/v1/timelines/home");
    json_of(&body)
        .as_array()
        .expect("timeline is an array")
        .iter()
        .map(|item| item["id"].as_str().expect("status has an id").to_owned())
        .collect()
}

/// What the replica holds, read from its own shard and nothing else.
async fn cached_ids(home: &HomeShards, account_id: &str) -> Vec<String> {
    home.shard(account_id)
        .range(account_id, home.cap())
        .await
        .expect("read the replica's cached range")
}

#[tokio::test]
async fn a_delete_on_one_replica_clears_the_other_replicas_cached_range() {
    let Some(url) = valkey_url() else {
        skip("a_delete_on_one_replica_clears_the_other_replicas_cached_range");
        return;
    };
    run_shared_db_test(move |store| {
        let url = url.clone();
        async move {
            let (state_a, _home_a) = replica(&store, &url, DEFAULT_CHANNEL);
            let (state_b, home_b) = replica(&store, &url, DEFAULT_CHANNEL);
            let app_a = root_router(state_a);
            let app_b = root_router(state_b);

            let pool = store.pool();
            let author = create_account(pool, "author").await;
            let reader = create_account(pool, "reader").await;
            follow(pool, &reader, &author).await;
            let author_token = create_token(pool, &author, &["read", "write:statuses"]).await;
            let reader_token = create_token(pool, &reader, &["read"]).await;

            let keep = post(&app_a, &author_token, "keep").await;
            let gone = post(&app_a, &author_token, "gone").await;

            // Replica B's cache is warm without B having answered a request: the two
            // replicas write the same keys on the same server.
            assert_eq!(
                cached_ids(&home_b, &reader).await,
                [gone.clone(), keep.clone()],
                "replica B reads what replica A fanned out"
            );

            // A answers the delete. From here on the test asks B — its cache, then its
            // router — and B never had the delete request.
            delete(&app_a, &author_token, &gone).await;

            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let ids = cached_ids(&home_b, &reader).await;
                assert!(
                    !ids.contains(&gone),
                    "replica B still holds the deleted id after 10s: {ids:?}"
                );
                if !ids.is_empty() {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "replica B's range never came back"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            assert_eq!(
                cached_ids(&home_b, &reader).await,
                std::slice::from_ref(&keep),
                "replica B's cached range lost exactly the deleted id"
            );
            // The page B serves now hydrates from the database, which is playable: the
            // deletion is a real row update, and B never saw the write.
            assert_eq!(home_ids(&app_b, &reader_token).await, [keep]);
        }
    })
    .await;
}

#[tokio::test]
async fn a_published_removal_clears_a_replica_that_did_not_write_it() {
    let Some(url) = valkey_url() else {
        skip("a_published_removal_clears_a_replica_that_did_not_write_it");
        return;
    };
    let cache: Arc<dyn HomeCache> = Arc::new(
        ValkeyHomeCache::open(&url)
            .unwrap_or_else(|error| panic!("NODUS_TEST_VALKEY_URL {url} is unusable: {error}")),
    );
    let home = Arc::new(
        HomeShards::new(vec![cache], DEFAULT_CAP).with_subscription(&url, DEFAULT_CHANNEL),
    );
    spawn_subscriber(&home);

    // A warm entry that no writer in this process produced: only the channel can remove it.
    let account = "remote_reader";
    let status = "remote_status";
    home.push(status, 1, &[account.to_owned()]).await;
    assert_eq!(cached_ids(&home, account).await, [status.to_owned()]);

    // A second replica's publisher, with no cache of its own: the only thing it can do is
    // publish, so B losing the entry is caused by the channel and nothing else.
    let publisher: Arc<dyn InvalidationSink> =
        Arc::new(ValkeyInvalidator::spawn(&url, DEFAULT_CHANNEL));
    publisher.invalidate(&[InvalidationKey::new(
        account,
        InvalidationKind::Home,
        status,
    )]);

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let ids = cached_ids(&home, account).await;
        if ids.is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the subscriber never applied the published removal: {ids:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    home.remove(status, &[account.to_owned()]).await;
}

/// A cache that cannot be reached when the process boots must not fail the request.
///
/// `ValkeyHomeCache::open` only parses the URL, so "down at boot" is an open that succeeds
/// and a first command that fails. The read path falls back to the SQL page, which is the
/// same deployment as `NODUS_VALKEY_URL` unset.
#[tokio::test]
async fn a_cache_that_is_down_at_boot_still_serves_the_sql_page() {
    // Reserve and close an ephemeral port: a connection to it is refused immediately, the
    // way a stopped broker behaves, without pretending port 1 is safe to name.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a closed port");
    let closed_port = probe.local_addr().expect("port").port();
    drop(probe);

    run_shared_db_test(move |store| async move {
        let cache: Arc<dyn HomeCache> = Arc::new(
            ValkeyHomeCache::open(&format!("redis://127.0.0.1:{closed_port}"))
                .expect("a URL is valid whether or not anything answers"),
        );
        let home = Arc::new(HomeShards::new(vec![cache], DEFAULT_CAP));
        let state = AppState::new(store.clone(), instance_config()).with_home(Some(home.clone()));
        let app = root_router(state);

        let pool = store.pool();
        let author = create_account(pool, "author").await;
        let reader = create_account(pool, "reader").await;
        follow(pool, &reader, &author).await;
        let author_token = create_token(pool, &author, &["read", "write:statuses"]).await;
        let reader_token = create_token(pool, &reader, &["read"]).await;
        let first = post(&app, &author_token, "one").await;

        assert!(
            home.shard(&reader)
                .range(&reader, home.cap())
                .await
                .is_err(),
            "the cache really is unreachable; otherwise this test proves nothing about boot"
        );
        assert_eq!(
            home_ids(&app, &reader_token).await,
            [first],
            "the reader's request is answered from SQL while the cache is down"
        );
    })
    .await;
}
