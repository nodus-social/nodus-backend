//! An unfollow must clear what the follow put on the reader's home timeline.
//!
//! Two copies hold that page: the fanned-out `timeline_entry` rows (the SQL page) and the
//! sorted set the cached read consults before hydrating through `home_rows`, which has no
//! follow predicate. A purge that clears only one of the two is visible here as the id
//! coming back on the second read — once through hydration, once through the SQL top-up.
//!
//! Every case runs against the in-memory cache and, when `NODUS_TEST_VALKEY_URL` names a
//! reachable server, against a real Valkey.

mod support;

use std::sync::Arc;

use axum::Router;

use nodus_server_api::home::{HomeCache, HomeShards, MemoryHomeCache};
use nodus_server_api::{root_router, AppState};
use nodus_server_store::Store;

use support::{create_account, create_token, expect_ok, follow, json_of, run_home_db_test, send};

fn memory_caches() -> Vec<Arc<dyn HomeCache>> {
    vec![Arc::new(MemoryHomeCache::new())]
}

fn valkey_caches() -> Option<Vec<Arc<dyn HomeCache>>> {
    let url = std::env::var("NODUS_TEST_VALKEY_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())?;
    let cache = nodus_server_api::home::ValkeyHomeCache::open(&url)
        .unwrap_or_else(|error| panic!("NODUS_TEST_VALKEY_URL {url} is unusable: {error}"));
    Some(vec![Arc::new(cache)])
}

fn skip(case: &str) {
    eprintln!("skipping the valkey half of {case}: NODUS_TEST_VALKEY_URL is unset");
}

fn app(state: &AppState, home: &Arc<HomeShards>) -> Router {
    root_router(state.clone().with_home(Some(home.clone())))
}

async fn home_ids(app: &Router, token: &str) -> Vec<String> {
    let (status, body) = send(app, token, "GET", "/api/v1/timelines/home", None).await;
    let body = expect_ok(status, &body, "/api/v1/timelines/home");
    let page = json_of(&body);
    page.as_array()
        .expect("timeline is an array")
        .iter()
        .map(|item| item["id"].as_str().expect("status has an id").to_owned())
        .collect()
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

#[tokio::test]
async fn unfollow_clears_the_unfollowed_authors_posts() {
    run_home_db_test(memory_caches(), |store, state, home| async move {
        unfollow_clears_the_authors_posts_with(&store, &state, &home).await;
    })
    .await;
    match valkey_caches() {
        Some(caches) => {
            run_home_db_test(caches, |store, state, home| async move {
                unfollow_clears_the_authors_posts_with(&store, &state, &home).await;
            })
            .await;
        }
        None => skip("unfollow_clears_the_unfollowed_authors_posts"),
    }
}

/// Two posts by the unfollowed author and one by an author the reader keeps following:
/// the unfollow must remove exactly the first two, from the rows and from the set alike,
/// and both reads afterwards must agree.
async fn unfollow_clears_the_authors_posts_with(
    store: &Store,
    state: &AppState,
    home: &Arc<HomeShards>,
) {
    let pool = store.pool();
    let author = create_account(pool, "unfollowed").await;
    let other = create_account(pool, "kept").await;
    let reader = create_account(pool, "reader").await;
    follow(pool, &reader, &author).await;
    follow(pool, &reader, &other).await;
    let author_token = create_token(pool, &author, &["read", "write:statuses"]).await;
    let other_token = create_token(pool, &other, &["read", "write:statuses"]).await;
    let reader_token = create_token(pool, &reader, &["read", "write:follows"]).await;
    let app = app(state, home);

    let gone = vec![
        post(&app, &author_token, "one").await,
        post(&app, &author_token, "two").await,
    ];
    let kept = post(&app, &other_token, "keep").await;

    let before = home_ids(&app, &reader_token).await;
    assert!(
        gone.iter().all(|id| before.contains(id)) && before.contains(&kept),
        "the follow fanned out nothing to purge: {before:?}"
    );

    let (status, body) = send(
        &app,
        &reader_token,
        "POST",
        &format!("/api/v1/accounts/{author}/unfollow"),
        None,
    )
    .await;
    expect_ok(status, &body, "POST /api/v1/accounts/{id}/unfollow");

    let cached = home
        .shard(&reader)
        .range(&reader, home.cap())
        .await
        .expect("read the reader's timeline");
    assert!(
        cached.iter().all(|id| !gone.contains(id)),
        "the sorted set still names an unfollowed author's posts: {cached:?}"
    );
    assert!(
        cached.iter().any(|id| id == &kept),
        "the purge removed a post of an author the reader still follows: {cached:?}"
    );

    let entries: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM timeline_entry e JOIN status s ON s.id = e.status_id \
          WHERE e.account_id = $1 AND s.account_id = $2",
    )
    .bind(&reader)
    .bind(&author)
    .fetch_one(pool)
    .await
    .expect("count the reader's entries for the unfollowed author");
    assert_eq!(
        entries, 0,
        "the fanned-out rows outlived the follow: the sql page would serve them"
    );

    // Twice: the first read can only resurrect the post from the hydrated set, the second
    // also sees anything the sql top-up re-admitted.
    for attempt in ["first", "second"] {
        let page = home_ids(&app, &reader_token).await;
        assert!(
            page.iter().all(|id| !gone.contains(id)),
            "the {attempt} read resurrected an unfollowed author's posts: {page:?}"
        );
        assert_eq!(
            page,
            vec![kept.clone()],
            "the {attempt} read must still carry the post of an author the reader follows"
        );
    }
}
