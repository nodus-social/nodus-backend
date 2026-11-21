//! The home timeline's cached read path.
//!
//! Every case runs twice: once against a scripted in-memory `HomeCache`, and — when
//! `NODUS_TEST_VALKEY_URL` names a reachable server — once against a real Valkey. The
//! in-memory half is the one that must pass everywhere; the scripted cache is deliberately
//! dumb (a sorted map), so a bug in the read path cannot hide behind the real thing.
//!
//! The database stays authoritative throughout: every id in a cache row is also a row in
//! `status`, and the fallback each case asserts is `statuses::home_page` unchanged.

mod support;

use std::sync::Arc;

use axum::Router;

use nodus_server_api::home::{HomeCache, HomeShards, MemoryHomeCache};
use nodus_server_api::{root_router, AppState};
use nodus_server_core::{PageParams, PageSize};
use nodus_server_store::Store;

use support::{
    create_account, create_status, create_token, expect_ok, follow, json_of, run_home_db_test, send,
};

/// One in-memory shard per entry, all identical from the outside.
fn memory_caches(shards: usize) -> Vec<Arc<dyn HomeCache>> {
    (0..shards)
        .map(|_| Arc::new(MemoryHomeCache::new()) as Arc<dyn HomeCache>)
        .collect()
}

/// The same shard count against a real server, when one was offered.
///
/// `None` means the suite's Valkey half does not run here; the caller prints why instead
/// of failing, because the in-memory half proves the read path and a missing server is not
/// a bug in this crate.
fn valkey_caches(shards: usize) -> Option<Vec<Arc<dyn HomeCache>>> {
    let url = std::env::var("NODUS_TEST_VALKEY_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())?;
    let mut caches: Vec<Arc<dyn HomeCache>> = Vec::with_capacity(shards);
    for _ in 0..shards {
        let cache = nodus_server_api::home::ValkeyHomeCache::open(&url)
            .unwrap_or_else(|error| panic!("NODUS_TEST_VALKEY_URL {url} is unusable: {error}"));
        caches.push(Arc::new(cache));
    }
    Some(caches)
}

fn skip(case: &str) {
    eprintln!("skipping the valkey half of {case}: NODUS_TEST_VALKEY_URL is unset");
}

fn app(state: &AppState, home: &Arc<HomeShards>) -> Router {
    root_router(state.clone().with_home(Some(home.clone())))
}

/// The ids on one page, in the order the client reads them.
async fn home_ids(app: &Router, token: &str) -> Vec<String> {
    home_ids_query(app, token, "").await
}

async fn home_ids_query(app: &Router, token: &str, query: &str) -> Vec<String> {
    let (status, body) = send(
        app,
        token,
        "GET",
        &format!("/api/v1/timelines/home{query}"),
        None,
    )
    .await;
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
async fn hydration_drops_a_deleted_id() {
    run_home_db_test(memory_caches(1), |store, state, home| async move {
        hydration_drops_a_deleted_id_with(&store, &state, &home).await;
    })
    .await;
    match valkey_caches(1) {
        Some(caches) => {
            run_home_db_test(caches, |store, state, home| async move {
                hydration_drops_a_deleted_id_with(&store, &state, &home).await;
            })
            .await;
        }
        None => skip("hydration_drops_a_deleted_id"),
    }
}

/// Three posts, the middle one deleted: the deleted id leaves the sorted set at once and
/// the page the reader gets holds exactly the two survivors, with no hole in it.
async fn hydration_drops_a_deleted_id_with(
    store: &Store,
    state: &AppState,
    home: &Arc<HomeShards>,
) {
    let pool = store.pool();
    let author = create_account(pool, "author").await;
    let reader = create_account(pool, "reader").await;
    follow(pool, &reader, &author).await;
    let author_token = create_token(pool, &author, &["read", "write:statuses"]).await;
    let reader_token = create_token(pool, &reader, &["read"]).await;
    let app = app(state, home);

    let first = post(&app, &author_token, "one").await;
    let middle = post(&app, &author_token, "two").await;
    let last = post(&app, &author_token, "three").await;

    let cached = home
        .shard(&reader)
        .range(&reader, home.cap())
        .await
        .expect("read the reader's timeline");
    assert_eq!(
        cached,
        [last.clone(), middle.clone(), first.clone()],
        "every post the author published is in the reader's timeline, newest first"
    );

    let (status, body) = send(
        &app,
        &author_token,
        "DELETE",
        &format!("/api/v1/statuses/{middle}"),
        None,
    )
    .await;
    expect_ok(status, &body, "DELETE /api/v1/statuses/{id}");

    let cached = home
        .shard(&reader)
        .range(&reader, home.cap())
        .await
        .expect("read the reader's timeline");
    assert_eq!(
        cached,
        [last.clone(), first.clone()],
        "the delete removed the id from every follower's sorted set"
    );
    assert_eq!(home_ids(&app, &reader_token).await, [last, first]);
}

#[tokio::test]
async fn hydration_keeps_the_order_the_sorted_set_gave() {
    run_home_db_test(memory_caches(1), |store, state, home| async move {
        hydration_keeps_order_with(&store, &state, &home).await;
    })
    .await;
    match valkey_caches(1) {
        Some(caches) => {
            run_home_db_test(caches, |store, state, home| async move {
                hydration_keeps_order_with(&store, &state, &home).await;
            })
            .await;
        }
        None => skip("hydration_keeps_the_order_the_sorted_set_gave"),
    }
}

/// Four posts pushed with scores that disagree with both insertion order and id order: the
/// page is the sorted set's order, not the order the rows happened to come back in.
async fn hydration_keeps_order_with(store: &Store, state: &AppState, home: &Arc<HomeShards>) {
    let pool = store.pool();
    let author = create_account(pool, "author").await;
    let reader = create_account(pool, "reader").await;
    follow(pool, &reader, &author).await;
    let reader_token = create_token(pool, &reader, &["read"]).await;

    let ids: Vec<String> = {
        let mut ids = Vec::new();
        for text in ["one", "two", "three", "four"] {
            ids.push(create_status(pool, &author, text, "public", &[], &[]).await);
        }
        ids
    };
    // Deliberately not the ids' own order and not the push order: descending scores arrive
    // last, so a read that trusted insertion or id order would answer differently.
    let scores = [40_i64, 10, 30, 20];
    for (id, score) in ids.iter().zip(scores) {
        home.push(id, score, std::slice::from_ref(&reader)).await;
    }

    let expected = [
        ids[0].clone(),
        ids[2].clone(),
        ids[3].clone(),
        ids[1].clone(),
    ];
    assert_eq!(
        home.shard(&reader)
            .range(&reader, home.cap())
            .await
            .expect("read the reader's timeline"),
        expected,
        "the scripted cache holds the scores we gave it"
    );
    let app = app(state, home);
    assert_eq!(home_ids(&app, &reader_token).await, expected);
}

#[tokio::test]
async fn a_shard_move_keeps_every_visible_id_visible() {
    run_home_db_test(memory_caches(2), |store, state, home| async move {
        a_shard_move_keeps_every_id_with(&store, &state, &home).await;
    })
    .await;
    match valkey_caches(2) {
        Some(caches) => {
            run_home_db_test(caches, |store, state, home| async move {
                a_shard_move_keeps_every_id_with(&store, &state, &home).await;
            })
            .await;
        }
        None => skip("a_shard_move_keeps_every_visible_id_visible"),
    }
}

/// Growing the cluster from two shards to three moves some accounts, and their cached
/// timeline is on a shard nobody filled. Nothing disappears from the reader's page: the
/// new shard answers empty, which is a miss, and the database answers the same ids.
async fn a_shard_move_keeps_every_id_with(store: &Store, state: &AppState, home: &Arc<HomeShards>) {
    let pool = store.pool();
    let author = create_account(pool, "author").await;
    let reader = create_account(pool, "reader").await;
    follow(pool, &reader, &author).await;
    let reader_token = create_token(pool, &reader, &["read"]).await;

    let mut ids = Vec::new();
    for text in ["one", "two", "three"] {
        ids.push(create_status(pool, &author, text, "public", &[], &[]).await);
    }
    // The materialised lane the create path writes, pushed the way fan-out pushes it.
    for (score, id) in (1..).zip(&ids) {
        home.push(id, score, std::slice::from_ref(&reader)).await;
    }
    let app = app(state, home);
    assert_eq!(
        home_ids(&app, &reader_token).await,
        ids.iter().rev().cloned().collect::<Vec<_>>()
    );

    // A third shard joins: some accounts move, and the reader's timeline is now on a shard
    // that has never heard of it. Only accounts whose owner changed are affected, and only
    // until their timeline is rebuilt — the read still answers with every visible id.
    let grown = Arc::new(HomeShards::new(memory_caches(3), home.cap()));
    assert_eq!(grown.len(), 3, "three shards after the move");
    assert!(
        grown.shard_of(&reader) < grown.len(),
        "every account has one owner"
    );
    assert_eq!(
        grown
            .shard(&reader)
            .range(&reader, grown.cap())
            .await
            .expect("read the new shard"),
        Vec::<String>::new(),
        "the new owner never saw this timeline: the read is a miss, not a hit"
    );
    let app = root_router(state.clone().with_home(Some(grown.clone())));
    let page = home_ids(&app, &reader_token).await;
    assert_eq!(
        page,
        ids.iter().rev().cloned().collect::<Vec<_>>(),
        "a shard move loses cached entries, never visible posts"
    );
}

#[tokio::test]
async fn the_fallback_produces_exactly_the_sql_page() {
    let cache = Arc::new(MemoryHomeCache::new());
    let caches: Vec<Arc<dyn HomeCache>> = vec![cache.clone()];
    run_home_db_test(caches, |store, state, home| async move {
        let pool = store.pool();
        let author = create_account(pool, "author").await;
        let stranger = create_account(pool, "stranger").await;
        let reader = create_account(pool, "reader").await;
        follow(pool, &reader, &author).await;
        let reader_token = create_token(pool, &reader, &["read"]).await;

        for text in ["one", "two", "three"] {
            create_status(pool, &author, text, "public", &[], &[]).await;
        }
        // Not followed: a post that must not reach this reader from either path.
        let stranger_id = create_status(pool, &stranger, "elsewhere", "public", &[], &[]).await;

        let params = PageParams {
            max_id: None,
            since_id: None,
            min_id: None,
            limit: Some(PageSize::default_max(None).get()),
        };
        let sql: Vec<String> = nodus_server_store::statuses::home_page(pool, &reader, params)
            .await
            .expect("sql page")
            .items
            .into_iter()
            .map(|row| row.id)
            .collect();
        assert_eq!(sql.len(), 3, "the database has the reader's three posts");
        assert!(
            !sql.contains(&stranger_id),
            "an unfollowed account is not in the page"
        );

        // A miss: nothing was ever pushed.
        let app = app(&state, &home);
        assert_eq!(
            home_ids(&app, &reader_token).await,
            sql,
            "empty cache = sql page"
        );

        // An error: the very same ids are in the cache, and the cache refuses to answer.
        for (score, id) in (1..).zip(&sql) {
            home.push(id, score, std::slice::from_ref(&reader)).await;
        }
        cache.fail(true);
        assert_eq!(
            home_ids(&app, &reader_token).await,
            sql,
            "a failed read = sql page"
        );
        cache.fail(false);
    })
    .await;
}

#[tokio::test]
async fn a_short_set_is_topped_up_from_the_database() {
    run_home_db_test(memory_caches(1), |store, state, home| async move {
        a_short_set_is_topped_up_with(&store, &state, &home).await;
    })
    .await;
    match valkey_caches(1) {
        Some(caches) => {
            run_home_db_test(caches, |store, state, home| async move {
                a_short_set_is_topped_up_with(&store, &state, &home).await;
            })
            .await;
        }
        None => skip("a_short_set_is_topped_up_from_the_database"),
    }
}

/// Six entries in `timeline_entry`, one id in the set: the set narrows the page, it does
/// not define it, so the five rows it cannot name come from the database.
async fn a_short_set_is_topped_up_with(store: &Store, state: &AppState, home: &Arc<HomeShards>) {
    let pool = store.pool();
    let author = create_account(pool, "author").await;
    let reader = create_account(pool, "reader").await;
    follow(pool, &reader, &author).await;
    let reader_token = create_token(pool, &reader, &["read"]).await;

    let mut ids = Vec::new();
    for index in 0..6 {
        ids.push(create_status(pool, &author, &format!("post {index}"), "public", &[], &[]).await);
    }
    // The set was created after the history existed: only the newest entry was fanned out.
    let newest = ids.last().expect("six ids").clone();
    home.push(&newest, 6, std::slice::from_ref(&reader)).await;

    let app = app(state, home);
    let page = home_ids(&app, &reader_token).await;
    assert_eq!(
        page,
        ids.iter().rev().cloned().collect::<Vec<_>>(),
        "a one-id set must not hide the five older entries"
    );
}

#[tokio::test]
async fn cursors_cross_the_set_database_boundary_without_gaps() {
    run_home_db_test(memory_caches(1), |store, state, home| async move {
        cursors_cross_the_boundary_with(&store, &state, &home).await;
    })
    .await;
    match valkey_caches(1) {
        Some(caches) => {
            run_home_db_test(caches, |store, state, home| async move {
                cursors_cross_the_boundary_with(&store, &state, &home).await;
            })
            .await;
        }
        None => skip("cursors_cross_the_set_database_boundary_without_gaps"),
    }
}

/// The same short set, paged two at a time: the first page ends inside the top-up, the
/// next ones are database-only. No id may repeat or vanish across that seam.
async fn cursors_cross_the_boundary_with(store: &Store, state: &AppState, home: &Arc<HomeShards>) {
    let pool = store.pool();
    let author = create_account(pool, "author").await;
    let reader = create_account(pool, "reader").await;
    follow(pool, &reader, &author).await;
    let reader_token = create_token(pool, &reader, &["read"]).await;

    let mut ids = Vec::new();
    for index in 0..6 {
        ids.push(create_status(pool, &author, &format!("post {index}"), "public", &[], &[]).await);
    }
    home.push(
        ids.last().expect("six ids"),
        6,
        std::slice::from_ref(&reader),
    )
    .await;

    let app = app(state, home);
    let mut seen = Vec::new();
    let mut query = "?limit=2".to_owned();
    for _ in 0..3 {
        let page = home_ids_query(&app, &reader_token, &query).await;
        assert_eq!(page.len(), 2, "a two-wide page mid-timeline is never short");
        let last = page.last().expect("two ids").clone();
        seen.extend(page);
        query = format!("?limit=2&max_id={last}");
    }
    let expected: Vec<String> = ids.iter().rev().cloned().collect();
    assert_eq!(
        seen, expected,
        "two-wide pages must cover the timeline exactly"
    );
    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        seen.len(),
        "a row appeared twice across the seam"
    );
    assert!(
        home_ids_query(&app, &reader_token, &query).await.is_empty(),
        "the last page must hand out no cursor to an empty page"
    );
}

#[tokio::test]
async fn the_empty_set_and_big_account_still_take_the_sql_page() {
    run_home_db_test(memory_caches(1), |store, state, home| async move {
        the_empty_set_and_big_account_take_sql_with(&store, &state, &home).await;
    })
    .await;
    match valkey_caches(1) {
        Some(caches) => {
            run_home_db_test(caches, |store, state, home| async move {
                the_empty_set_and_big_account_take_sql_with(&store, &state, &home).await;
            })
            .await;
        }
        None => skip("the_empty_set_and_big_account_still_take_the_sql_page"),
    }
}

/// Both cases the cache was already forbidden to answer: an empty set is a miss, and a
/// reader who follows a big account needs the read-time merge. Neither may change.
async fn the_empty_set_and_big_account_take_sql_with(
    store: &Store,
    state: &AppState,
    home: &Arc<HomeShards>,
) {
    let pool = store.pool();
    let sql_page = |account_id: String| async move {
        let params = PageParams {
            max_id: None,
            since_id: None,
            min_id: None,
            limit: Some(PageSize::default_max(None).get()),
        };
        nodus_server_store::statuses::home_page(pool, &account_id, params)
            .await
            .expect("sql page")
            .items
            .into_iter()
            .map(|row| row.id)
            .collect::<Vec<_>>()
    };

    let author = create_account(pool, "author").await;
    let reader = create_account(pool, "reader").await;
    follow(pool, &reader, &author).await;
    let reader_token = create_token(pool, &reader, &["read"]).await;
    for index in 0..3 {
        create_status(pool, &author, &format!("post {index}"), "public", &[], &[]).await;
    }
    let sql = sql_page(reader.clone()).await;
    let app = app(state, home);
    assert_eq!(
        home_ids(&app, &reader_token).await,
        sql,
        "an empty set is a miss"
    );

    let big = create_account(pool, "bigauthor").await;
    let big_reader = create_account(pool, "bigreader").await;
    follow(pool, &big_reader, &big).await;
    sqlx::query("UPDATE account SET followers_count = $2 WHERE id = $1")
        .bind(&big)
        .bind(nodus_server_core::limits::BIG_ACCOUNT_THRESHOLD)
        .execute(pool)
        .await
        .expect("mark the author big");
    let big_token = create_token(pool, &big_reader, &["read"]).await;
    let mut big_ids = Vec::new();
    for index in 0..2 {
        big_ids.push(create_status(pool, &big, &format!("big {index}"), "public", &[], &[]).await);
    }
    // A non-empty set must not change the answer: a big account is merged at read time.
    home.push(&big_ids[0], 1, std::slice::from_ref(&big_reader))
        .await;
    let sql = sql_page(big_reader.clone()).await;
    assert_eq!(sql.len(), 2, "the big-account lane holds both posts");
    assert_eq!(
        home_ids(&app, &big_token).await,
        sql,
        "a reader who follows a big account still takes the sql page"
    );
}
