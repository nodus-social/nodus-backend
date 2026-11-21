//! How much the fan-out costs, in milliseconds, on one account with 1000 followers.
//!
//! Issue #43 asks for numbers rather than adjectives. This binary seeds a follower set,
//! then times the two operations an operator cares about — publishing a status (the
//! database fan-out, with and without the cache push) and a follower reading their home
//! page (the sorted set, compared with the SQL fallback) — and prints p50/p95.
//!
//! Gated on `NODUS_BENCH=1` so `cargo test` stays fast, and on `NODUS_TEST_VALKEY_URL`
//! because the "on" half needs a broker. `DATABASE_URL` is required by the schema harness;
//! without it the run is skipped like every other contract test.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use sqlx::PgPool;

use nodus_server_api::home::{HomeCache, HomeShards, ValkeyHomeCache, DEFAULT_CAP};
use nodus_server_api::{root_router, AppState};

use support::{
    create_account, create_token, expect_ok, instance_config, json_of, run_shared_db_test, send,
};

/// The follower count issue #43 names.
const FOLLOWERS: i64 = 1000;

/// Timed iterations per half. Enough for a p95 to be a measured value and not the max.
const RUNS: usize = 30;

/// Iterations for the push measured on its own.
const PUSH_RUNS: usize = 50;

fn percentile(samples: &mut [Duration], percent: usize) -> Duration {
    samples.sort_unstable();
    samples[(samples.len() - 1) * percent / 100]
}

fn print_table(half: &str, create: &mut [Duration], read: &mut [Duration]) {
    let create_p50 = percentile(create, 50);
    let create_p95 = percentile(create, 95);
    let read_p50 = percentile(read, 50);
    let read_p95 = percentile(read, 95);
    println!(
        "{half:<16} POST /api/v1/statuses  p50 {:>7.2} ms  p95 {:>7.2} ms\n\
         {:<16} GET  /api/v1/timelines/home  p50 {:>7.2} ms  p95 {:>7.2} ms",
        millis(create_p50),
        millis(create_p95),
        "",
        millis(read_p50),
        millis(read_p95),
    );
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// One author with [`FOLLOWERS`] accepted followers, so the fan-out crosses a page boundary.
///
/// Fixed-width ids, the bulk shape `store/tests/home_fanout.rs` uses one row past a
/// 500-follower page.
async fn seed_followers(pool: &PgPool) -> String {
    let author = create_account(pool, "bench_author").await;
    sqlx::query(
        "INSERT INTO account (id, username, display_name, note, local) \
         SELECT 'bench' || lpad(i::text, 4, '0'), 'bench' || i::text, '', '', true \
           FROM generate_series(1, $1) AS i",
    )
    .bind(FOLLOWERS)
    .execute(pool)
    .await
    .expect("seed followers");
    sqlx::query(
        "INSERT INTO follow (id, account_id, target_account_id, state, reblogs, notify) \
         SELECT 'benchfollow' || lpad(i::text, 4, '0'), 'bench' || lpad(i::text, 4, '0'), $1, \
                'accepted', true, false \
           FROM generate_series(1, $2) AS i",
    )
    .bind(&author)
    .bind(FOLLOWERS)
    .execute(pool)
    .await
    .expect("seed follows");
    sqlx::query("UPDATE account SET followers_count = $2 WHERE id = $1")
        .bind(&author)
        .bind(FOLLOWERS)
        .execute(pool)
        .await
        .expect("set followers_count");
    author
}

/// One create and the read that should include it, timed into `create` and `read`.
async fn timed_round(
    app: &Router,
    author_token: &str,
    reader_token: &str,
    label: &str,
    run: usize,
    create: &mut Vec<Duration>,
    read: &mut Vec<Duration>,
) {
    let started = Instant::now();
    let id = post(app, author_token, &format!("{label} {run}")).await;
    create.push(started.elapsed());
    let started = Instant::now();
    let ids = home_ids(app, reader_token).await;
    read.push(started.elapsed());
    assert!(ids.contains(&id), "the {label} page carries the new post");
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

#[tokio::test]
async fn fanout_and_cached_read_latency_on_a_thousand_followers() {
    if std::env::var("NODUS_BENCH").ok().as_deref() != Some("1") {
        eprintln!("skipping the latencies: NODUS_BENCH is unset");
        return;
    }
    let Some(url) = std::env::var("NODUS_TEST_VALKEY_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
    else {
        eprintln!(
            "skipping the latencies: NODUS_TEST_VALKEY_URL is unset, and the fan-out half needs a broker"
        );
        return;
    };

    run_shared_db_test(move |store| async move {
        let pool = store.pool();
        let author = seed_followers(pool).await;

        let reader = "bench0001";
        let author_token = create_token(pool, &author, &["read", "write:statuses"]).await;
        let reader_token = create_token(pool, reader, &["read"]).await;

        let cache: Arc<dyn HomeCache> =
            Arc::new(ValkeyHomeCache::open(&url).unwrap_or_else(|error| {
                panic!("NODUS_TEST_VALKEY_URL {url} is unusable: {error}")
            }));
        let home = Arc::new(HomeShards::new(vec![cache], DEFAULT_CAP));
        let cached_state =
            AppState::new(store.clone(), instance_config()).with_home(Some(home.clone()));
        let sql_state = AppState::new(store.clone(), instance_config());
        let cached_app = root_router(cached_state);
        let sql_app = root_router(sql_state);

        // One untimed post and read per half: page allocation and the first connection
        // belong to warm-up, not to the numbers.
        let warm = post(&cached_app, &author_token, "warm-up").await;
        assert!(home_ids(&cached_app, &reader_token).await.contains(&warm));
        let warm = post(&sql_app, &author_token, "warm-up sql").await;
        assert!(home_ids(&sql_app, &reader_token).await.contains(&warm));

        println!(
            "fan-out on / off, {FOLLOWERS} followers, {RUNS} timed runs each, reader bench0001:"
        );

        let mut cached_create = Vec::with_capacity(RUNS);
        let mut cached_read = Vec::with_capacity(RUNS);
        let mut sql_create = Vec::with_capacity(RUNS);
        let mut sql_read = Vec::with_capacity(RUNS);
        for run in 0..RUNS {
            // Alternate which half goes first: a compile or a checkpoint on the host then
            // lands on both halves instead of only the one that always ran second.
            let order = if run % 2 == 0 {
                [true, false]
            } else {
                [false, true]
            };
            for cached in order {
                if cached {
                    timed_round(
                        &cached_app,
                        &author_token,
                        &reader_token,
                        "cached",
                        run,
                        &mut cached_create,
                        &mut cached_read,
                    )
                    .await;
                } else {
                    timed_round(
                        &sql_app,
                        &author_token,
                        &reader_token,
                        "sql",
                        run,
                        &mut sql_create,
                        &mut sql_read,
                    )
                    .await;
                }
            }
        }
        print_table("fan-out on", &mut cached_create, &mut cached_read);
        print_table("fan-out off", &mut sql_create, &mut sql_read);

        // The write alone, with no request around it: this is what the create delta would
        // shrink to if the follower scan were free.
        let accounts: Vec<String> = (1..=FOLLOWERS).map(|i| format!("bench{i:04}")).collect();
        let mut push = Vec::with_capacity(PUSH_RUNS);
        for run in 0..PUSH_RUNS {
            let started = Instant::now();
            home.push(&format!("benchpush{run}"), 1, &accounts).await;
            push.push(started.elapsed());
        }
        println!(
            "cache push of {FOLLOWERS} entries  p50 {:>7.2} ms  p95 {:>7.2} ms",
            millis(percentile(&mut push, 50)),
            millis(percentile(&mut push, 95)),
        );
    })
    .await;
}
