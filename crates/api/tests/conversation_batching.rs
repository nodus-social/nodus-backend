//! A thread's participants are read once, not once per participant.
//!
//! `POST /api/v1/conversations/{id}/read` and the mute routes used to look each
//! participant's account up in a loop. A thread is a single subject, but its
//! participants are a page of accounts, so one batch answers for all of them. This
//! binary captures sqlx's statement log and pins the account reads at one.

mod support;

use std::sync::{Arc, Mutex};

use axum::Router;
use sqlx::PgPool;

use nodus_server_store::Store;

use support::{create_account, create_status, create_token, expect_ok, json_of, run_db_test, send};

/// A writer that keeps sqlx's statement log so the test can count statements.
#[derive(Clone)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
    type Writer = CapturedLog;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn clear(log: &CapturedLog) {
    log.0.lock().expect("log buffer").clear();
}

fn captured(log: &CapturedLog) -> String {
    String::from_utf8_lossy(&log.0.lock().expect("log buffer")).into_owned()
}

/// Every statement sqlx logs, whatever the query builder was.
fn statements(log: &CapturedLog) -> usize {
    captured(log).matches("sqlx::query:").count()
}

/// How many statements read the account table; a per-participant loop shows up here as N.
fn account_reads(log: &CapturedLog) -> usize {
    captured(log).matches("FROM account").count()
}

/// Account reads that asked for a whole set at once. A participant loop cannot produce
/// one of these; it reads one row per statement instead.
fn batched_account_reads(log: &CapturedLog) -> usize {
    captured(log).matches("FROM account WHERE id = ANY").count()
}

/// Account reads that asked for exactly one row, the shape a per-participant loop makes.
fn single_account_reads(log: &CapturedLog) -> usize {
    captured(log).matches("FROM account WHERE id = $1").count()
}

/// A direct message from `viewer` naming `participants`, and the thread's root id.
async fn seed_thread(pool: &PgPool, viewer: &str, participants: &[String]) -> String {
    create_status(pool, viewer, "hello all", "direct", participants, &[]).await
}

/// The removed path, replayed for the same thread: one participant lookup, then one
/// account read per participant.
async fn old_path_statements(store: &Store, viewer: &str, root: &str, log: &CapturedLog) -> usize {
    clear(log);
    let ids: Vec<String> = nodus_server_store::conversations::participants(
        store.pool(),
        viewer,
        std::slice::from_ref(&root.to_owned()),
    )
    .await
    .expect("participants")
    .into_iter()
    .map(|(_, id)| id)
    .collect();
    assert!(ids.len() > 1, "the thread needs several participants");
    for id in &ids {
        let _ = store.account(id).await.expect("participant read");
    }
    assert_eq!(
        single_account_reads(log),
        ids.len(),
        "the removed path paid one statement per participant"
    );
    statements(log)
}

/// A request that renders one thread, and what it cost.
async fn thread_stats(
    app: &Router,
    token: &str,
    root: &str,
    log: &CapturedLog,
) -> (usize, usize, serde_json::Value) {
    clear(log);
    let (status, body) = send(
        app,
        token,
        "POST",
        &format!("/api/v1/conversations/{root}/read"),
        None,
    )
    .await;
    let body = expect_ok(status, &body, "conversation read");
    (statements(log), account_reads(log), json_of(&body))
}

#[tokio::test]
async fn a_thread_reads_its_participants_once() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let viewer = create_account(pool, "dm-viewer").await;
        let token = create_token(pool, &viewer, &["read", "write"]).await;
        let mut participants = Vec::new();
        for label in ["dm-one", "dm-two", "dm-three"] {
            participants.push(create_account(pool, label).await);
        }
        let root = seed_thread(pool, &viewer, &participants).await;

        // sqlx logs each statement at `DEBUG`; the subscriber lives for this process and
        // this binary has one test, so the capture cannot pick up another test's queries.
        let log = CapturedLog(Arc::new(Mutex::new(Vec::new())));
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(log.clone())
            .try_init()
            .expect("install the capturing subscriber");

        let (total, accounts, body) = thread_stats(&app, &token, &root, &log).await;
        // The status's own author and its mentioned accounts are reads of their own
        // (`crates/api/src/statuses.rs`); the participants must arrive together, which is
        // what the `ANY` read proves — a per-participant loop could not produce one.
        assert_eq!(
            batched_account_reads(&log),
            1,
            "one thread must read its participants in one statement, saw {accounts} account \
             reads in total"
        );
        let rendered = body["accounts"].as_array().expect("accounts array");
        assert_eq!(
            rendered.len(),
            participants.len(),
            "every participant still reaches the payload: {body}"
        );

        // The list route renders the same threads. It reads participants in one statement
        // and the threads' last-status authors in a second: two batch reads for the page,
        // not one per thread.
        clear(&log);
        let (status, list) = send(&app, &token, "GET", "/api/v1/conversations", None).await;
        let list = expect_ok(status, &list, "/api/v1/conversations");
        assert_eq!(
            batched_account_reads(&log),
            2,
            "the conversation list reads participants and status authors in two statements"
        );
        assert_eq!(
            json_of(&list).as_array().expect("list array").len(),
            1,
            "the thread is listed"
        );

        // The inbox is a page: one thread and twenty must cost the same statements. The
        // last statuses are named in one `by_ids` read and painted by one page hydration;
        // a per-thread `by_id` loop would add a statement for every extra row.
        let one_page = statements(&log);
        for _ in 1..20 {
            seed_thread(pool, &viewer, &participants).await;
        }
        clear(&log);
        let (status, list) = send(&app, &token, "GET", "/api/v1/conversations", None).await;
        let list = expect_ok(status, &list, "/api/v1/conversations");
        let twenty_page = statements(&log);
        assert_eq!(
            json_of(&list).as_array().expect("list array").len(),
            20,
            "twenty threads are listed"
        );
        // A conversation's newest status is direct, so its audience check cannot be
        // batched: `can_view_for_viewer` reads the author's account state per subject
        // (deleted, remote moderation) before it serves the row. That floor is two
        // statements per thread. Everything else — the page query, participants, muted
        // roots, the last-status `by_ids` and the page hydration — is flat.
        assert_eq!(
            twenty_page - one_page,
            2 * 19,
            "only the per-subject DM audience check may grow with the page"
        );
        eprintln!(
            "conversation list: {one_page} statements at one thread, {twenty_page} at twenty \
             (+2 per thread: the per-subject audience check)"
        );

        let before = old_path_statements(&store, &viewer, &root, &log).await;
        assert_eq!(
            before,
            1 + participants.len(),
            "the removed path paid the participant lookup plus one read per participant"
        );
        eprintln!(
            "conversation participants: {before} statements before, 2 now (one participant \
             lookup, one batched account read); request total {total}, {accounts} account reads"
        );
    })
    .await;
}
