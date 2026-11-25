//! A discovery page paints its statuses with a page hydration, not one at a time.
//!
//! Search and trends both answer with a list of statuses. They used to build each row
//! through `statuses::dto_with_pictures`, so the statement count followed the number of
//! hits. Both now call `pages::hydrate_statuses`; the pins below measure the same
//! endpoint at one and twenty rows and fail if the second costs more.

mod support;

use std::sync::{Arc, Mutex};

use serde_json::Value;
use sqlx::PgPool;

use support::{create_account, create_status, create_token, expect_ok, json_of, run_db_test, send};

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

fn statements(log: &CapturedLog) -> usize {
    String::from_utf8_lossy(&log.0.lock().expect("log buffer"))
        .matches("sqlx::query:")
        .count()
}

async fn measure(log: &CapturedLog, app: &axum::Router, token: &str, uri: &str) -> (usize, Value) {
    log.0.lock().expect("log buffer").clear();
    let (status, body) = send(app, token, "GET", uri, None).await;
    let body = expect_ok(status, &body, uri);
    let statements = statements(log);
    (statements, json_of(&body))
}

/// The unique term keeps search from matching rows another case seeded.
const TERM: &str = "hydrated-quokka-page";

async fn seed_status(pool: &PgPool, author: &str, label: &str) {
    create_status(pool, author, &format!("{TERM} {label}"), "public", &[], &[]).await;
}

#[tokio::test]
async fn a_discovery_page_hydrates_its_statuses_once() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let log = CapturedLog(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(log.clone())
            .finish();
        let _ = tracing_subscriber::util::SubscriberInitExt::try_init(subscriber);

        let author = create_account(&pool, "discovery-author").await;
        let reader = create_account(&pool, "discovery-reader").await;
        let token = create_token(&pool, &reader, &["read"]).await;

        seed_status(&pool, &author, "one").await;

        let search_one_uri = format!("/api/v2/search?q={TERM}&type=statuses&limit=1");
        let (search_one, body) = measure(&log, &app, &token, &search_one_uri).await;
        assert_eq!(
            body["statuses"].as_array().map(Vec::len),
            Some(1),
            "one search hit"
        );

        let (trends_one, body) = measure(&log, &app, &token, "/api/v1/trends/statuses").await;
        assert_eq!(
            body.as_array().map(Vec::len),
            Some(1),
            "one trending status"
        );

        for index in 1..20 {
            seed_status(&pool, &author, &format!("{index}")).await;
        }

        let search_twenty_uri = format!("/api/v2/search?q={TERM}&type=statuses&limit=20");
        let (search_twenty, body) = measure(&log, &app, &token, &search_twenty_uri).await;
        assert_eq!(
            body["statuses"].as_array().map(Vec::len),
            Some(20),
            "twenty search hits"
        );

        let (trends_twenty, body) = measure(&log, &app, &token, "/api/v1/trends/statuses").await;
        assert_eq!(
            body.as_array().map(Vec::len),
            Some(20),
            "twenty trending statuses"
        );

        // Search used to pay one `by_id`/account/media/decoration build per hit; both
        // endpoints now hydrate the whole page in one pass.
        eprintln!(
            "discovery: search {search_one} at one hit, {search_twenty} at twenty; trends \
             {trends_one} at one, {trends_twenty} at twenty"
        );
        assert_eq!(search_one, search_twenty, "search statements must not grow");
        assert_eq!(trends_one, trends_twenty, "trends statements must not grow");
    })
    .await;
}
