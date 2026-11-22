//! `/nodeinfo/2.0` reads its usage counts in one statement, not one per account.
//!
//! A directory crawler polls this document on its own schedule, so a per-account count
//! would turn every poll into N round trips. This binary has a single test because the
//! capturing subscriber is process-wide.

mod support;

use std::sync::{Arc, Mutex};

use support::{create_account, create_status, expect_ok, json_of, run_db_test, send_anon};

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

/// Every statement sqlx logs, whatever the query builder was.
fn statements(log: &CapturedLog) -> usize {
    String::from_utf8_lossy(&log.0.lock().expect("log buffer"))
        .matches("sqlx::query:")
        .count()
}

#[tokio::test]
async fn the_nodeinfo_usage_counts_cost_one_statement() {
    run_db_test(|store, app| async move {
        for index in 0..5 {
            let account = create_account(store.pool(), &format!("nodeinfo-cost{index}")).await;
            create_status(store.pool(), &account, "hello", "public", &[], &[]).await;
        }

        // Installed after seeding, so the log holds the request's statements only.
        let log = CapturedLog(Arc::new(Mutex::new(Vec::new())));
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(log.clone())
            .try_init()
            .expect("install the capturing subscriber");

        let (status, body) = send_anon(&app, "GET", "/nodeinfo/2.0").await;
        let document = json_of(&expect_ok(status, &body, "/nodeinfo/2.0"));
        assert_eq!(document["usage"]["users"]["total"], 5);
        assert_eq!(
            statements(&log),
            1,
            "the usage document must cost one statement"
        );
    })
    .await;
}
