//! A Postgres schema that belongs to one test.
//!
//! The listener test spawns the real binary, and both roles migrate before they bind.
//! `migrate()` compares the rows in `_sqlx_migrations` against the files and refuses to
//! run when a row was applied from different bytes, so migrating the shared `public`
//! schema on a long-lived development database fails for a reason that has nothing to do
//! with the role under test. This module gives the child a schema the test created itself,
//! and removes it again even when an assertion fails.

use std::sync::atomic::{AtomicU64, Ordering};

use sqlx::{Connection, PgConnection};

/// Names every schema in this process: one binary, one process, one counter.
static NEXT: AtomicU64 = AtomicU64::new(0);

/// Builds the URL that points a connection at `schema`, with `public` still reachable so
/// extensions and helper tables installed there are found.
fn private_database_url(url: &str, schema: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}

/// A schema of this test's own, created on construction and dropped on `Drop`.
pub struct PrivateSchema {
    base: String,
    schema: String,
}

impl PrivateSchema {
    /// Creates a fresh schema on the database `base` points at.
    pub fn new(base: &str) -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let schema = format!("pgtest_aio_{}_{id}", std::process::id());
        block_on(async {
            let mut admin = PgConnection::connect(base)
                .await
                .expect("connect to postgres for the test schema");
            sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
                .execute(&mut admin)
                .await
                .expect("create the test schema");
        });
        Self {
            base: base.to_owned(),
            schema,
        }
    }

    /// The URL a role should be given so its migrations land in this schema.
    pub fn url(&self) -> String {
        private_database_url(&self.base, &self.schema)
    }
}

impl Drop for PrivateSchema {
    fn drop(&mut self) {
        block_on(async {
            let Ok(mut admin) = PgConnection::connect(&self.base).await else {
                return;
            };
            // A child that is still running can hold locks. A leftover `pgtest_aio_…`
            // schema is harmless; a suite that hangs is not.
            let _ = sqlx::query("SET statement_timeout = '10s'")
                .execute(&mut admin)
                .await;
            let _ = sqlx::query(&format!(
                "DROP SCHEMA IF EXISTS \"{}\" CASCADE",
                self.schema
            ))
            .execute(&mut admin)
            .await;
        });
    }
}

/// The roles tests are plain `#[test]` functions, so a runtime can be built here.
fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a tokio runtime for the test database")
        .block_on(future)
}
