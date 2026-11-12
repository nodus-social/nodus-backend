//! All SQL lives here.
//!
//! One rule keeps the layering honest: **the API never names a table.** A handler asks
//! for a page, a row or a write; the query that answers it, and the transaction it
//! needs, are in this crate. That is what makes the fan-out guarantees ("the entry and
//! the status commit together") checkable in one place.

pub mod accounts;
pub mod jobs;
pub mod statuses;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// The store: a connection pool, and nothing else.
///
/// It is cloned into axum state and into the worker; `PgPool` is already a handle.
#[derive(Debug, Clone)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    /// Connects and fails fast: a server that cannot reach its database has nothing
    /// useful to do, so startup does not retry silently.
    pub async fn connect(url: &str, max_connections: u32) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(url)
            .await?;
        Ok(Self { pool })
    }

    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// A pool that connects on first use.
    ///
    /// Used by tests and by `--migrate-only`, where the process must start without a
    /// live database but the first query still has to fail loudly.
    #[must_use]
    pub fn connect_lazy(url: &str, max_connections: u32) -> Self {
        Self {
            pool: PgPoolOptions::new()
                .max_connections(max_connections)
                .connect_lazy(url)
                .unwrap_or_else(|error| panic!("invalid database url: {error}")),
        }
    }

    /// Runs the migrations in `migrations/`. Forward-only, one transaction each.
    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        sqlx::migrate!("./migrations").run(&self.pool).await
    }

    /// Readiness: the database answers and the schema is at head.
    ///
    /// A reachable database with a stale schema is the failure mode that produced this
    /// check: the API answers `/healthz` while every write fails on a missing column.
    pub async fn ready(&self) -> bool {
        let reachable: Result<i32, _> = sqlx::query_scalar("SELECT 1").fetch_one(&self.pool).await;
        if reachable.is_err() {
            return false;
        }
        let applied: Result<i64, _> =
            sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success").fetch_one(&self.pool).await;
        let pending: Result<i64, _> = sqlx::query_scalar(
            "SELECT count(*) FROM _sqlx_migrations WHERE NOT success",
        )
        .fetch_one(&self.pool)
        .await;
        matches!((applied, pending), (Ok(a), Ok(p)) if a > 0 && p == 0)
    }
}
