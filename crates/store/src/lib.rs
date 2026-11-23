//! All SQL lives here.
//!
//! One rule keeps the layering honest: **the API never names a table.** A handler asks
//! for a page, a row or a write; the query that answers it, and the transaction it
//! needs, are in this crate. That is what makes the fan-out guarantees ("the entry and
//! the status commit together") checkable in one place.
//!
//! The same rule is why a delivery's whole life — queued, retried, rejected, delivered —
//! lives in [`delivery`]: an operator asking why a post never reached a peer reads a row,
//! not a log line that may have rotated away.

pub mod account_blocks;
pub mod accounts;
pub mod alerts;
pub mod announcements;
pub mod appeals;
pub mod apps;
pub mod blocklist;
pub mod blocks;
pub mod collections;
pub mod conversations;
pub mod delivery;
pub mod discovery;
pub mod drive;
pub mod escalation;
pub mod events;
pub mod external_ids;
pub mod filters;
pub mod forwarded;
pub mod highlights;
pub mod hydrate;
pub mod invalidate;
pub mod jobs;
pub mod lists;
pub mod live;
pub mod markers;
pub mod media;
pub mod media_nodes;
pub mod miauth;
pub mod moderation;
pub mod moderation_rules;
pub mod nodeinfo;
pub mod notification_policy;
pub mod pauses;
pub mod polls;
pub mod preferences;
pub mod remote_moderation;
pub mod rules;
pub mod scanners;
pub mod schedules;
pub mod social;
pub mod stats;
pub mod statuses;
pub mod tags;
pub mod writer;

pub use hydrate::{Batch, BatchOutcome, ExternalIds, MentionRow, RowMap, StatusDecorations};

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

    /// The raw pool, for the modules that have not been moved behind the read seam yet.
    ///
    /// **No new caller may be added.** A handler that takes this handle can write any
    /// query it likes, which is exactly what `crates/store` exists to prevent: the API
    /// names no table. Reach for a function in `crates/store` — a single subject, or, for
    /// a page, [`Store::batch`] — before this.
    ///
    /// The callers that still hold it, and why each is not yet moved:
    ///
    /// - `crates/api/src` — every module whose reads are still per-row: `activitypub`,
    ///   `misskey`/`misskey_page`, `statuses`, `admin/*`, `filters`, `notifications`,
    ///   `outbox`, `drive`, `media`, `lists`, `highlights`, `nodus`, `streaming`,
    ///   `client_metadata`. Each is the next module to take the three-stage move that
    ///   `accounts` took (raw function private, curated `Store` op, page read batched).
    /// - `crates/media/src/serve.rs` and `crates/prune/src/run.rs` — drive pooled reads
    ///   for media refs and retention sweeps, not page reads.
    /// - the integration tests in `crates/api/tests` and the `migrated_state` helper in
    ///   `crates/api/tests/support/mod.rs` — they check what the server wrote, and a test
    ///   asserting query counts has to reach the same pool the server used.
    ///
    /// When the last module is moved, this method goes away.
    #[doc(hidden)]
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Wraps a pool this process already owns.
    ///
    /// This exists for the store's own integration tests, which are separate crates and
    /// drive the raw, schema-scoped pool `sqlx::test` hands them. It is not an API entry
    /// point: no handler may derive a `Store` from anything but [`Store::connect`].
    #[doc(hidden)]
    #[must_use]
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The writer's own pool: one connection, built from this pool's connect options.
    ///
    /// `max_connections(1)` is not a tuning knob — it is the single writer. Copying the
    /// connect options keeps whatever this pool was opened with, including the
    /// `search_path` a test harness scopes a schema to.
    #[must_use]
    pub fn write_pool(&self) -> PgPool {
        PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy_with((*self.pool.connect_options()).clone())
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
            sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success")
                .fetch_one(&self.pool)
                .await;
        let pending: Result<i64, _> =
            sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE NOT success")
                .fetch_one(&self.pool)
                .await;
        matches!((applied, pending), (Ok(a), Ok(p)) if a > 0 && p == 0)
    }
}
