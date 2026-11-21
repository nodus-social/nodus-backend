//! The one-time recompute of `account.statuses_count`.
//!
//! The harness applies the migrations to an empty schema, so this test seeds the state an
//! existing instance carries across the upgrade — rows already stored, counter still 0 —
//! and runs the backfill statement itself. The rows are inserted directly, so the test
//! does not depend on the incremental paths whose counter the migration replaces.
//!
//! The seeded rows pin both edges of the definition: a soft-deleted post and a
//! Mastodon-style boost must not count, while a Misskey renote (empty body but a
//! `content_source`) must, because `statuses::create` counts it. `last_status_at` is a
//! high-water mark: a NULL is filled from the newest counted row, an existing value is
//! never lowered.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

const BACKFILL: &str = include_str!("../migrations/0054_status_count_backfill.sql");

const SEED: &str = r"
INSERT INTO account (id, username, domain, local, statuses_count, last_status_at) VALUES
    ('backfill-local',   'backfill_local',   NULL,          true,  0, NULL),
    ('backfill-remote',  'backfill_remote',  'remote.test', false, 0, NULL),
    ('backfill-correct', 'backfill_correct', 'remote.test', false, 1, '2026-06-01T00:00:00Z');

INSERT INTO status (id, account_id, content, visibility, local, created_at) VALUES
    ('local-live',   'backfill-local', 'hello', 'public', true,  '2026-01-01T10:00:00Z'),
    ('remote-live',  'backfill-remote', 'hi',   'public', false, '2026-02-01T00:00:00Z'),
    ('remote-old',   'backfill-remote', 'old',  'public', false, '2026-02-05T00:00:00Z'),
    ('correct-live', 'backfill-correct', 'kept', 'public', false, '2026-01-01T00:00:00Z');

INSERT INTO status
    (id, account_id, content, content_source, visibility, local, reblog_of_id, created_at)
VALUES
    ('local-renote', 'backfill-local', '', '', 'public', true, 'local-live',
     '2026-01-02T00:00:00Z'),
    ('local-boost',  'backfill-local', '', NULL, 'public', true, 'local-live',
     '2026-01-04T00:00:00Z');

INSERT INTO status (id, account_id, content, visibility, local, created_at, deleted_at) VALUES
    ('local-deleted', 'backfill-local', 'gone', 'public', true,
     '2026-01-03T00:00:00Z', '2026-01-10T00:00:00Z');

UPDATE status SET deleted_at = '2026-01-10T00:00:00Z' WHERE id = 'remote-old';
";

#[derive(Debug, PartialEq, sqlx::FromRow)]
struct Counter {
    id: String,
    statuses_count: i64,
    last_status_at: Option<DateTime<Utc>>,
}

async fn counters(pool: &PgPool) -> Vec<Counter> {
    sqlx::query_as("SELECT id, statuses_count, last_status_at FROM account ORDER BY id")
        .fetch_all(pool)
        .await
        .expect("read account counters")
}

fn counter<'a>(rows: &'a [Counter], id: &str) -> &'a Counter {
    rows.iter()
        .find(|row| row.id == id)
        .expect("seeded account is present")
}

fn ts(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("valid timestamp")
        .with_timezone(&Utc)
}

#[sqlx::test(migrations = "./migrations")]
async fn backfills_a_stale_statuses_count_and_never_lowers_last_status_at(pool: PgPool) {
    sqlx::raw_sql(SEED)
        .execute(&pool)
        .await
        .expect("seed the pre-a4e0281 state");

    sqlx::raw_sql(BACKFILL)
        .execute(&pool)
        .await
        .expect("run the backfill");

    let rows = counters(&pool).await;

    let local = counter(&rows, "backfill-local");
    assert_eq!(
        local.statuses_count, 2,
        "a live post and a Misskey renote count; the boost and the tombstone do not"
    );
    assert_eq!(
        local.last_status_at,
        Some(ts("2026-01-02T00:00:00Z")),
        "the tombstone and the newer boost must not move the account's last post"
    );

    let remote = counter(&rows, "backfill-remote");
    assert_eq!(
        remote.statuses_count, 1,
        "only the live remote note counts, not its tombstone"
    );
    assert_eq!(
        remote.last_status_at,
        Some(ts("2026-02-01T00:00:00Z")),
        "the newest live remote note fills the NULL"
    );

    let already_correct = counter(&rows, "backfill-correct");
    assert_eq!(already_correct.statuses_count, 1);
    assert_eq!(
        already_correct.last_status_at,
        Some(ts("2026-06-01T00:00:00Z")),
        "an existing high-water mark is never lowered to the newest live row"
    );

    sqlx::raw_sql(BACKFILL)
        .execute(&pool)
        .await
        .expect("run the backfill a second time");

    assert_eq!(
        counters(&pool).await,
        rows,
        "an absolute recompute is idempotent"
    );
}
