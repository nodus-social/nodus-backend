//! Reading positions.
//!
//! Mastodon's markers are per-account and per-timeline: "this reader has read up to
//! here in `home`". They are stored separately from statuses because the position is a
//! property of the reader, not of the timeline.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

/// One marker as stored.
#[derive(Debug, Clone, FromRow)]
pub struct MarkerRow {
    pub timeline: String,
    pub last_read_id: String,
    pub version: i32,
    pub updated_at: DateTime<Utc>,
}

/// Every marker this reader has, newest first.
pub async fn list(pool: &PgPool, account_id: &str) -> Result<Vec<MarkerRow>, sqlx::Error> {
    sqlx::query_as::<_, MarkerRow>(
        "SELECT timeline, last_read_id, version, updated_at FROM marker \
          WHERE account_id = $1 ORDER BY timeline ASC",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await
}

/// Creates or moves one marker.
///
/// The version is the client's own counter, echoed back so a client can tell whether
/// its write was the one that landed. A write older than the stored one is rejected by
/// the `WHERE` on the conflict branch rather than silently going backwards.
///
/// Everything this instance issues is a fixed-width ULID, so comparing the two ids as
/// text orders them correctly; a client that hands back an id it was given is always
/// comparing like with like.
///
/// A write that would move the marker backwards is not an error: it is a client
/// catching up out of order, and the reply is the position we kept.
pub async fn upsert(
    pool: &PgPool,
    account_id: &str,
    timeline: &str,
    last_read_id: &str,
    version: i32,
) -> Result<MarkerRow, sqlx::Error> {
    sqlx::query_as::<_, MarkerRow>(
        "WITH moved AS ( \
            INSERT INTO marker (account_id, timeline, last_read_id, version) \
            VALUES ($1, $2, $3, $4) \
            ON CONFLICT (account_id, timeline) DO UPDATE \
               SET last_read_id = EXCLUDED.last_read_id, version = EXCLUDED.version, \
                   updated_at = now() \
             WHERE marker.last_read_id < EXCLUDED.last_read_id \
                OR marker.version < EXCLUDED.version \
            RETURNING timeline, last_read_id, version, updated_at \
         ) \
         SELECT timeline, last_read_id, version, updated_at FROM moved \
         UNION ALL \
         SELECT timeline, last_read_id, version, updated_at FROM marker \
          WHERE account_id = $1 AND timeline = $2 \
            AND NOT EXISTS (SELECT 1 FROM moved) \
         LIMIT 1",
    )
    .bind(account_id)
    .bind(timeline)
    .bind(last_read_id)
    .bind(version)
    .fetch_one(pool)
    .await
}

/// Marks a conversation read up to a status.
pub async fn mark_conversation_read(
    pool: &PgPool,
    account_id: &str,
    root_id: &str,
    last_read_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO conversation_read (account_id, root_id, last_read_id) VALUES ($1, $2, $3) \
         ON CONFLICT (account_id, root_id) DO UPDATE \
            SET last_read_id = EXCLUDED.last_read_id, updated_at = now() \
          WHERE conversation_read.last_read_id < EXCLUDED.last_read_id",
    )
    .bind(account_id)
    .bind(root_id)
    .bind(last_read_id)
    .execute(pool)
    .await?;
    Ok(())
}
