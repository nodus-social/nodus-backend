//! The append-only event log and its hash chain.
//!
//! The chain is what makes "fill the gap" safe: a client that has hash `h` can ask for
//! everything after it, and a server that has pruned `h` says so instead of silently
//! returning a page from a different history.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::FromRow;
use sqlx::PgPool;

/// One link in a collection's chain.
#[derive(Debug, Clone, FromRow)]
pub struct EventRow {
    pub seq: i64,
    pub id: String,
    pub collection: String,
    pub kind: String,
    pub payload: Value,
    pub previous_hash: Option<String>,
    pub hash: String,
    pub created_at: DateTime<Utc>,
}

/// Appends an event and advances the collection root in one transaction.
///
/// The row lock on `collection_state` serialises writers per collection, which is what
/// keeps two concurrent appends from both claiming the same predecessor.
pub async fn append(
    pool: &PgPool,
    collection: &str,
    kind: &str,
    payload: &Value,
) -> Result<EventRow, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO collection_state (collection) VALUES ($1) \
         ON CONFLICT (collection) DO NOTHING",
    )
    .bind(collection)
    .execute(&mut *tx)
    .await?;
    let previous: Option<String> =
        sqlx::query_scalar("SELECT root FROM collection_state WHERE collection = $1 FOR UPDATE")
            .bind(collection)
            .fetch_one(&mut *tx)
            .await?;
    let id = ulid::Ulid::new().to_string();
    let hash = chain_hash(previous.as_deref(), &id, kind, payload);
    let row = sqlx::query_as::<_, EventRow>(
        "INSERT INTO event_log (id, collection, kind, payload, previous_hash, hash) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         RETURNING seq, id, collection, kind, payload, previous_hash, hash, created_at",
    )
    .bind(&id)
    .bind(collection)
    .bind(kind)
    .bind(payload)
    .bind(&previous)
    .bind(&hash)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("UPDATE collection_state SET root = $2, updated_at = now() WHERE collection = $1")
        .bind(collection)
        .bind(&hash)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(row)
}

/// The current root, or `None` for a collection with no events.
pub async fn root(pool: &PgPool, collection: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT root FROM collection_state WHERE collection = $1")
        .bind(collection)
        .fetch_optional(pool)
        .await
        .map(Option::flatten)
}

/// Events after a known hash, oldest first.
///
/// An unknown hash yields an empty page, not an error: the caller decides between
/// "already current" and "history diverged" by comparing [`root`].
pub async fn after(
    pool: &PgPool,
    collection: &str,
    since: &str,
    limit: i64,
) -> Result<Vec<EventRow>, sqlx::Error> {
    sqlx::query_as::<_, EventRow>(
        "SELECT seq, id, collection, kind, payload, previous_hash, hash, created_at \
         FROM event_log \
         WHERE collection = $1 \
           AND seq > COALESCE((SELECT seq FROM event_log WHERE hash = $2), $3) \
         ORDER BY seq ASC LIMIT $4",
    )
    .bind(collection)
    .bind(since)
    .bind(i64::MAX)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// How many retained events the collection has.
pub async fn count(pool: &PgPool, collection: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM event_log WHERE collection = $1")
        .bind(collection)
        .fetch_one(pool)
        .await
}

/// Whether `hash` exists in this collection's retained history.
pub async fn knows(pool: &PgPool, collection: &str, hash: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM event_log WHERE collection = $1 AND hash = $2)",
    )
    .bind(collection)
    .bind(hash)
    .fetch_one(pool)
    .await
}

/// Recomputes one link exactly as [`append`] did.
#[must_use]
pub fn chain_hash(previous: Option<&str>, id: &str, kind: &str, payload: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"nodus-sync-v1\0");
    hasher.update(previous.unwrap_or_default().as_bytes());
    hasher.update(b"\0");
    hasher.update(id.as_bytes());
    hasher.update(b"\0");
    hasher.update(kind.as_bytes());
    hasher.update(b"\0");
    hasher.update(payload.to_string().as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chain_link_depends_on_its_predecessor() {
        let payload = serde_json::json!({"status_id": "1"});
        let first = chain_hash(None, "a", "status", &payload);
        let second = chain_hash(Some(&first), "b", "status", &payload);
        assert_ne!(first, second);
        assert_eq!(first, chain_hash(None, "a", "status", &payload));
    }

    #[test]
    fn the_payload_is_part_of_the_hash() {
        let one = chain_hash(None, "a", "status", &serde_json::json!({"n": 1}));
        let two = chain_hash(None, "a", "status", &serde_json::json!({"n": 2}));
        assert_ne!(one, two);
    }
}
