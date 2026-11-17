//! Posts that are waiting to go out.
//!
//! A scheduled post is not a status yet: it is a composed body plus a time. It is stored
//! as the client's own JSON so a schedule survives changes to what a post may contain,
//! and published by the scheduler once its time has come.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgPool};

/// One scheduled post as stored.
#[derive(Debug, Clone, FromRow)]
pub struct ScheduledRow {
    pub id: String,
    pub account_id: String,
    pub scheduled_at: DateTime<Utc>,
    pub params: Value,
}

pub async fn create(
    pool: &PgPool,
    id: &str,
    account_id: &str,
    scheduled_at: DateTime<Utc>,
    params: &Value,
) -> Result<ScheduledRow, sqlx::Error> {
    sqlx::query_as::<_, ScheduledRow>(
        "INSERT INTO scheduled_status (id, account_id, scheduled_at, params) \
         VALUES ($1, $2, $3, $4) \
         RETURNING id, account_id, scheduled_at, params",
    )
    .bind(id)
    .bind(account_id)
    .bind(scheduled_at)
    .bind(params)
    .fetch_one(pool)
    .await
}

/// Everything this account has queued, soonest first.
pub async fn list(pool: &PgPool, account_id: &str) -> Result<Vec<ScheduledRow>, sqlx::Error> {
    sqlx::query_as::<_, ScheduledRow>(
        "SELECT id, account_id, scheduled_at, params FROM scheduled_status \
          WHERE account_id = $1 ORDER BY scheduled_at ASC, id ASC",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await
}

/// Removes one queued post, if it belongs to this account.
pub async fn cancel(pool: &PgPool, account_id: &str, id: &str) -> Result<bool, sqlx::Error> {
    let done = sqlx::query("DELETE FROM scheduled_status WHERE id = $1 AND account_id = $2")
        .bind(id)
        .bind(account_id)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() > 0)
}

/// The posts whose time has come.
pub async fn due(pool: &PgPool, limit: i64) -> Result<Vec<ScheduledRow>, sqlx::Error> {
    sqlx::query_as::<_, ScheduledRow>(
        "SELECT id, account_id, scheduled_at, params FROM scheduled_status \
          WHERE scheduled_at <= now() ORDER BY scheduled_at ASC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Removes a row after it has been published, so a crash between the two cannot publish
/// the same post twice.
pub async fn remove(pool: &PgPool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM scheduled_status WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}
