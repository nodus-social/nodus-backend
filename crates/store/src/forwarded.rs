//! Reports we sent to the peer that hosts the reported account.
//!
//! The delivery itself belongs to [`crate::delivery`] — this module only remembers which
//! report produced which activity and mirrors the queue's lifecycle. The mirror is kept by
//! a trigger in migration 0047, not by a writer here, so a retry or a give-up that happens
//! in the worker is reflected without either side knowing about the other.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// The states a forwarded report can be in, in the queue's vocabulary.
pub const STATES: [&str; 4] = ["pending", "delivered", "failed", "gave_up"];

/// One forwarded report as the console reads it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ForwardRow {
    pub id: String,
    pub report_id: String,
    pub target_domain: String,
    pub activity_uri: String,
    pub state: String,
    pub attempts: i32,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const COLUMNS: &str = "id, report_id, target_domain, activity_uri, state, attempts, \
     last_error, created_at, updated_at";

/// Whether this report was already forwarded, whatever the outcome.
pub async fn by_report(pool: &PgPool, report_id: &str) -> Result<Option<ForwardRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM report_forward WHERE report_id = $1"
    ))
    .bind(report_id)
    .fetch_optional(pool)
    .await
}

/// Writes the forward down, or returns `None` when another request already did.
///
/// The unique `report_id` is the idempotency guard: two concurrent forwards mint two
/// activities, but only the first row survives, and the loser re-reads it and answers with
/// the same state instead of queueing a second `Flag`.
pub async fn create(
    pool: &PgPool,
    report_id: &str,
    target_domain: &str,
    activity_uri: &str,
) -> Result<Option<ForwardRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "INSERT INTO report_forward (id, report_id, target_domain, activity_uri) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (report_id) DO NOTHING \
         RETURNING {COLUMNS}"
    ))
    .bind(ulid::Ulid::new().to_string())
    .bind(report_id)
    .bind(target_domain)
    .bind(activity_uri)
    .fetch_optional(pool)
    .await
}

/// Removes a row that never made it into the queue, so a refused forward leaves no trace.
pub async fn delete(pool: &PgPool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM report_forward WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// A page of forwards, newest first, narrowed by state and/or target domain.
pub async fn list(
    pool: &PgPool,
    state: Option<&str>,
    domain: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<ForwardRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM report_forward \
          WHERE ($1::text IS NULL OR state = $1) \
            AND ($2::text IS NULL OR target_domain = $2) \
          ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4"
    ))
    .bind(state)
    .bind(domain)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}
