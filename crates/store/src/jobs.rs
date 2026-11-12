//! The job queue: enqueue, lease, release.
//!
//! The lease is the whole safety story. A worker never deletes a row it has not
//! finished: it sets `locked_until`, and a crashed worker's row becomes claimable again
//! when the lease expires. `attempts` is incremented on claim, not on failure, so a
//! worker that dies still counts against the retry budget — otherwise a job that kills
//! its worker every time would retry forever.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgPool};

use nodus_server_core::Id;

/// The kinds the worker knows. A kind that is not here cannot be enqueued: the
/// database's `job_kind_valid` check is the second line of defence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JobKind {
    FanOut,
    Deliver,
    MediaProcess,
    IngestRemote,
    Prune,
}

impl JobKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FanOut => "fan_out",
            Self::Deliver => "deliver",
            Self::MediaProcess => "media_process",
            Self::IngestRemote => "ingest_remote",
            Self::Prune => "prune",
        }
    }

    /// Higher runs first: a delivery that is already late must not wait behind pruning.
    #[must_use]
    pub fn priority(self) -> i16 {
        match self {
            Self::Deliver => 100,
            Self::FanOut => 50,
            Self::MediaProcess => 20,
            Self::IngestRemote => 10,
            Self::Prune => 0,
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "fan_out" => Some(Self::FanOut),
            "deliver" => Some(Self::Deliver),
            "media_process" => Some(Self::MediaProcess),
            "ingest_remote" => Some(Self::IngestRemote),
            "prune" => Some(Self::Prune),
            _ => None,
        }
    }
}

/// A claimed job.
#[derive(Debug, Clone, FromRow)]
pub struct Job {
    pub id: String,
    pub kind: String,
    pub payload: Value,
    pub attempts: i32,
}

/// Enqueues a job, or does nothing when one with the same `(kind, subject)` is already
/// outstanding.
///
/// Returning `None` is a success: a duplicate enqueue means the work is already
/// queued, which is what the caller wanted.
pub async fn enqueue(
    pool: &PgPool,
    kind: JobKind,
    subject_id: Option<&str>,
    payload: &Value,
) -> Result<Option<String>, sqlx::Error> {
    let id = Id::new().to_string();
    let row: Option<(String,)> = sqlx::query_as(
        "INSERT INTO job (id, kind, priority, subject_id, payload) VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (kind, subject_id) WHERE finished_at IS NULL AND subject_id IS NOT NULL \
         DO NOTHING RETURNING id",
    )
    .bind(&id)
    .bind(kind.as_str())
    .bind(kind.priority())
    .bind(subject_id)
    .bind(payload)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(id,)| id))
}

/// Claims one ready job for `worker` and leases it for `lease`.
///
/// `FOR UPDATE SKIP LOCKED` is what makes N workers safe: each takes a different row
/// or nothing, without a coordinator.
pub async fn claim(
    pool: &PgPool,
    worker: &str,
    lease: std::time::Duration,
) -> Result<Option<Job>, sqlx::Error> {
    let lease_seconds = i64::try_from(lease.as_secs()).unwrap_or(120);
    sqlx::query_as::<_, Job>(
        "UPDATE job SET locked_by = $1, \
                        locked_until = now() + ($2::bigint * interval '1 second'), \
                        attempts = attempts + 1 \
         WHERE id = ( \
             SELECT id FROM job \
              WHERE finished_at IS NULL \
                AND (locked_until IS NULL OR locked_until < now()) \
                AND earliest_at <= now() \
              ORDER BY priority DESC, earliest_at \
              FOR UPDATE SKIP LOCKED \
              LIMIT 1) \
         RETURNING id, kind, payload, attempts",
    )
    .bind(worker)
    .bind(lease_seconds)
    .fetch_optional(pool)
    .await
}

/// Marks a job done.
pub async fn succeed(pool: &PgPool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE job SET finished_at = now(), locked_by = NULL, locked_until = NULL WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map(drop)
}

/// Releases a job for a later attempt, keeping the error for the operator.
///
/// After `max_attempts` the job is finished instead, so a permanently failing delivery
/// stops consuming a worker slot.
pub async fn retry_or_finish(
    pool: &PgPool,
    id: &str,
    attempts: i32,
    delay: std::time::Duration,
    error: &str,
    max_attempts: i32,
) -> Result<bool, sqlx::Error> {
    let delay_seconds = i64::try_from(delay.as_secs()).unwrap_or(60);
    if attempts >= max_attempts {
        sqlx::query(
            "UPDATE job SET finished_at = now(), locked_by = NULL, locked_until = NULL, \
                            last_error = $2 WHERE id = $1",
        )
        .bind(id)
        .bind(error)
        .execute(pool)
        .await
        .map(drop)
        .map(|()| false)
    } else {
        sqlx::query(
            "UPDATE job SET locked_by = NULL, locked_until = NULL, last_error = $2, \
                            earliest_at = now() + ($3::bigint * interval '1 second') \
             WHERE id = $1",
        )
        .bind(id)
        .bind(error)
        .bind(delay_seconds)
        .execute(pool)
        .await
        .map(drop)
        .map(|()| true)
    }
}

/// Outstanding jobs by kind: the HPA metric and the operator's first question.
pub async fn backlog(pool: &PgPool) -> Result<Vec<(String, i64)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT kind, count(*) FROM job \
          WHERE finished_at IS NULL AND earliest_at <= now() GROUP BY kind ORDER BY kind",
    )
    .fetch_all(pool)
    .await
}

/// The next time a job becomes ready, so an idle worker sleeps instead of polling.
pub async fn next_ready_at(pool: &PgPool) -> Result<Option<DateTime<Utc>>, sqlx::Error> {
    let row: Option<(Option<DateTime<Utc>>,)> = sqlx::query_as(
        "SELECT min(earliest_at) FROM job \
          WHERE finished_at IS NULL AND (locked_until IS NULL OR locked_until < now())",
    )
    .fetch_one(pool)
    .await?;
    Ok(row.and_then(|(at,)| at))
}
