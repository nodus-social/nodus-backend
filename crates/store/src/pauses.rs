//! Reversible, expiring domain pauses — the middle of the moderation scale.
//!
//! A block (`instance_block`) is final: a severity, reject flags and no expiry. A pause is
//! the opposite shape: no severity, an optional deadline, and it is read on every request
//! rather than swept. The peer is never told, so lifting one is invisible to them.
//!
//! Every query here answers "is this domain paused *right now*"; callers on the delivery,
//! timeline and media paths must not cache the answer past the request.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// One pause as stored.
#[derive(Debug, Clone)]
pub struct DomainPauseRow {
    pub domain: String,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl DomainPauseRow {
    /// Whether the pause still applies at `now`.
    ///
    /// The same predicate is in every SQL read below and in the delivery queue, so an
    /// expired row stops applying everywhere at once even though it is kept as a record.
    #[must_use]
    pub fn in_force(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_none_or(|expires_at| expires_at > now)
    }
}

/// A pause plus the handle of whoever made it, for the console list.
#[derive(Debug, Clone)]
pub struct ListedDomainPause {
    pub row: DomainPauseRow,
    pub created_by_handle: Option<String>,
}

/// What creating or changing a pause needs.
#[derive(Debug, Clone)]
pub struct NewDomainPause<'a> {
    pub domain: &'a str,
    pub reason: &'a str,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_by: Option<&'a str>,
}

fn row_from(
    (domain, reason, expires_at, created_by, created_at): (
        String,
        String,
        Option<DateTime<Utc>>,
        Option<String>,
        DateTime<Utc>,
    ),
) -> DomainPauseRow {
    DomainPauseRow {
        domain,
        reason,
        expires_at,
        created_by,
        created_at,
    }
}

/// Creates or replaces the pause for a domain.
///
/// Re-pausing an already paused domain updates reason/expiry in place and reports
/// `inserted = false`, so a console can tell "paused" from "pause changed".
pub async fn upsert(
    pool: &PgPool,
    pause: &NewDomainPause<'_>,
) -> Result<(DomainPauseRow, bool), sqlx::Error> {
    let inserted: (
        String,
        String,
        Option<DateTime<Utc>>,
        Option<String>,
        DateTime<Utc>,
        bool,
    ) = sqlx::query_as(
        "INSERT INTO domain_pause (domain, reason, expires_at, created_by) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (domain) DO UPDATE \
                SET reason = EXCLUDED.reason, expires_at = EXCLUDED.expires_at, \
                    created_by = EXCLUDED.created_by, created_at = now() \
             RETURNING domain, reason, expires_at, created_by, created_at, (xmax = 0)",
    )
    .bind(pause.domain)
    .bind(pause.reason)
    .bind(pause.expires_at)
    .bind(pause.created_by)
    .fetch_one(pool)
    .await?;
    let (domain, reason, expires_at, created_by, created_at, inserted) = inserted;
    Ok((
        row_from((domain, reason, expires_at, created_by, created_at)),
        inserted,
    ))
}

/// Removes a pause. Returns whether there was one to remove.
pub async fn lift(pool: &PgPool, domain: &str) -> Result<bool, sqlx::Error> {
    let removed = sqlx::query("DELETE FROM domain_pause WHERE domain = $1")
        .bind(domain)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(removed == 1)
}

/// Every pause, expired ones included, so the console can show what was once decided.
pub async fn list(
    pool: &PgPool,
    limit: i64,
    offset: i64,
) -> Result<Vec<ListedDomainPause>, sqlx::Error> {
    type Row = (
        String,
        String,
        Option<DateTime<Utc>>,
        Option<String>,
        DateTime<Utc>,
        Option<String>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT p.domain, p.reason, p.expires_at, p.created_by, p.created_at, \
                a.username::text \
           FROM domain_pause p \
           LEFT JOIN account a ON a.id = p.created_by \
          ORDER BY p.created_at DESC, p.domain ASC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(domain, reason, expires_at, created_by, created_at, created_by_handle)| {
                ListedDomainPause {
                    row: row_from((domain, reason, expires_at, created_by, created_at)),
                    created_by_handle,
                }
            },
        )
        .collect())
}

/// Whether this domain is paused right now. Expired rows do not count.
pub async fn in_force(pool: &PgPool, domain: &str) -> Result<bool, sqlx::Error> {
    let paused: Option<bool> = sqlx::query_scalar(
        "SELECT true FROM domain_pause \
          WHERE domain = $1 AND (expires_at IS NULL OR expires_at > now())",
    )
    .bind(domain)
    .fetch_optional(pool)
    .await?;
    Ok(paused.unwrap_or(false))
}

/// Every domain with a pause in force right now.
///
/// The delivery path uses this to drop new inboxes; SQL callers use the `NOT EXISTS`
/// predicate directly so an expired row never needs a client-side clock.
pub async fn active_domains(pool: &PgPool) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT domain FROM domain_pause \
          WHERE expires_at IS NULL OR expires_at > now() \
          ORDER BY domain",
    )
    .fetch_all(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn an_expired_pause_is_no_longer_in_force() {
        let now = Utc::now();
        let row = DomainPauseRow {
            domain: "remote.test".to_owned(),
            reason: String::new(),
            expires_at: Some(now - Duration::seconds(1)),
            created_by: None,
            created_at: now,
        };
        assert!(!row.in_force(now));
        assert!(row.in_force(now - Duration::seconds(2)));
    }
}
