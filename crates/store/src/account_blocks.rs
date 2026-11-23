//! A person's own domain blocks.
//!
//! This is deliberately not [`crate::blocks`] or `instance_block`: those are the
//! instance's policy and every reader obeys them. A row here belongs to one account and
//! only hides its host from that account's timelines and notifications.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use nodus_server_core::Id;

use crate::blocks::bare_host;

/// One domain an account chose to stop reading.
#[derive(Debug, Clone)]
pub struct AccountDomainBlockRow {
    pub host: String,
    pub reject_media: bool,
    pub reject_reports: bool,
    pub created_at: DateTime<Utc>,
}

/// The flags Mastodon's v2 domain-block shape carries.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlockOptions {
    pub reject_media: bool,
    pub reject_reports: bool,
}

/// The domains `account_id` blocked, newest first.
pub async fn list(
    pool: &PgPool,
    account_id: &str,
) -> Result<Vec<AccountDomainBlockRow>, sqlx::Error> {
    sqlx::query_as::<_, (String, bool, bool, DateTime<Utc>)>(
        "SELECT host::text, reject_media, reject_reports, created_at \
         FROM account_domain_block WHERE account_id = $1 \
         ORDER BY created_at DESC, host",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(
                |(host, reject_media, reject_reports, created_at)| AccountDomainBlockRow {
                    host,
                    reject_media,
                    reject_reports,
                    created_at,
                },
            )
            .collect()
    })
}

/// Blocks `host` for `account_id`, or updates its flags if it was already blocked.
///
/// The host is normalised with [`bare_host`]; anything else is a programming error,
/// because the route has already refused it with an explanation.
pub async fn add(
    pool: &PgPool,
    account_id: &str,
    host: &str,
    options: BlockOptions,
) -> Result<(), sqlx::Error> {
    let host = bare_host(host)
        .ok_or_else(|| sqlx::Error::Protocol(format!("{host:?} is not a bare host name")))?;
    sqlx::query(
        "INSERT INTO account_domain_block \
             (id, account_id, host, reject_media, reject_reports) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (account_id, host) DO UPDATE SET \
             reject_media = EXCLUDED.reject_media, \
             reject_reports = EXCLUDED.reject_reports",
    )
    .bind(Id::new().to_string())
    .bind(account_id)
    .bind(host)
    .bind(options.reject_media)
    .bind(options.reject_reports)
    .execute(pool)
    .await?;
    Ok(())
}

/// Removes `host` from `account_id`'s list, returning whether a row went away.
pub async fn remove(pool: &PgPool, account_id: &str, host: &str) -> Result<bool, sqlx::Error> {
    let host = bare_host(host)
        .ok_or_else(|| sqlx::Error::Protocol(format!("{host:?} is not a bare host name")))?;
    let result =
        sqlx::query("DELETE FROM account_domain_block WHERE account_id = $1 AND host = $2")
            .bind(account_id)
            .bind(host)
            .execute(pool)
            .await?;
    Ok(result.rows_affected() > 0)
}

/// Whether `account_id` blocked `host`.
///
/// The timeline predicates ask this in SQL rather than per row; the standalone function
/// is for handlers and tests that hold one candidate host.
pub async fn blocks(pool: &PgPool, account_id: &str, host: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM account_domain_block \
         WHERE account_id = $1 AND host = $2)",
    )
    .bind(account_id)
    .bind(host)
    .fetch_one(pool)
    .await
}
