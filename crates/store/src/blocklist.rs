//! Carrying a block list between instances, and keeping it in step with a peer.
//!
//! A domain block is one row a moderator writes by hand; a block list is the same policy
//! written once and carried everywhere. Two shapes matter here. The export is a streamed
//! page of rows in a stable order, so an instance with a very large list does not have to
//! fit it in memory. The import is a classification *then* a write: every parsed row is
//! either new, a change to a row we already have, or identical to it, and only the first
//! two write — which is what makes a re-import of a list we already applied idle instead of
//! a storm of updates and audit rows.
//!
//! Nothing here deletes. An import or a subscription may add a block or widen one; a human
//! decides when a block comes off, because a peer with an empty list (or a peer that was
//! compromised) must not be able to unblock a domain on this instance.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{FromRow, PgConnection, PgPool};

use nodus_server_core::Id;

use crate::moderation;

/// The columns an export carries, in the order the CSV header names them.
const EXPORT_COLUMNS: &str = "domain::text AS domain, severity, reject_media, reject_reports, \
     reject_follows, public_comment AS comment, created_at";

/// One block as it travels.
///
/// `comment` is the export's name for `public_comment`: a list is read by a person, and
/// "comment" is the word a Mastodon export uses for the same field.
#[derive(Debug, Clone, FromRow)]
pub struct BlockExportRow {
    pub domain: String,
    pub severity: String,
    pub reject_media: bool,
    pub reject_reports: bool,
    pub reject_follows: bool,
    pub comment: String,
    pub created_at: DateTime<Utc>,
}

/// One parsed import row, borrowed from the payload.
#[derive(Debug, Clone)]
pub struct ImportRow<'a> {
    pub domain: &'a str,
    pub severity: &'a str,
    pub reject_media: bool,
    pub reject_reports: bool,
    pub reject_follows: bool,
    pub comment: &'a str,
}

/// What one row of an import turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    New,
    Updated,
    Unchanged,
}

/// The counts an import reports, whether or not it wrote.
#[derive(Debug, Clone, Copy, Default, serde::Serialize, PartialEq, Eq)]
pub struct Counts {
    pub new: usize,
    pub updated: usize,
    pub unchanged: usize,
}

impl Counts {
    pub fn record(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::New => self.new += 1,
            Outcome::Updated => self.updated += 1,
            Outcome::Unchanged => self.unchanged += 1,
        }
    }
}

/// Where an applied row came from, for the audit trail.
///
/// "A moderator imported the list" and "the subscription pulled it" are different facts
/// about the same block, and a moderator reviewing a block they did not write needs to
/// know which. The subscription id is the whole answer: the URL is one join away and does
/// not belong copied into every audit row.
#[derive(Debug, Clone, Copy)]
pub struct Source<'a> {
    pub subscription_id: Option<&'a str>,
}

impl Source<'_> {
    fn detail(self, severity: &str) -> serde_json::Value {
        match self.subscription_id {
            Some(id) => json!({
                "severity": severity,
                "source": "subscription",
                "subscription_id": id,
            }),
            None => json!({ "severity": severity, "source": "import" }),
        }
    }
}

/// One page of the block list, in domain order.
///
/// The order is the cursor: sorting by `created_at` while paging would let two rows that
/// share a timestamp swap places between pages and appear twice.
pub async fn export_page(
    pool: &PgPool,
    limit: i64,
    offset: i64,
) -> Result<Vec<BlockExportRow>, sqlx::Error> {
    let sql =
        format!("SELECT {EXPORT_COLUMNS} FROM instance_block ORDER BY domain LIMIT $1 OFFSET $2");
    sqlx::query_as(&sql)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
}

/// Every block whose domain is in `domains`, keyed by domain.
///
/// One query rather than one per row: an import of a few thousand domains would otherwise
/// be a few thousand round trips, and the classification needs the same answer either way.
pub async fn existing(
    conn: &mut PgConnection,
    domains: &[String],
) -> Result<HashMap<String, BlockExportRow>, sqlx::Error> {
    if domains.is_empty() {
        return Ok(HashMap::new());
    }
    let sql = format!("SELECT {EXPORT_COLUMNS} FROM instance_block WHERE domain = ANY($1::text[])");
    let rows: Vec<BlockExportRow> = sqlx::query_as(&sql).bind(domains).fetch_all(conn).await?;
    Ok(rows
        .into_iter()
        .map(|row| (row.domain.to_ascii_lowercase(), row))
        .collect())
}

/// Whether a parsed row would change the block we already have.
///
/// `created_at` is deliberately not compared: it is the peer's date for a row that already
/// exists here, and taking it over would rewrite history on every re-import. The identity
/// of a block is its domain; the rest is the policy.
fn outcome_for(old: Option<&BlockExportRow>, row: &ImportRow<'_>) -> Outcome {
    match old {
        None => Outcome::New,
        Some(old) => {
            if old.severity == row.severity
                && old.reject_media == row.reject_media
                && old.reject_reports == row.reject_reports
                && old.reject_follows == row.reject_follows
                && old.comment == row.comment
            {
                Outcome::Unchanged
            } else {
                Outcome::Updated
            }
        }
    }
}

/// Applies parsed rows, or only classifies them.
///
/// `dry_run` runs exactly the same classification against the same snapshot and writes
/// nothing, so the counts a preview shows are the counts the apply will report — a preview
/// computed by a different code path is a preview that can be wrong.
///
/// When it does write, everything goes in one transaction: the blocks and their audit rows
/// commit together, so a failure halfway through leaves neither a half-applied list nor an
/// audit trail describing changes that did not happen.
pub async fn import(
    pool: &PgPool,
    actor_id: &str,
    rows: &[ImportRow<'_>],
    source: Source<'_>,
    dry_run: bool,
) -> Result<Counts, sqlx::Error> {
    let domains: Vec<String> = rows
        .iter()
        .map(|row| row.domain.to_ascii_lowercase())
        .collect();
    let mut counts = Counts::default();
    if dry_run {
        let mut conn = pool.acquire().await?;
        let old = existing(&mut conn, &domains).await?;
        for row in rows {
            counts.record(outcome_for(old.get(&row.domain.to_ascii_lowercase()), row));
        }
        return Ok(counts);
    }

    let mut tx = pool.begin().await?;
    let old = existing(&mut tx, &domains).await?;
    for row in rows {
        let outcome = outcome_for(old.get(&row.domain.to_ascii_lowercase()), row);
        counts.record(outcome);
        let action = match outcome {
            Outcome::New => {
                sqlx::query(
                    "INSERT INTO instance_block (id, domain, severity, reject_media, \
                         reject_reports, obfuscate, public_comment, reject_follows) \
                     VALUES ($1, $2, $3, $4, $5, false, $6, $7)",
                )
                .bind(Id::new().to_string())
                .bind(row.domain)
                .bind(row.severity)
                .bind(row.reject_media)
                .bind(row.reject_reports)
                .bind(row.comment)
                .bind(row.reject_follows)
                .execute(&mut *tx)
                .await?;
                "create_domain_block"
            }
            Outcome::Updated => {
                sqlx::query(
                    "UPDATE instance_block SET severity = $2, reject_media = $3, \
                         reject_reports = $4, public_comment = $5, reject_follows = $6 \
                     WHERE domain = $1",
                )
                .bind(row.domain)
                .bind(row.severity)
                .bind(row.reject_media)
                .bind(row.reject_reports)
                .bind(row.comment)
                .bind(row.reject_follows)
                .execute(&mut *tx)
                .await?;
                "update_domain_block"
            }
            // An unchanged row is not a change: an audit row per re-imported line would
            // bury the entries a moderator actually needs to read.
            Outcome::Unchanged => continue,
        };
        moderation::audit_in_as(
            &mut tx,
            (!actor_id.is_empty()).then_some(actor_id),
            action,
            "domain",
            Some(row.domain),
            &source.detail(row.severity),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(counts)
}

// ---------------------------------------------------------------------------------------
// Subscriptions
// ---------------------------------------------------------------------------------------

/// A peer block list this instance keeps in step with.
#[derive(Debug, Clone, FromRow)]
pub struct SubscriptionRow {
    pub id: String,
    pub url: String,
    pub format: String,
    pub enabled: bool,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub last_synced_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
}

const SUBSCRIPTION_COLUMNS: &str = "id, url, format, enabled, etag, last_modified, \
     last_synced_at, last_error, created_at";

pub async fn subscriptions(pool: &PgPool) -> Result<Vec<SubscriptionRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {SUBSCRIPTION_COLUMNS} FROM domain_block_subscription ORDER BY created_at, id"
    );
    sqlx::query_as(&sql).fetch_all(pool).await
}

pub async fn subscription(pool: &PgPool, id: &str) -> Result<Option<SubscriptionRow>, sqlx::Error> {
    let sql = format!("SELECT {SUBSCRIPTION_COLUMNS} FROM domain_block_subscription WHERE id = $1");
    sqlx::query_as(&sql).bind(id).fetch_optional(pool).await
}

/// Adds a subscription, or `None` when the same URL is already subscribed.
///
/// The URL is the identity a moderator thinks in — subscribing twice to the same list would
/// mean two syncs racing over the same rows — so a repeat is a conflict, not a second row.
pub async fn create_subscription(
    pool: &PgPool,
    url: &str,
    format: &str,
) -> Result<Option<SubscriptionRow>, sqlx::Error> {
    let sql = format!(
        "INSERT INTO domain_block_subscription (id, url, format) VALUES ($1, $2, $3) \
         ON CONFLICT (url) DO NOTHING RETURNING {SUBSCRIPTION_COLUMNS}"
    );
    sqlx::query_as(&sql)
        .bind(Id::new().to_string())
        .bind(url)
        .bind(format)
        .fetch_optional(pool)
        .await
}

pub async fn delete_subscription(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query("DELETE FROM domain_block_subscription WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?
            .rows_affected()
            == 1,
    )
}

/// Enabled subscriptions that have waited long enough, oldest first.
///
/// `stale_after` is the interval the sweep works to; the query answers it rather than the
/// caller filtering a list, so a thousand subscriptions do not all get fetched to discard
/// most of them.
pub async fn due_subscriptions(
    pool: &PgPool,
    stale_after_seconds: i64,
    limit: i64,
) -> Result<Vec<SubscriptionRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {SUBSCRIPTION_COLUMNS} FROM domain_block_subscription \
         WHERE enabled AND (last_synced_at IS NULL OR last_synced_at < $1) \
         ORDER BY last_synced_at NULLS FIRST LIMIT $2"
    );
    // The cutoff is computed here rather than in SQL: `now() - make_interval(...)` would take
    // a float, and a seconds count does not need one.
    let cutoff = Utc::now() - chrono::Duration::seconds(stale_after_seconds);
    sqlx::query_as(&sql)
        .bind(cutoff)
        .bind(limit)
        .fetch_all(pool)
        .await
}

/// Records a sync that brought a body: the new validators, and that the peer answered.
pub async fn record_sync(
    pool: &PgPool,
    id: &str,
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE domain_block_subscription SET etag = $2, last_modified = $3, \
             last_synced_at = now(), last_error = NULL WHERE id = $1",
    )
    .bind(id)
    .bind(etag)
    .bind(last_modified)
    .execute(pool)
    .await?;
    Ok(())
}

/// Records a `304`.
///
/// The rows are not touched — the peer said the list is what we already have — but
/// `last_synced_at` moves: a poll that succeeded is evidence the subscription is alive, and
/// a console that shows "last synced: never" for a healthy list is telling the moderator the
/// opposite of the truth. The validators stay as they are; a `304` came with the same ones.
pub async fn record_unchanged(pool: &PgPool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE domain_block_subscription SET last_synced_at = now(), last_error = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Records a failure without touching the validators or the last good sync time.
///
/// The message is truncated to what a console row can show; a peer that answers with a
/// megabyte of HTML must not bloat the table.
pub async fn record_error(pool: &PgPool, id: &str, error: &str) -> Result<(), sqlx::Error> {
    let message: String = error.chars().take(500).collect();
    sqlx::query("UPDATE domain_block_subscription SET last_error = $2 WHERE id = $1")
        .bind(id)
        .bind(message)
        .execute(pool)
        .await?;
    Ok(())
}
