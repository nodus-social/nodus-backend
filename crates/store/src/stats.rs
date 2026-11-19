//! The numbers behind the moderation dashboard.
//!
//! Each section is one round trip: the console polls this view, and a page that costs ten
//! queries every sixty seconds is a page that competes with the request path. Counts are
//! `i64` and an empty median is `NULL`, so an instance with no history renders zeroes and
//! a dash rather than an error.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

/// Signups, people who posted, and posts — the shape of the window, not the backlog.
#[derive(Debug, Clone, FromRow)]
pub struct ActivityCounts {
    pub signups: i64,
    pub active_accounts: i64,
    pub posts: i64,
}

pub async fn activity(
    pool: &PgPool,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Result<ActivityCounts, sqlx::Error> {
    sqlx::query_as(
        "SELECT \
             (SELECT count(*) FROM account a \
               WHERE a.local AND a.created_at >= $1 AND a.created_at < $2)::bigint AS signups, \
             (SELECT count(DISTINCT s.account_id) FROM status s \
                JOIN account a ON a.id = s.account_id \
               WHERE a.local AND s.deleted_at IS NULL \
                 AND s.created_at >= $1 AND s.created_at < $2)::bigint AS active_accounts, \
             (SELECT count(*) FROM status s \
               WHERE s.deleted_at IS NULL \
                 AND s.created_at >= $1 AND s.created_at < $2)::bigint AS posts",
    )
    .bind(since)
    .bind(until)
    .fetch_one(pool)
    .await
}

/// The report queue in the window, plus the backlog that is still open now.
#[derive(Debug, Clone, FromRow)]
pub struct ReportCounts {
    pub opened: i64,
    pub resolved: i64,
    pub reopened: i64,
    pub pending: i64,
}

pub async fn reports(
    pool: &PgPool,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Result<ReportCounts, sqlx::Error> {
    sqlx::query_as(
        "SELECT \
             (SELECT count(*) FROM report r \
               WHERE r.created_at >= $1 AND r.created_at < $2)::bigint AS opened, \
             (SELECT count(DISTINCT a.target_id) FROM audit_log a \
               WHERE a.target_type = 'report' \
                 AND a.action IN ('resolve_report', 'resolve_report_with_note') \
                 AND a.created_at >= $1 AND a.created_at < $2)::bigint AS resolved, \
             (SELECT count(*) FROM audit_log a \
               WHERE a.target_type = 'report' AND a.action = 'reopen_report' \
                 AND a.created_at >= $1 AND a.created_at < $2)::bigint AS reopened, \
             (SELECT count(*) FROM report r WHERE r.state = 'open')::bigint AS pending",
    )
    .bind(since)
    .bind(until)
    .fetch_one(pool)
    .await
}

/// How moderators actually decided, by the action they took on an account.
#[derive(Debug, Clone, FromRow)]
pub struct DecisionCounts {
    pub approve: i64,
    pub reject: i64,
    pub silence: i64,
    pub suspend: i64,
    pub enable: i64,
}

pub async fn decisions(
    pool: &PgPool,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Result<DecisionCounts, sqlx::Error> {
    sqlx::query_as(
        "SELECT \
             count(*) FILTER (WHERE action = 'account_approve')::bigint AS approve, \
             count(*) FILTER (WHERE action = 'account_reject')::bigint AS reject, \
             count(*) FILTER (WHERE action = 'account_silence')::bigint AS silence, \
             count(*) FILTER (WHERE action = 'account_suspend')::bigint AS suspend, \
             count(*) FILTER (WHERE action = 'account_enable')::bigint AS enable \
           FROM audit_log \
          WHERE target_type = 'account' \
            AND action IN ('account_approve', 'account_reject', 'account_silence', \
                           'account_suspend', 'account_enable') \
            AND created_at >= $1 AND created_at < $2",
    )
    .bind(since)
    .bind(until)
    .fetch_one(pool)
    .await
}

/// Seconds from a report being opened to the moderator's resolve audit row.
///
/// One row per report (`DISTINCT ON`) so a report that was reopened and resolved again
/// contributes its first resolution, not every attempt. `NULL` when the window holds no
/// resolution — `percentile_cont` of an empty set is `NULL`, which is the honest answer.
pub async fn median_time_to_decision(
    pool: &PgPool,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Result<Option<f64>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT percentile_cont(0.5) WITHIN GROUP ( \
                    ORDER BY extract(epoch FROM (resolved.created_at - report.created_at))) \
                AS seconds \
           FROM report \
           JOIN (SELECT DISTINCT ON (a.target_id) a.target_id, a.created_at \
                   FROM audit_log a \
                  WHERE a.target_type = 'report' \
                    AND a.action IN ('resolve_report', 'resolve_report_with_note') \
                    AND a.created_at >= $1 AND a.created_at < $2 \
                  ORDER BY a.target_id, a.created_at) resolved \
             ON resolved.target_id = report.id",
    )
    .bind(since)
    .bind(until)
    .fetch_one(pool)
    .await
}

/// A reporter with the handle the console shows.
#[derive(Debug, Clone, FromRow)]
pub struct ReporterCount {
    pub account_id: String,
    pub username: String,
    pub domain: Option<String>,
    pub count: i64,
}

pub async fn top_reporters(
    pool: &PgPool,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Result<Vec<ReporterCount>, sqlx::Error> {
    sqlx::query_as(
        "SELECT a.id AS account_id, a.username::text AS username, a.domain::text AS domain, \
                count(*)::bigint AS count \
           FROM report r JOIN account a ON a.id = r.account_id \
          WHERE r.created_at >= $1 AND r.created_at < $2 \
          GROUP BY a.id, a.username, a.domain \
          ORDER BY count(*) DESC, a.id \
          LIMIT 10",
    )
    .bind(since)
    .bind(until)
    .fetch_all(pool)
    .await
}

/// The remote domains whose accounts were reported most in the window.
#[derive(Debug, Clone, FromRow)]
pub struct DomainCount {
    pub domain: String,
    pub count: i64,
}

pub async fn top_reported_domains(
    pool: &PgPool,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Result<Vec<DomainCount>, sqlx::Error> {
    sqlx::query_as(
        "SELECT a.domain::text AS domain, count(*)::bigint AS count \
           FROM report r JOIN account a ON a.id = r.target_account_id \
          WHERE a.domain IS NOT NULL \
            AND r.created_at >= $1 AND r.created_at < $2 \
          GROUP BY a.domain \
          ORDER BY count(*) DESC, a.domain \
          LIMIT 10",
    )
    .bind(since)
    .bind(until)
    .fetch_all(pool)
    .await
}

/// What the scanners have in flight and what they have caught.
#[derive(Debug, Clone, FromRow)]
pub struct ScannerCounts {
    pub queued: i64,
    pub flagged: i64,
    pub quarantined: i64,
}

pub async fn scanners(pool: &PgPool) -> Result<ScannerCounts, sqlx::Error> {
    sqlx::query_as(
        "SELECT \
             (SELECT count(*) FROM scan WHERE state IN ('pending', 'running'))::bigint AS queued, \
             (SELECT count(*) FROM scan_flag WHERE state = 'open')::bigint AS flagged, \
             ((SELECT count(*) FROM media_attachment \
                  WHERE quarantine_state = 'quarantined') \
              + (SELECT count(*) FROM status WHERE quarantined_at IS NOT NULL))::bigint \
                 AS quarantined",
    )
    .fetch_one(pool)
    .await
}
