//! Content scanners, what they are configured to do, and what they found.
//!
//! A scanner is an external service the instance trusts with one kind of content — an
//! image, a video, a piece of text. It reports labels and confidence; it never decides
//! policy. This module owns the registry, the per-label rules that turn a label into a
//! severity, the content sets an administrator supplies, the durable scan queue and the
//! review queue a verdict feeds. It never makes an HTTP request: the sweep calls
//! [`claim`], does the work, and reports back through [`finish`] or [`fail`].

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgPool};

use nodus_server_core::Id;

// ---------------------------------------------------------------------------------------
// Content sets
// ---------------------------------------------------------------------------------------

/// A set of hashes, words or weights an administrator supplied. The instance stores the
/// bytes and the digest; it never reads the contents.
#[derive(Debug, Clone, FromRow)]
pub struct AssetRow {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub digest: String,
    pub size: i64,
    pub content_type: String,
    pub created_at: DateTime<Utc>,
}

const ASSET_COLUMNS: &str = "id, name, kind, digest, size, content_type, created_at";

#[derive(Debug, Clone)]
pub struct NewAsset<'a> {
    pub name: &'a str,
    pub kind: &'a str,
    pub digest: &'a str,
    pub size: i64,
    pub content_type: &'a str,
    pub content: &'a [u8],
}

pub async fn assets(pool: &PgPool) -> Result<Vec<AssetRow>, sqlx::Error> {
    let sql =
        format!("SELECT {ASSET_COLUMNS} FROM scanner_asset ORDER BY created_at DESC LIMIT 100");
    sqlx::query_as(&sql).fetch_all(pool).await
}

pub async fn asset(pool: &PgPool, id: &str) -> Result<Option<AssetRow>, sqlx::Error> {
    let sql = format!("SELECT {ASSET_COLUMNS} FROM scanner_asset WHERE id = $1");
    sqlx::query_as(&sql).bind(id).fetch_optional(pool).await
}

/// Registers a set. Uploading the same bytes twice is the same set: the digest decides.
pub async fn create_asset(pool: &PgPool, new: &NewAsset<'_>) -> Result<AssetRow, sqlx::Error> {
    let sql = format!(
        "INSERT INTO scanner_asset (id, name, kind, digest, size, content_type, content) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (digest) DO UPDATE SET name = EXCLUDED.name \
         RETURNING {ASSET_COLUMNS}"
    );
    sqlx::query_as(&sql)
        .bind(Id::new().to_string())
        .bind(new.name)
        .bind(new.kind)
        .bind(new.digest)
        .bind(new.size)
        .bind(new.content_type)
        .bind(new.content)
        .fetch_one(pool)
        .await
}

pub async fn delete_asset(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM scanner_asset WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected()
        == 1)
}

/// The bytes themselves. Only a scanner service asks for these, and only for the set its
/// own row points at, so no endpoint exposes another node's content.
pub async fn asset_bytes(pool: &PgPool, id: &str) -> Result<Option<Vec<u8>>, sqlx::Error> {
    sqlx::query_scalar::<_, Vec<u8>>("SELECT content FROM scanner_asset WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn asset_in_use(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM scanner WHERE asset_id = $1)")
        .bind(id)
        .fetch_one(pool)
        .await
}

/// `(name, content)` for every set of one `kind`, oldest first — the order an
/// administrator registered them in, which is the order a matcher should report hits in.
///
/// Separate from [`assets`] because the bytes are up to sixty-four megabytes each and a
/// listing almost never wants them: only the caller that is about to parse the sets asks
/// for the contents.
pub async fn assets_of_kind(
    pool: &PgPool,
    kind: &str,
) -> Result<Vec<(String, Vec<u8>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT name, content FROM scanner_asset WHERE kind = $1 ORDER BY created_at ASC",
    )
    .bind(kind)
    .fetch_all(pool)
    .await
}

// ---------------------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, FromRow)]
pub struct ScannerRow {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub endpoint: String,
    pub secret: Option<String>,
    pub enabled: bool,
    pub asset_id: Option<String>,
    pub contract: i32,
    pub labels: Vec<String>,
    pub manifest: Value,
    pub manifest_at: Option<DateTime<Utc>>,
    pub timeout_ms: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const SCANNER_COLUMNS: &str = "id, name, kind, endpoint, secret, enabled, asset_id, contract, \
     labels, manifest, manifest_at, timeout_ms, created_at, updated_at";

#[derive(Debug, Clone)]
pub struct NewScanner<'a> {
    pub name: &'a str,
    pub kind: &'a str,
    pub endpoint: &'a str,
    pub secret: Option<&'a str>,
    pub enabled: bool,
    pub asset_id: Option<&'a str>,
    pub timeout_ms: i32,
}

pub async fn scanners(pool: &PgPool) -> Result<Vec<ScannerRow>, sqlx::Error> {
    let sql = format!("SELECT {SCANNER_COLUMNS} FROM scanner ORDER BY created_at DESC LIMIT 100");
    sqlx::query_as(&sql).fetch_all(pool).await
}

pub async fn scanner(pool: &PgPool, id: &str) -> Result<Option<ScannerRow>, sqlx::Error> {
    let sql = format!("SELECT {SCANNER_COLUMNS} FROM scanner WHERE id = $1");
    sqlx::query_as(&sql).bind(id).fetch_optional(pool).await
}

/// Enabled scanners for one kind. A scanner with no rules still appears here; the sweep
/// asks it and then has nothing to apply, which is what "unconfigured does nothing" means.
pub async fn enabled(pool: &PgPool, kind: &str) -> Result<Vec<ScannerRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {SCANNER_COLUMNS} FROM scanner WHERE enabled AND kind = $1 ORDER BY created_at"
    );
    sqlx::query_as(&sql).bind(kind).fetch_all(pool).await
}

pub async fn create_scanner(
    pool: &PgPool,
    new: &NewScanner<'_>,
) -> Result<ScannerRow, sqlx::Error> {
    let sql = format!(
        "INSERT INTO scanner (id, name, kind, endpoint, secret, enabled, asset_id, timeout_ms) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING {SCANNER_COLUMNS}"
    );
    sqlx::query_as(&sql)
        .bind(Id::new().to_string())
        .bind(new.name)
        .bind(new.kind)
        .bind(new.endpoint)
        .bind(new.secret)
        .bind(new.enabled)
        .bind(new.asset_id)
        .bind(new.timeout_ms)
        .fetch_one(pool)
        .await
}

pub async fn update_scanner(
    pool: &PgPool,
    id: &str,
    new: &NewScanner<'_>,
) -> Result<Option<ScannerRow>, sqlx::Error> {
    let sql = format!(
        "UPDATE scanner SET name = $2, kind = $3, endpoint = $4, secret = $5, enabled = $6, \
             asset_id = $7, timeout_ms = $8, updated_at = now() \
         WHERE id = $1 RETURNING {SCANNER_COLUMNS}"
    );
    sqlx::query_as(&sql)
        .bind(id)
        .bind(new.name)
        .bind(new.kind)
        .bind(new.endpoint)
        .bind(new.secret)
        .bind(new.enabled)
        .bind(new.asset_id)
        .bind(new.timeout_ms)
        .fetch_optional(pool)
        .await
}

/// Records what the scanner said it can do. Called on registration and on refresh: a
/// changed label vocabulary is visible in the console instead of quietly altering what the
/// rules match.
pub async fn record_manifest(
    pool: &PgPool,
    id: &str,
    contract: i32,
    labels: &[String],
    manifest: &Value,
) -> Result<Option<ScannerRow>, sqlx::Error> {
    let sql = format!(
        "UPDATE scanner SET contract = $2, labels = $3, manifest = $4, manifest_at = now(), \
             updated_at = now() WHERE id = $1 RETURNING {SCANNER_COLUMNS}"
    );
    sqlx::query_as(&sql)
        .bind(id)
        .bind(contract)
        .bind(labels)
        .bind(manifest)
        .fetch_optional(pool)
        .await
}

pub async fn delete_scanner(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM scanner WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected()
        == 1)
}

// ---------------------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------------------

/// What one label means on this instance. Severity is the administrator's call; without a
/// rule a label is reported and ignored.
#[derive(Debug, Clone, FromRow)]
pub struct RuleRow {
    pub id: String,
    pub scanner_id: String,
    pub label: String,
    pub threshold: f64,
    pub severity: String,
    pub created_at: DateTime<Utc>,
}

const RULE_COLUMNS: &str = "id, scanner_id, label, threshold, severity, created_at";

pub async fn rules(pool: &PgPool, scanner_id: &str) -> Result<Vec<RuleRow>, sqlx::Error> {
    let sql =
        format!("SELECT {RULE_COLUMNS} FROM scanner_rule WHERE scanner_id = $1 ORDER BY label");
    sqlx::query_as(&sql).bind(scanner_id).fetch_all(pool).await
}

pub async fn rules_all(pool: &PgPool) -> Result<Vec<RuleRow>, sqlx::Error> {
    let sql = format!("SELECT {RULE_COLUMNS} FROM scanner_rule ORDER BY scanner_id, label");
    sqlx::query_as(&sql).fetch_all(pool).await
}

/// One rule per (scanner, label): saving the form twice edits the rule rather than
/// stacking a second one behind it.
pub async fn upsert_rule(
    pool: &PgPool,
    scanner_id: &str,
    label: &str,
    threshold: f64,
    severity: &str,
) -> Result<RuleRow, sqlx::Error> {
    let sql = format!(
        "INSERT INTO scanner_rule (id, scanner_id, label, threshold, severity) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (scanner_id, label) DO UPDATE SET threshold = EXCLUDED.threshold, \
             severity = EXCLUDED.severity \
         RETURNING {RULE_COLUMNS}"
    );
    sqlx::query_as(&sql)
        .bind(Id::new().to_string())
        .bind(scanner_id)
        .bind(label)
        .bind(threshold)
        .bind(severity)
        .fetch_one(pool)
        .await
}

pub async fn delete_rule(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM scanner_rule WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected()
        == 1)
}

// ---------------------------------------------------------------------------------------
// Queue
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, FromRow)]
pub struct ScanRow {
    pub id: String,
    pub scanner_id: String,
    pub kind: String,
    pub subject_type: String,
    pub subject_id: String,
    pub url: Option<String>,
    pub text: Option<String>,
    pub mime: Option<String>,
    pub state: String,
    pub score: Option<f32>,
    pub labels: Vec<String>,
    pub detail: Value,
    pub error: Option<String>,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

const SCAN_COLUMNS: &str = "id, scanner_id, kind, subject_type, subject_id, url, text, mime, \
     state, score, labels, detail, error, attempts, created_at, finished_at";

/// Queues one scan per enabled scanner of `kind` for one subject. A duplicate subject is
/// not an error: the first queue entry already covers it.
pub async fn enqueue_for(
    pool: &PgPool,
    kind: &str,
    subject_type: &str,
    subject_id: &str,
    url: Option<&str>,
    text: Option<&str>,
    mime: Option<&str>,
) -> Result<u64, sqlx::Error> {
    let configured = enabled(pool, kind).await?;
    let mut queued = 0;
    for scanner in configured {
        queued += sqlx::query(
            "INSERT INTO scan (id, scanner_id, kind, subject_type, subject_id, url, text, mime) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (scanner_id, subject_type, subject_id) DO NOTHING",
        )
        .bind(Id::new().to_string())
        .bind(&scanner.id)
        .bind(kind)
        .bind(subject_type)
        .bind(subject_id)
        .bind(url)
        .bind(text)
        .bind(mime)
        .execute(pool)
        .await?
        .rows_affected();
    }
    Ok(queued)
}

/// Leases up to `limit` scans. A lease that expired is claimable again: the sweep that
/// took it died, and the verdict it never produced is still wanted.
pub async fn claim(
    pool: &PgPool,
    limit: i64,
    lease_seconds: i64,
) -> Result<Vec<ScanRow>, sqlx::Error> {
    let sql = format!(
        "UPDATE scan SET state = 'running', attempts = attempts + 1, \
             locked_until = now() + ($2 || ' seconds')::interval \
         WHERE id IN ( \
             SELECT id FROM scan \
             WHERE (state = 'pending' OR (state = 'running' AND locked_until < now())) \
                 AND attempts < 5 \
             ORDER BY created_at \
             FOR UPDATE SKIP LOCKED \
             LIMIT $1 \
         ) RETURNING {SCAN_COLUMNS}"
    );
    sqlx::query_as(&sql)
        .bind(limit)
        .bind(lease_seconds)
        .fetch_all(pool)
        .await
}

/// Subjects that have never been queued for this kind of scanner.
///
/// The sweep asks for these on every tick, so a status posted while the service was down is
/// picked up when it returns instead of being skipped forever. `limit` bounds the burst.
pub async fn unqueued_statuses(
    pool: &PgPool,
    kind: &str,
    limit: i64,
) -> Result<Vec<(String, String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT s.id, s.content, s.spoiler_text FROM status s \
         WHERE s.local AND s.deleted_at IS NULL \
           AND EXISTS (SELECT 1 FROM scanner sc WHERE sc.enabled AND sc.kind = $1) \
           AND NOT EXISTS ( \
               SELECT 1 FROM scan x JOIN scanner sc ON sc.id = x.scanner_id \
               WHERE x.subject_type = 'status' AND x.subject_id = s.id AND sc.kind = $1 \
           ) \
         ORDER BY s.created_at DESC LIMIT $2",
    )
    .bind(kind)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Media attachments that have never been queued for a scanner of this kind.
pub async fn unqueued_media(
    pool: &PgPool,
    kind: &str,
    limit: i64,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT m.id, m.content_type FROM media_attachment m \
         WHERE NOT m.remote \
           AND (CASE WHEN $2 = 'video' THEN m.content_type LIKE 'video/%' \
                     ELSE m.content_type LIKE 'image/%' END) \
           AND EXISTS (SELECT 1 FROM scanner sc WHERE sc.enabled AND sc.kind = $2) \
           AND NOT EXISTS ( \
               SELECT 1 FROM scan x JOIN scanner sc ON sc.id = x.scanner_id \
               WHERE x.subject_type = 'media' AND x.subject_id = m.id AND sc.kind = $2 \
           ) \
         ORDER BY m.created_at DESC LIMIT $1",
    )
    .bind(limit)
    .bind(kind)
    .fetch_all(pool)
    .await
}

/// The queue as a moderator sees it: newest first, optionally filtered by state.
pub async fn scans(
    pool: &PgPool,
    state: Option<&str>,
    limit: i64,
) -> Result<Vec<ScanRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {SCAN_COLUMNS} FROM scan \
         WHERE $1::text IS NULL OR state = $1 \
         ORDER BY created_at DESC LIMIT $2"
    );
    sqlx::query_as(&sql)
        .bind(state)
        .bind(limit)
        .fetch_all(pool)
        .await
}

pub async fn finish(
    pool: &PgPool,
    id: &str,
    score: Option<f32>,
    labels: &[String],
    detail: &Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE scan SET state = 'done', score = $2, labels = $3, detail = $4, error = NULL, \
             locked_until = NULL, finished_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(score)
    .bind(labels)
    .bind(detail)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn fail(pool: &PgPool, id: &str, error: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE scan SET state = CASE WHEN attempts >= 5 THEN 'failed' ELSE 'pending' END, \
             error = $2, locked_until = NULL, \
             finished_at = CASE WHEN attempts >= 5 THEN now() ELSE NULL END \
         WHERE id = $1",
    )
    .bind(id)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}

/// What a scan is about: the status a moderator would look at, and whose it is. A media
/// scan resolves through the attachment, because the post it belongs to is what gets
/// acted on.
#[derive(Debug, Clone, FromRow)]
pub struct SubjectRow {
    pub status_id: Option<String>,
    pub account_id: Option<String>,
}

pub async fn subject(
    pool: &PgPool,
    subject_type: &str,
    subject_id: &str,
) -> Result<Option<SubjectRow>, sqlx::Error> {
    let sql = if subject_type == "media" {
        "SELECT status_id, account_id FROM media_attachment WHERE id = $1"
    } else {
        "SELECT id AS status_id, account_id FROM status WHERE id = $1"
    };
    sqlx::query_as(sql)
        .bind(subject_id)
        .fetch_optional(pool)
        .await
}

// ---------------------------------------------------------------------------------------
// Review queue
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, FromRow)]
pub struct FlagRow {
    pub id: String,
    pub scan_id: String,
    pub status_id: Option<String>,
    pub account_id: Option<String>,
    pub reason: String,
    pub score: Option<f32>,
    pub labels: Vec<String>,
    pub severity: String,
    pub state: String,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

const FLAG_COLUMNS: &str = "id, scan_id, status_id, account_id, reason, score, labels, severity, \
     state, resolved_by, resolved_at, created_at";

/// Records a verdict worth a human's attention. One row per scan, so a scanner that runs
/// twice on the same content does not double the review queue.
pub async fn raise_flag(
    pool: &PgPool,
    scan: &ScanRow,
    status_id: Option<&str>,
    account_id: Option<&str>,
    reason: &str,
    severity: &str,
) -> Result<Option<FlagRow>, sqlx::Error> {
    let sql = format!(
        "INSERT INTO scan_flag (id, scan_id, status_id, account_id, reason, score, labels, \
             severity) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (scan_id) DO NOTHING RETURNING {FLAG_COLUMNS}"
    );
    sqlx::query_as(&sql)
        .bind(Id::new().to_string())
        .bind(&scan.id)
        .bind(status_id)
        .bind(account_id)
        .bind(reason)
        .bind(scan.score)
        .bind(&scan.labels)
        .bind(severity)
        .fetch_optional(pool)
        .await
}

pub async fn flags(
    pool: &PgPool,
    state: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<FlagRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {FLAG_COLUMNS} FROM scan_flag \
         WHERE ($1::text IS NULL OR state = $1) ORDER BY created_at DESC LIMIT $2 OFFSET $3"
    );
    sqlx::query_as(&sql)
        .bind(state)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
}

pub async fn flag(pool: &PgPool, id: &str) -> Result<Option<FlagRow>, sqlx::Error> {
    let sql = format!("SELECT {FLAG_COLUMNS} FROM scan_flag WHERE id = $1");
    sqlx::query_as(&sql).bind(id).fetch_optional(pool).await
}

pub async fn open_flags(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*)::bigint FROM scan_flag WHERE state = 'open'")
        .fetch_one(pool)
        .await
}

pub async fn resolve_flag(
    pool: &PgPool,
    id: &str,
    state: &str,
    actor_id: &str,
) -> Result<Option<FlagRow>, sqlx::Error> {
    let sql = format!(
        "UPDATE scan_flag SET state = $2, resolved_by = $3, resolved_at = now() WHERE id = $1 \
         RETURNING {FLAG_COLUMNS}"
    );
    sqlx::query_as(&sql)
        .bind(id)
        .bind(state)
        .bind(actor_id)
        .fetch_optional(pool)
        .await
}

/// The scans behind one subject, newest first: what a moderator sees when asking "why was
/// this flagged?".
pub async fn for_subject(
    pool: &PgPool,
    subject_type: &str,
    subject_id: &str,
) -> Result<Vec<ScanRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {SCAN_COLUMNS} FROM scan WHERE subject_type = $1 AND subject_id = $2 \
         ORDER BY created_at DESC LIMIT 50"
    );
    sqlx::query_as(&sql)
        .bind(subject_type)
        .bind(subject_id)
        .fetch_all(pool)
        .await
}
