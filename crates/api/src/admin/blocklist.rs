//! Block lists that leave the instance and block lists that arrive from a peer.
//!
//! Two operations, one policy: a domain block is a decision an administrator makes once and
//! should not have to retype on the next instance, and a published list is a decision
//! somebody else already made that this instance may want to follow. Both are the same row,
//! so both go through [`nodus_server_store::blocklist`] — the export reads it a page at a
//! time, the import classifies every line before it writes any of them, and a subscription
//! is that import on a clock.
//!
//! The import never deletes. A list may add a block or widen one; a domain comes off only
//! when a person here takes it off, because a peer with an empty list — or a peer that has
//! been taken over — must not be able to unblock a domain on this instance.

use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use nodus_server_store::blocklist::{
    self, BlockExportRow, Counts, ImportRow, Source, SubscriptionRow,
};

use crate::activitypub::validate_remote_url;
use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::remote;
use crate::state::AppState;

use super::{csv_cell, Body};

// ---------------------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------------------

/// How many blocks one streamed chunk carries.
///
/// The export exists to be carried to another instance, not to sit in a `String`: each page
/// is formatted as it is read and dropped once the body has it, so a list of fifty thousand
/// blocks costs one page of memory, not fifty thousand rows.
const EXPORT_PAGE: i64 = 500;

/// The columns, in the order both formats write them.
///
/// `comment` is the store's name for `public_comment`; `created_at` travels because a
/// receiving instance may want to show when a block was made, and dropping it would make
/// the export lossy in a way nothing warns about.
const EXPORT_HEADER: &str =
    "domain,severity,reject_media,reject_reports,reject_follows,comment,created_at\r\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Csv,
    Json,
}

impl Format {
    fn parse(raw: Option<&str>) -> ApiResult<Self> {
        match raw.unwrap_or("csv").trim().to_ascii_lowercase().as_str() {
            "csv" => Ok(Self::Csv),
            "json" => Ok(Self::Json),
            _ => Err(ApiError::unprocessable("format is either csv or json")),
        }
    }

    fn from_stored(raw: &str) -> Option<Self> {
        match raw {
            "csv" => Some(Self::Csv),
            "json" => Some(Self::Json),
            _ => None,
        }
    }

    fn accept(self) -> &'static str {
        match self {
            Self::Csv => "text/csv",
            Self::Json => "application/json",
        }
    }

    fn content_type(self) -> &'static str {
        match self {
            Self::Csv => "text/csv; charset=utf-8",
            Self::Json => "application/json; charset=utf-8",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    format: Option<String>,
}

fn csv_row(row: &BlockExportRow) -> String {
    let cells = [
        csv_cell(&row.domain),
        csv_cell(&row.severity),
        csv_cell(if row.reject_media { "true" } else { "false" }),
        csv_cell(if row.reject_reports { "true" } else { "false" }),
        csv_cell(if row.reject_follows { "true" } else { "false" }),
        csv_cell(&row.comment),
        csv_cell(&row.created_at.to_rfc3339()),
    ];
    let mut line = cells.join(",");
    line.push_str("\r\n");
    line
}

fn json_row(row: &BlockExportRow) -> String {
    json!({
        "domain": row.domain,
        "severity": row.severity,
        "reject_media": row.reject_media,
        "reject_reports": row.reject_reports,
        "reject_follows": row.reject_follows,
        "comment": row.comment,
        "created_at": row.created_at.to_rfc3339(),
    })
    .to_string()
}

/// What the stream carries between chunks: the format, and how far it has read.
struct ExportCursor {
    pool: sqlx::PgPool,
    format: Format,
    offset: i64,
    opened: bool,
    body_done: bool,
    closed: bool,
    first_row: bool,
}

fn export_chunk(cursor: &mut ExportCursor, rows: &[BlockExportRow]) -> String {
    let mut chunk = String::new();
    for row in rows {
        match cursor.format {
            Format::Csv => chunk.push_str(&csv_row(row)),
            Format::Json => {
                if !cursor.first_row {
                    chunk.push_str(",\r\n");
                }
                cursor.first_row = false;
                chunk.push_str(&json_row(row));
            }
        }
    }
    chunk
}

/// `GET /api/v1/admin/domain-blocks/export` — the block list as a file.
///
/// Both formats are paged by domain and streamed; the JSON body is the array Mastodon's
/// importer expects, assembled the same way so a large instance does not build it in one
/// allocation.
async fn export(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<ExportQuery>,
) -> ApiResult<Response> {
    auth.require_admin("admin:read")?;
    let format = Format::parse(query.format.as_deref())?;
    let cursor = ExportCursor {
        pool: state.store().pool().clone(),
        format,
        offset: 0,
        opened: false,
        body_done: false,
        closed: false,
        first_row: true,
    };
    let stream = futures_util::stream::unfold(cursor, |mut cursor| async move {
        if !cursor.opened {
            cursor.opened = true;
            let head = match cursor.format {
                Format::Csv => EXPORT_HEADER.to_owned(),
                Format::Json => "[\r\n".to_owned(),
            };
            return Some((Ok::<Bytes, std::io::Error>(Bytes::from(head)), cursor));
        }
        if !cursor.body_done {
            match blocklist::export_page(&cursor.pool, EXPORT_PAGE, cursor.offset).await {
                // A failed read has to break the transfer: a stream that ends quietly would
                // hand the console a truncated list that looks complete, and a truncated
                // list is worse than none — it silently drops blocks.
                Err(error) => {
                    tracing::error!(error = %error, "domain block export read failed");
                    return Some((
                        Err::<Bytes, std::io::Error>(std::io::Error::other(
                            "domain block export read failed",
                        )),
                        cursor,
                    ));
                }
                Ok(rows) => {
                    if rows.is_empty()
                        || i64::try_from(rows.len()).unwrap_or(i64::MAX) < EXPORT_PAGE
                    {
                        cursor.body_done = true;
                    }
                    cursor.offset += i64::try_from(rows.len()).unwrap_or(i64::MAX);
                    let chunk = export_chunk(&mut cursor, &rows);
                    if !chunk.is_empty() {
                        return Some((Ok::<Bytes, std::io::Error>(Bytes::from(chunk)), cursor));
                    }
                }
            }
        }
        if !cursor.closed {
            cursor.closed = true;
            if cursor.format == Format::Json {
                return Some((
                    Ok::<Bytes, std::io::Error>(Bytes::from_static(b"]\r\n")),
                    cursor,
                ));
            }
        }
        None
    });
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, format.content_type())
        .header(
            header::CONTENT_DISPOSITION,
            format!(
                "attachment; filename=\"domain-blocks.{}\"",
                match format {
                    Format::Csv => "csv",
                    Format::Json => "json",
                }
            ),
        )
        .body(axum::body::Body::from_stream(stream))
        .map_err(|error| {
            tracing::error!(error = %error, "domain block export response failed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not build the export",
            )
        })?;
    Ok(response)
}

// ---------------------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------------------

/// The largest payload an import will read.
///
/// A block list is a few hundred domains; five megabytes is thousands of lines and still a
/// size that can be parsed in one request. The cap is a refusal, not a truncation: half an
/// applied list is a policy nobody chose.
const IMPORT_MAX_BYTES: usize = 5 * 1024 * 1024;

/// The largest number of lines an import will consider, so a payload of tiny rows cannot
/// turn one request into a hundred thousand queries.
const IMPORT_MAX_ROWS: usize = 50_000;

#[derive(Debug, Deserialize)]
pub struct ImportQuery {
    dry_run: Option<bool>,
}

/// One line the parser could not use, and why.
///
/// The line number is what makes a 3 000-line import fixable: a moderator edits that line
/// and re-imports instead of hunting through the file.
#[derive(Debug, Serialize)]
pub struct InvalidLine {
    line: usize,
    reason: String,
}

#[derive(Debug, Serialize)]
pub struct ImportReport {
    parsed: usize,
    new: usize,
    updated: usize,
    unchanged: usize,
    invalid: Vec<InvalidLine>,
}

/// A parsed line, owned, ready to be borrowed as an [`ImportRow`].
#[derive(Debug)]
struct Record {
    domain: String,
    severity: String,
    reject_media: bool,
    reject_reports: bool,
    reject_follows: bool,
    comment: String,
}

/// A parsed payload: the rows we can apply, and the lines we cannot.
struct Parsed {
    rows: Vec<Record>,
    invalid: Vec<InvalidLine>,
}

/// A domain as a block names it: a bare hostname.
fn check_domain(domain: &str) -> Result<(), String> {
    if domain.is_empty() {
        return Err("the domain is empty".to_owned());
    }
    if domain.contains('/') || domain.contains(' ') || domain.contains('@') {
        return Err(
            "a domain is a bare hostname like example.com, with no scheme, path or user".to_owned(),
        );
    }
    if !domain.contains('.') {
        return Err("a domain needs a dot, like example.com".to_owned());
    }
    Ok(())
}

fn check_severity(severity: &str) -> Result<(), String> {
    match severity {
        "suspend" | "silence" => Ok(()),
        _ => Err("severity is either suspend or silence".to_owned()),
    }
}

fn parse_flag(raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "false" | "0" | "no" => Ok(false),
        "true" | "1" | "yes" => Ok(true),
        _ => Err(format!("{raw:?} is not true or false")),
    }
}

/// Splits CSV into records, keeping the line each record started on.
///
/// RFC 4180 quoting: a quoted field may hold commas, doubled quotes and newlines, and the
/// newline inside it does not start a new record — which is why this cannot be
/// `text.lines().map(split(','))`. Blank lines are returned and skipped by the caller.
fn csv_records(text: &str) -> Vec<(usize, Vec<String>)> {
    let mut records = Vec::new();
    let mut fields: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut line = 1_usize;
    let mut record_line = 1_usize;
    let mut touched = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            match c {
                '"' => {
                    if chars.peek() == Some(&'"') {
                        field.push('"');
                        chars.next();
                    } else {
                        quoted = false;
                    }
                }
                '\n' => {
                    field.push('\n');
                    line += 1;
                }
                _ => field.push(c),
            }
            continue;
        }
        match c {
            '"' if field.is_empty() => {
                quoted = true;
                touched = true;
            }
            ',' => {
                fields.push(std::mem::take(&mut field));
                touched = true;
            }
            '\r' | '\n' => {
                if c == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                }
                fields.push(std::mem::take(&mut field));
                records.push((record_line, std::mem::take(&mut fields)));
                line += 1;
                record_line = line;
                touched = false;
            }
            _ => {
                field.push(c);
                touched = true;
            }
        }
    }
    if touched || !field.is_empty() || !fields.is_empty() {
        fields.push(field);
        records.push((record_line, fields));
    }
    records
}

/// Where a named column sits, case-insensitively.
fn column(header: &[String], name: &str) -> Option<usize> {
    header
        .iter()
        .position(|cell| cell.trim().eq_ignore_ascii_case(name))
}

fn record_from_fields(fields: &[String], columns: &Columns) -> Result<Record, String> {
    let cell = |index: Option<usize>| -> &str {
        index
            .and_then(|index| fields.get(index))
            .map_or("", String::as_str)
    };
    let domain = cell(columns.domain).trim().to_ascii_lowercase();
    check_domain(&domain)?;
    let severity = match cell(columns.severity).trim().to_ascii_lowercase() {
        value if value.is_empty() => "suspend".to_owned(),
        value => value,
    };
    check_severity(&severity)?;
    let reject_media = parse_flag(cell(columns.reject_media))
        .map_err(|reason| format!("reject_media: {reason}"))?;
    let reject_reports = parse_flag(cell(columns.reject_reports))
        .map_err(|reason| format!("reject_reports: {reason}"))?;
    let reject_follows = parse_flag(cell(columns.reject_follows))
        .map_err(|reason| format!("reject_follows: {reason}"))?;
    Ok(Record {
        domain,
        severity,
        reject_media,
        reject_reports,
        reject_follows,
        comment: cell(columns.comment).trim().to_owned(),
    })
}

/// The column positions of a CSV import.
struct Columns {
    domain: Option<usize>,
    severity: Option<usize>,
    reject_media: Option<usize>,
    reject_reports: Option<usize>,
    reject_follows: Option<usize>,
    comment: Option<usize>,
}

impl Columns {
    fn from_header(header: &[String]) -> Option<Self> {
        let domain = column(header, "domain")?;
        Some(Self {
            domain: Some(domain),
            severity: column(header, "severity"),
            reject_media: column(header, "reject_media"),
            reject_reports: column(header, "reject_reports"),
            reject_follows: column(header, "reject_follows"),
            comment: column(header, "comment").or_else(|| column(header, "public_comment")),
        })
    }
}

fn parse_csv(text: &str) -> ApiResult<Parsed> {
    let mut records = csv_records(text).into_iter();
    let Some((_, header)) = records.next() else {
        return Err(ApiError::unprocessable(
            "an import needs a header line naming its columns",
        ));
    };
    // A header is the only thing that says which column is which: without it the same file
    // is a list of commas, and guessing would apply the wrong field to the wrong flag.
    let columns = Columns::from_header(&header).ok_or_else(|| {
        ApiError::unprocessable(
            "an import needs a header line naming its columns, starting with domain",
        )
    })?;
    let mut parsed = Parsed {
        rows: Vec::new(),
        invalid: Vec::new(),
    };
    for (line, fields) in records {
        if fields.iter().all(|field| field.trim().is_empty()) {
            continue;
        }
        if parsed.rows.len() + parsed.invalid.len() >= IMPORT_MAX_ROWS {
            return Err(ApiError::unprocessable(
                "an import is at most 50 000 lines; split the list",
            ));
        }
        match record_from_fields(&fields, &columns) {
            Ok(record) => parsed.rows.push(record),
            Err(reason) => parsed.invalid.push(InvalidLine { line, reason }),
        }
    }
    Ok(parsed)
}

fn parse_json(text: &str) -> ApiResult<Parsed> {
    let values: Vec<serde_json::Value> = serde_json::from_str(text).map_err(|error| {
        ApiError::unprocessable(format!("a JSON import is an array of objects: {error}"))
    })?;
    let mut parsed = Parsed {
        rows: Vec::new(),
        invalid: Vec::new(),
    };
    for (index, value) in values.into_iter().enumerate() {
        // JSON has no lines; the index is the line number a re-import can be edited
        // against, and a re-import of a corrected file reports the same number.
        let line = index + 1;
        if parsed.rows.len() + parsed.invalid.len() >= IMPORT_MAX_ROWS {
            return Err(ApiError::unprocessable(
                "an import is at most 50 000 lines; split the list",
            ));
        }
        let Some(object) = value.as_object() else {
            parsed.invalid.push(InvalidLine {
                line,
                reason: "each entry is an object like {\"domain\": \"example.com\"}".to_owned(),
            });
            continue;
        };
        let mut fields = Vec::new();
        // The same order as the CSV path, so one validator covers both.
        let columns = Columns {
            domain: Some(0),
            severity: Some(1),
            reject_media: Some(2),
            reject_reports: Some(3),
            reject_follows: Some(4),
            comment: Some(5),
        };
        fields.push(match object.get("domain") {
            Some(serde_json::Value::String(domain)) => domain.clone(),
            Some(other) => other.to_string(),
            None => String::new(),
        });
        fields.push(match object.get("severity") {
            Some(serde_json::Value::String(severity)) => severity.clone(),
            Some(other) => other.to_string(),
            None => String::new(),
        });
        let flag = |key: &str| match object.get(key) {
            None => String::new(),
            Some(serde_json::Value::Bool(value)) => value.to_string(),
            Some(serde_json::Value::Number(value)) => value.to_string(),
            Some(serde_json::Value::String(value)) => value.clone(),
            Some(other) => other.to_string(),
        };
        fields.push(flag("reject_media"));
        fields.push(flag("reject_reports"));
        fields.push(flag("reject_follows"));
        fields.push(match object.get("comment") {
            Some(serde_json::Value::String(comment)) => comment.clone(),
            Some(other) => other.to_string(),
            None => String::new(),
        });
        match record_from_fields(&fields, &columns) {
            Ok(record) => parsed.rows.push(record),
            Err(reason) => parsed.invalid.push(InvalidLine { line, reason }),
        }
    }
    Ok(parsed)
}

fn parse_payload(text: &str) -> ApiResult<Parsed> {
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        return parse_json(trimmed);
    }
    parse_csv(text)
}

/// `POST /api/v1/admin/domain-blocks/import` — apply a list, or say what applying it would do.
///
/// The same call is a preview and an apply: `dry_run=true` runs the identical classification
/// and writes nothing, so the numbers a moderator sees before committing are the numbers
/// they get after.
async fn import(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<ImportQuery>,
    body: Bytes,
) -> ApiResult<Json<ImportReport>> {
    auth.require_admin("admin:write")?;
    if body.len() > IMPORT_MAX_BYTES {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "an import is at most 5 MB; split the list",
        ));
    }
    let text = std::str::from_utf8(&body)
        .map_err(|_| ApiError::unprocessable("an import must be UTF-8 text"))?;
    let dry_run = query.dry_run.unwrap_or(false);
    let parsed = parse_payload(text)?;
    let rows: Vec<ImportRow<'_>> = parsed
        .rows
        .iter()
        .map(|record| ImportRow {
            domain: &record.domain,
            severity: &record.severity,
            reject_media: record.reject_media,
            reject_reports: record.reject_reports,
            reject_follows: record.reject_follows,
            comment: &record.comment,
        })
        .collect();
    let counts = blocklist::import(
        state.store().pool(),
        &auth.0.account.id,
        &rows,
        Source {
            subscription_id: None,
        },
        dry_run,
    )
    .await?;
    Ok(Json(report(
        parsed.rows.len() + parsed.invalid.len(),
        counts,
        parsed.invalid,
    )))
}

fn report(parsed: usize, counts: Counts, invalid: Vec<InvalidLine>) -> ImportReport {
    ImportReport {
        parsed,
        new: counts.new,
        updated: counts.updated,
        unchanged: counts.unchanged,
        invalid,
    }
}

// ---------------------------------------------------------------------------------------
// Subscriptions
// ---------------------------------------------------------------------------------------

/// How long a subscription may go un-synced before the sweep picks it up.
///
/// A published block list changes when the peer decides to change it, not on a schedule of
/// ours; six hours is often enough to notice a raid and rare enough that a peer sees a few
/// requests a day. `If-None-Match` makes the common case one `304` and no body.
const SYNC_STALE_SECONDS: i64 = 6 * 60 * 60;

/// How often the sweep looks for one that is due.
const SYNC_TICK: Duration = Duration::from_secs(600);

/// How many subscriptions one sweep syncs, so a slow peer cannot hold the loop for hours.
const SYNC_BATCH: i64 = 10;

/// How long one list download may take.
const SYNC_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Serialize)]
pub struct SubscriptionDto {
    id: String,
    url: String,
    format: String,
    enabled: bool,
    etag: Option<String>,
    last_modified: Option<String>,
    last_synced_at: Option<chrono::DateTime<chrono::Utc>>,
    last_error: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<SubscriptionRow> for SubscriptionDto {
    fn from(row: SubscriptionRow) -> Self {
        Self {
            id: row.id,
            url: row.url,
            format: row.format,
            enabled: row.enabled,
            etag: row.etag,
            last_modified: row.last_modified,
            last_synced_at: row.last_synced_at,
            last_error: row.last_error,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SubscriptionForm {
    url: String,
    #[serde(default = "default_format")]
    format: String,
}

fn default_format() -> String {
    "csv".to_owned()
}

/// The URL a subscription is allowed to name.
///
/// The same guard the federation path uses: `https` only, no credentials, a host that is a
/// name rather than an address, and not a private one. The address is checked again at fetch
/// time, where the resolution is pinned — a host whose DNS changes after the subscription is
/// created must not be able to point us at `127.0.0.1`.
fn check_subscription(url: &str, format: &str) -> ApiResult<(String, String)> {
    let parsed = validate_remote_url(url.trim()).map_err(|_| {
        ApiError::unprocessable(
            "a subscription URL must be a public https URL, with no credentials in it",
        )
    })?;
    let format = format.trim().to_ascii_lowercase();
    if Format::from_stored(&format).is_none() {
        return Err(ApiError::unprocessable("format is either csv or json"));
    }
    Ok((parsed.to_string(), format))
}

async fn list_subscriptions(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<Vec<SubscriptionDto>>> {
    auth.require_admin("admin:read")?;
    let rows = blocklist::subscriptions(state.store().pool()).await?;
    Ok(Json(rows.into_iter().map(SubscriptionDto::from).collect()))
}

async fn create_subscription(
    State(state): State<AppState>,
    auth: Auth,
    Body(form): Body<SubscriptionForm>,
) -> ApiResult<Json<SubscriptionDto>> {
    auth.require_admin("admin:write")?;
    let (url, format) = check_subscription(&form.url, &form.format)?;
    let row = blocklist::create_subscription(state.store().pool(), &url, &format)
        .await?
        .ok_or_else(|| ApiError::unprocessable("that URL is already subscribed"))?;
    super::audit_write_detail(
        &state,
        &auth,
        "create_domain_block_subscription",
        "domain_block_subscription",
        &row.id,
        json!({ "url": row.url, "format": row.format }),
    )
    .await?;
    Ok(Json(SubscriptionDto::from(row)))
}

async fn delete_subscription(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    auth.require_admin("admin:write")?;
    let row = blocklist::subscription(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that subscription does not exist"))?;
    if !blocklist::delete_subscription(state.store().pool(), &id).await? {
        return Err(ApiError::not_found("that subscription does not exist"));
    }
    super::audit_write_detail(
        &state,
        &auth,
        "delete_domain_block_subscription",
        "domain_block_subscription",
        &id,
        json!({ "url": row.url }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// What one pull produced.
#[derive(Debug, Serialize)]
pub struct SyncReport {
    /// `applied` when the peer sent a list, `not_modified` when it answered `304`.
    status: &'static str,
    parsed: usize,
    new: usize,
    updated: usize,
    unchanged: usize,
    invalid: usize,
}

/// The largest list one sync will read.
const SYNC_MAX_BYTES: usize = 5 * 1024 * 1024;

/// Reads a body with a hard ceiling, reporting the reason instead of growing without bound.
async fn read_capped(response: &mut reqwest::Response, max: usize) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > max as u64)
    {
        return Err("the list is larger than 5 MB".to_owned());
    }
    let mut body: Vec<u8> = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > max {
                    return Err("the list is larger than 5 MB".to_owned());
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(error) => return Err(format!("the peer stopped mid-list: {error}")),
        }
    }
    Ok(body)
}

/// Pulls one subscription and applies it.
///
/// Every failure is a recorded `last_error` and a returned `ApiError`: a peer that is down,
/// a host that resolves somewhere private, a body that is not a list. None of them is a
/// reason to stop the worker, and none of them may touch the rows we already have.
async fn pull(
    state: &AppState,
    row: &SubscriptionRow,
) -> ApiResult<(SyncReport, Vec<InvalidLine>)> {
    let pool = state.store().pool();
    let Some(format) = Format::from_stored(&row.format) else {
        let reason = format!("stored format {:?} is not csv or json", row.format);
        blocklist::record_error(pool, &row.id, &reason).await?;
        return Err(ApiError::new(StatusCode::BAD_GATEWAY, reason));
    };
    // The guard again, now that there is a host to resolve: this is where a private address
    // and a host that no longer resolves are refused.
    let client = match remote::outbound_client(&row.url, SYNC_TIMEOUT).await {
        Ok(client) => client,
        Err(error) => {
            // Not a bad request from the moderator: the peer or its DNS is the problem.
            let reason = format!("could not reach the list host: {}", error.message());
            blocklist::record_error(pool, &row.id, &reason).await?;
            return Err(ApiError::new(StatusCode::BAD_GATEWAY, reason));
        }
    };
    let mut request = client.get(&row.url).header(header::ACCEPT, format.accept());
    if let Some(etag) = row.etag.as_deref() {
        request = request.header(header::IF_NONE_MATCH, etag);
    }
    if let Some(modified) = row.last_modified.as_deref() {
        request = request.header(header::IF_MODIFIED_SINCE, modified);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => {
            let reason = format!("could not reach the list: {error}");
            blocklist::record_error(pool, &row.id, &reason).await?;
            return Err(ApiError::new(StatusCode::BAD_GATEWAY, reason));
        }
    };
    // An unchanged list costs one status line: the peer compares the validators and says so.
    // `last_synced_at` moves anyway, because a poll that succeeded is the only evidence the
    // subscription is alive, and a console that shows it as never synced would be lying.
    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        blocklist::record_unchanged(pool, &row.id).await?;
        return Ok((
            SyncReport {
                status: "not_modified",
                parsed: 0,
                new: 0,
                updated: 0,
                unchanged: 0,
                invalid: 0,
            },
            Vec::new(),
        ));
    }
    if !response.status().is_success() {
        let reason = format!("the peer answered {}", response.status());
        blocklist::record_error(pool, &row.id, &reason).await?;
        return Err(ApiError::new(StatusCode::BAD_GATEWAY, reason));
    }
    let etag = response
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let last_modified = response
        .headers()
        .get(header::LAST_MODIFIED)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut response = response;
    let body = match read_capped(&mut response, SYNC_MAX_BYTES).await {
        Ok(body) => body,
        Err(reason) => {
            blocklist::record_error(pool, &row.id, &reason).await?;
            return Err(ApiError::new(StatusCode::BAD_GATEWAY, reason));
        }
    };
    let Ok(text) = std::str::from_utf8(&body) else {
        let reason = "the list is not UTF-8 text".to_owned();
        blocklist::record_error(pool, &row.id, &reason).await?;
        return Err(ApiError::new(StatusCode::BAD_GATEWAY, reason));
    };
    apply_body(pool, row, text, etag.as_deref(), last_modified.as_deref()).await
}

/// The body a peer sent, parsed and applied.
///
/// Split out of `pull` so the status handling reads top-down: a body is only worth parsing
/// once the peer has answered 200 with something that looks like a list.
async fn apply_body(
    pool: &sqlx::PgPool,
    row: &SubscriptionRow,
    text: &str,
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> ApiResult<(SyncReport, Vec<InvalidLine>)> {
    let parsed = match parse_payload(text) {
        Ok(parsed) => parsed,
        Err(error) => {
            // The moderator subscribed; the peer sent something else. That is a gateway
            // problem, and the row says so until the next pull.
            let reason = format!("the list could not be read: {}", error.message());
            blocklist::record_error(pool, &row.id, &reason).await?;
            return Err(ApiError::new(StatusCode::BAD_GATEWAY, reason));
        }
    };
    let rows: Vec<ImportRow<'_>> = parsed
        .rows
        .iter()
        .map(|record| ImportRow {
            domain: &record.domain,
            severity: &record.severity,
            reject_media: record.reject_media,
            reject_reports: record.reject_reports,
            reject_follows: record.reject_follows,
            comment: &record.comment,
        })
        .collect();
    // The subscription is written down as the source, so a block nobody here remembers
    // adding still has an answer in the audit trail.
    let counts = blocklist::import(
        pool,
        "",
        &rows,
        Source {
            subscription_id: Some(&row.id),
        },
        false,
    )
    .await?;
    // Recorded only after the rows committed: a peer that sent a list we could not apply
    // must be retried, not skipped until the next time it changes.
    blocklist::record_sync(pool, &row.id, etag, last_modified).await?;
    Ok((
        SyncReport {
            status: "applied",
            parsed: parsed.rows.len() + parsed.invalid.len(),
            new: counts.new,
            updated: counts.updated,
            unchanged: counts.unchanged,
            invalid: parsed.invalid.len(),
        },
        parsed.invalid,
    ))
}

/// `POST /api/v1/admin/domain-blocks/subscriptions/{id}/sync` — pull one now.
async fn sync_subscription(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<SyncReport>> {
    auth.require_admin("admin:write")?;
    let row = blocklist::subscription(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("that subscription does not exist"))?;
    let (report, _invalid) = pull(&state, &row).await?;
    Ok(Json(report))
}

/// Syncs the subscriptions that are due, one at a time.
///
/// Sequentially on purpose: a handful of peers is not worth the concurrency, and one slow
/// list then delays the others by seconds rather than holding a pool connection each.
async fn sweep(state: &AppState) -> ApiResult<usize> {
    let rows =
        blocklist::due_subscriptions(state.store().pool(), SYNC_STALE_SECONDS, SYNC_BATCH).await?;
    let mut synced = 0;
    for row in &rows {
        match pull(state, row).await {
            Ok((report, _invalid)) => {
                synced += 1;
                tracing::info!(
                    subscription = %row.id,
                    url = %row.url,
                    status = report.status,
                    new = report.new,
                    updated = report.updated,
                    "block list subscription synced"
                );
            }
            // `pull` already recorded the reason on the row; the loop keeps going, because
            // one unreachable peer is not a reason to skip the rest.
            Err(error) => tracing::warn!(
                subscription = %row.id,
                url = %row.url,
                error = %error.message(),
                "block list subscription failed"
            ),
        }
    }
    Ok(synced)
}

/// The periodic half: sync what is due, on a clock, in the process that already serves.
pub async fn run(state: AppState) {
    let mut ticker = tokio::time::interval(SYNC_TICK);
    // The first tick fires immediately; skipping it keeps startup cheap, and a subscription
    // is due within one tick anyway.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        match sweep(&state).await {
            Ok(0) => {}
            Ok(count) => tracing::info!(count, "block list subscriptions synced"),
            Err(error) => tracing::warn!(error = %error.message(), "block list sweep failed"),
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/domain-blocks/export", get(export))
        // The body is a file, not a form: `Bytes` reads it whole, so the limit has to be
        // raised past axum's 2 MB default or a legitimate list is refused before the
        // handler can say why.
        .route(
            "/api/v1/admin/domain-blocks/import",
            post(import).layer(DefaultBodyLimit::max(IMPORT_MAX_BYTES)),
        )
        .route(
            "/api/v1/admin/domain-blocks/subscriptions",
            get(list_subscriptions).post(create_subscription),
        )
        .route(
            "/api/v1/admin/domain-blocks/subscriptions/{id}",
            delete(delete_subscription),
        )
        .route(
            "/api/v1/admin/domain-blocks/subscriptions/{id}/sync",
            post(sync_subscription),
        )
}
