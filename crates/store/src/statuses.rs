//! Statuses and the two timeline lanes.
//!
//! The home timeline is a union, not a single scan: statuses of ordinary accounts are
//! materialised into `timeline_entry` by the `fan_out` worker, while accounts above
//! [`BIG_ACCOUNT_THRESHOLD`] are merged at read time. Both lanes are ordered by the
//! same id and deduped, so a status that crosses the threshold never appears twice.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};

use nodus_server_core::limits::BIG_ACCOUNT_THRESHOLD;
use nodus_server_core::{PageParams, PageSize};

/// A row of `status`, as the timeline queries return it.
#[derive(Debug, Clone, FromRow)]
pub struct StatusRow {
    pub id: String,
    pub account_id: String,
    pub uri: Option<String>,
    pub content: String,
    pub content_html: String,
    pub content_source: Option<String>,
    pub content_format: String,
    pub spoiler_text: String,
    pub visibility: String,
    pub sensitive: bool,
    pub in_reply_to_id: Option<String>,
    pub in_reply_to_account_id: Option<String>,
    pub reblog_of_id: Option<String>,
    pub language: Option<String>,
    pub local: bool,
    pub edited_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub favourites_count: i64,
    pub reblogs_count: i64,
    pub replies_count: i64,
}

const STATUS_COLUMNS: &str = "s.id, s.account_id, s.uri, s.content, s.content_html, \
     s.content_source, s.content_format, s.spoiler_text, s.visibility, s.sensitive, s.in_reply_to_id, s.in_reply_to_account_id, \
     s.reblog_of_id, s.language, s.local, s.edited_at, s.created_at, \
     s.favourites_count, s.reblogs_count, s.replies_count";

/// A page of statuses, newest first.
#[derive(Debug, Clone)]
pub struct StatusPage {
    pub items: Vec<StatusRow>,
    /// The cursor for the next page: present only when another page exists, because a
    /// `Link` header on the last page makes clients loop on an empty response.
    pub next_max_id: Option<String>,
}

/// One status by id, tombstoned rows excluded.
pub async fn by_id(pool: &PgPool, id: &str) -> Result<Option<StatusRow>, sqlx::Error> {
    let sql =
        format!("SELECT {STATUS_COLUMNS} FROM status s WHERE s.id = $1 AND s.deleted_at IS NULL");
    sqlx::query_as::<_, StatusRow>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// `/api/v1/timelines/public`: public visibility only.
///
/// `local_only` is the default the app asks for (`public:local`); the federated view
/// adds remote statuses once federation exists.
pub async fn public_page(
    pool: &PgPool,
    params: PageParams,
    local_only: bool,
) -> Result<StatusPage, sqlx::Error> {
    let size = PageSize::default_max(params.limit);
    let sql = format!(
        "SELECT {STATUS_COLUMNS} FROM status s \
         WHERE s.deleted_at IS NULL AND s.visibility = 'public' \
           AND ($1::text IS NULL OR s.id < $1) \
           AND (NOT $2 OR s.local) \
         ORDER BY s.id DESC LIMIT $3"
    );
    let rows = sqlx::query_as::<_, StatusRow>(&sql)
        .bind(params.max_id.map(|id| id.to_string()))
        .bind(local_only)
        .bind(size.as_i64() + 1)
        .fetch_all(pool)
        .await?;
    Ok(finish(rows, size))
}

/// `GET /users/{username}/outbox`: local, publicly addressable statuses by one author.
///
/// Direct and followers-only posts are absent, not merely filtered by the caller. An
/// outbox is a protocol surface a stranger can read, so the visibility predicate is in
/// the query that every other outbox reader uses.
pub async fn account_page(
    pool: &PgPool,
    account_id: &str,
    params: PageParams,
) -> Result<StatusPage, sqlx::Error> {
    let size = PageSize::default_max(params.limit);
    let sql = format!(
        "SELECT {STATUS_COLUMNS} FROM status s \
         WHERE s.account_id = $1 AND s.deleted_at IS NULL \
           AND s.visibility IN ('public', 'unlisted') \
           AND ($2::text IS NULL OR s.id < $2) \
         ORDER BY s.id DESC LIMIT $3"
    );
    let rows = sqlx::query_as::<_, StatusRow>(&sql)
        .bind(account_id)
        .bind(params.max_id.map(|id| id.to_string()))
        .bind(size.as_i64() + 1)
        .fetch_all(pool)
        .await?;
    Ok(finish(rows, size))
}

/// `/api/v1/timelines/home`: the materialised lane union the big-account lane.
///
/// Direct messages are excluded here and served by the notifications path: they reach
/// their mentions, not the follower timeline.
pub async fn home_page(
    pool: &PgPool,
    account_id: &str,
    params: PageParams,
) -> Result<StatusPage, sqlx::Error> {
    let size = PageSize::default_max(params.limit);
    let sql = format!(
        "SELECT {STATUS_COLUMNS} FROM timeline_entry e \
           JOIN status s ON s.id = e.status_id \
          WHERE e.account_id = $1 AND e.kind = 'home' AND s.deleted_at IS NULL \
            AND ($2::text IS NULL OR s.id < $2) \
         UNION \
         SELECT {STATUS_COLUMNS} FROM status s \
          WHERE s.account_id IN ( \
                  SELECT f.target_account_id FROM follow f \
                    JOIN account a ON a.id = f.target_account_id \
                   WHERE f.account_id = $1 AND a.followers_count >= $4) \
            AND s.deleted_at IS NULL AND s.visibility <> 'direct' \
            AND ($2::text IS NULL OR s.id < $2) \
         ORDER BY id DESC LIMIT $3"
    );
    let rows = sqlx::query_as::<_, StatusRow>(&sql)
        .bind(account_id)
        .bind(params.max_id.map(|id| id.to_string()))
        .bind(size.as_i64() + 1)
        .bind(BIG_ACCOUNT_THRESHOLD)
        .fetch_all(pool)
        .await?;
    Ok(finish(rows, size))
}

/// A status being written. `id` is minted by the caller so the same id can be used for
/// the entry rows the fan-out writes.
#[derive(Debug, Clone)]
pub struct NewStatus<'a> {
    pub id: &'a str,
    pub account_id: &'a str,
    pub content: &'a str,
    pub content_html: &'a str,
    pub content_source: Option<&'a str>,
    pub content_format: &'a str,
    pub spoiler_text: &'a str,
    pub visibility: &'a str,
    pub sensitive: bool,
    pub in_reply_to_id: Option<&'a str>,
    pub in_reply_to_account_id: Option<&'a str>,
    pub reblog_of_id: Option<&'a str>,
    pub language: Option<&'a str>,
}

/// Inserts a local status and returns it exactly as a timeline would.
/// Soft-deletes a status owned by `account_id`.
pub async fn delete_owned(
    pool: &PgPool,
    status_id: &str,
    account_id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE status SET deleted_at = now()          WHERE id = $1 AND account_id = $2 AND deleted_at IS NULL",
    )
    .bind(status_id)
    .bind(account_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn insert(pool: &PgPool, new: &NewStatus<'_>) -> Result<StatusRow, sqlx::Error> {
    let sql = format!(
        "INSERT INTO status (id, account_id, content, content_html, content_source, \
                             content_format, spoiler_text, visibility, sensitive, \
                             in_reply_to_id, in_reply_to_account_id, reblog_of_id, \
                             language, local) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, true) \
         RETURNING {STATUS_COLUMNS_SIMPLE}"
    );
    sqlx::query_as::<_, StatusRow>(&sql)
        .bind(new.id)
        .bind(new.account_id)
        .bind(new.content)
        .bind(new.content_html)
        .bind(new.content_source)
        .bind(new.content_format)
        .bind(new.spoiler_text)
        .bind(new.visibility)
        .bind(new.sensitive)
        .bind(new.in_reply_to_id)
        .bind(new.in_reply_to_account_id)
        .bind(new.reblog_of_id)
        .bind(new.language)
        .fetch_one(pool)
        .await
}

/// `RETURNING` cannot carry the `s.` alias the page queries use.
const STATUS_COLUMNS_SIMPLE: &str = "id, account_id, uri, content, content_html, \
     content_source, content_format, spoiler_text, visibility, sensitive, in_reply_to_id, in_reply_to_account_id, \
     reblog_of_id, language, local, edited_at, created_at, \
     favourites_count, reblogs_count, replies_count";

/// A reaction and how many accounts chose it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, FromRow)]
pub struct ReactionCount {
    pub reaction: String,
    pub count: i64,
}

/// Adds or replaces one account's reaction on a status.
///
/// Misskey allows one reaction per account per note, so a second call replaces
/// the first rather than adding a second row.
pub async fn set_reaction(
    pool: &PgPool,
    status_id: &str,
    account_id: &str,
    reaction: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO status_reaction (status_id, account_id, reaction) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (status_id, account_id) \
         DO UPDATE SET reaction = EXCLUDED.reaction, created_at = now()",
    )
    .bind(status_id)
    .bind(account_id)
    .bind(reaction)
    .execute(pool)
    .await?;
    Ok(())
}

/// Removes an account's reaction, if it has one.
pub async fn remove_reaction(
    pool: &PgPool,
    status_id: &str,
    account_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM status_reaction WHERE status_id = $1 AND account_id = $2")
        .bind(status_id)
        .bind(account_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Reaction counts for one status, most common first.
pub async fn reactions(pool: &PgPool, status_id: &str) -> Result<Vec<ReactionCount>, sqlx::Error> {
    sqlx::query_as::<_, ReactionCount>(
        "SELECT reaction, COUNT(*)::bigint AS count \
           FROM status_reaction WHERE status_id = $1 \
          GROUP BY reaction ORDER BY count DESC, reaction ASC",
    )
    .bind(status_id)
    .fetch_all(pool)
    .await
}

/// Truncates to the page size and reports the cursor when more rows exist.
///
/// One extra row is fetched on purpose: asking for `limit + 1` is how a server knows
/// whether a next page exists without a second `COUNT(*)`.
fn finish(mut rows: Vec<StatusRow>, size: PageSize) -> StatusPage {
    let limit = usize::try_from(size.get()).unwrap_or(usize::from(u16::MAX));
    let next_max_id = if rows.len() > limit {
        rows.truncate(limit);
        rows.last().map(|row| row.id.clone())
    } else {
        None
    };
    StatusPage {
        items: rows,
        next_max_id,
    }
}
