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
use nodus_server_core::{PageOrder, PageParams, PageSize};

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

/// One status by its canonical `ActivityPub` URI.
pub async fn by_uri(pool: &PgPool, uri: &str) -> Result<Option<StatusRow>, sqlx::Error> {
    let sql =
        format!("SELECT {STATUS_COLUMNS} FROM status s WHERE s.uri = $1 AND s.deleted_at IS NULL");
    sqlx::query_as::<_, StatusRow>(&sql)
        .bind(uri)
        .fetch_optional(pool)
        .await
}

/// A remote note learned from an inbound activity.
#[derive(Debug, Clone)]
pub struct NewRemoteStatus<'a> {
    pub id: &'a str,
    pub account_id: &'a str,
    pub uri: &'a str,
    pub content: &'a str,
    pub content_html: &'a str,
    pub spoiler_text: &'a str,
    pub sensitive: bool,
    pub in_reply_to_id: Option<&'a str>,
    pub in_reply_to_account_id: Option<&'a str>,
    pub created_at: DateTime<Utc>,
}

/// Inserts or refreshes a remote note, keyed by its canonical URI.
pub async fn upsert_remote(
    pool: &PgPool,
    new: &NewRemoteStatus<'_>,
) -> Result<StatusRow, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let sql = format!(
        "INSERT INTO status (id, account_id, uri, content, content_html, spoiler_text, \
             visibility, sensitive, in_reply_to_id, in_reply_to_account_id, local, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'public', $7, $8, $9, false, $10) \
         ON CONFLICT (uri) DO UPDATE SET content = EXCLUDED.content, \
             content_html = EXCLUDED.content_html, spoiler_text = EXCLUDED.spoiler_text, \
             sensitive = EXCLUDED.sensitive, edited_at = now() \
         RETURNING {STATUS_COLUMNS_SIMPLE}"
    );
    let row = sqlx::query_as::<_, StatusRow>(&sql)
        .bind(new.id)
        .bind(new.account_id)
        .bind(new.uri)
        .bind(new.content)
        .bind(new.content_html)
        .bind(new.spoiler_text)
        .bind(new.sensitive)
        .bind(new.in_reply_to_id)
        .bind(new.in_reply_to_account_id)
        .bind(new.created_at)
        .fetch_one(&mut *tx)
        .await?;
    if let Some(parent_id) = new.in_reply_to_id {
        refresh_replies_count(&mut tx, parent_id).await?;
    }
    tx.commit().await?;
    Ok(row)
}

/// Soft-deletes a remote status by URI.
pub async fn delete_remote(pool: &PgPool, uri: &str) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let deleted: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "UPDATE status SET deleted_at = now() \
          WHERE uri = $1 AND deleted_at IS NULL \
          RETURNING id, in_reply_to_id, reblog_of_id",
    )
    .bind(uri)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((status_id, in_reply_to_id, reblog_of_id)) = deleted else {
        return Ok(false);
    };
    cleanup_deleted_status(
        &mut tx,
        &status_id,
        in_reply_to_id.as_deref(),
        reblog_of_id.as_deref(),
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

fn page_bounds(params: PageParams) -> (Option<String>, Option<String>, &'static str) {
    let max_id = params.max_id.map(|id| id.to_string());
    let lower_id = params.lower_bound().map(|id| id.to_string());
    let order = match params.order() {
        PageOrder::NewestFirst => "DESC",
        PageOrder::OldestFirst => "ASC",
    };
    (max_id, lower_id, order)
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
    let (max_id, lower_id, order) = page_bounds(params);
    let sql = format!(
        "SELECT {STATUS_COLUMNS} FROM status s \
           JOIN account a ON a.id = s.account_id \
         WHERE s.deleted_at IS NULL AND s.visibility = 'public' \
           AND a.suspended_at IS NULL AND a.silenced_at IS NULL \
           AND NOT EXISTS (SELECT 1 FROM instance_block b WHERE b.domain = a.domain \
                           AND b.severity IN ('suspend', 'silence')) \
           AND ($1::text IS NULL OR s.id < $1) \
           AND ($2::text IS NULL OR s.id > $2) \
           AND (NOT $3 OR s.local) \
         ORDER BY s.id {order} LIMIT $4"
    );
    let rows = sqlx::query_as::<_, StatusRow>(&sql)
        .bind(max_id)
        .bind(lower_id)
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
    let (max_id, lower_id, order) = page_bounds(params);
    let sql = format!(
        "SELECT {STATUS_COLUMNS} FROM status s \
         WHERE s.account_id = $1 AND s.deleted_at IS NULL \
           AND s.visibility IN ('public', 'unlisted') \
           AND ($2::text IS NULL OR s.id < $2) \
           AND ($3::text IS NULL OR s.id > $3) \
         ORDER BY s.id {order} LIMIT $4"
    );
    let rows = sqlx::query_as::<_, StatusRow>(&sql)
        .bind(account_id)
        .bind(max_id)
        .bind(lower_id)
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
    let (max_id, lower_id, order) = page_bounds(params);
    let sql = format!(
        "SELECT {STATUS_COLUMNS} FROM timeline_entry e \
           JOIN status s ON s.id = e.status_id \
           JOIN account a ON a.id = s.account_id \
          WHERE e.account_id = $1 AND e.kind = 'home' AND s.deleted_at IS NULL \
            AND a.suspended_at IS NULL AND a.silenced_at IS NULL \
            AND NOT EXISTS (SELECT 1 FROM account_relation r WHERE r.account_id = $1 \
                            AND r.target_account_id = s.account_id AND r.kind = 'block') \
            AND ($2::text IS NULL OR s.id < $2) \
            AND ($3::text IS NULL OR s.id > $3) \
         UNION \
         SELECT {STATUS_COLUMNS} FROM status s \
           JOIN account a ON a.id = s.account_id \
          WHERE s.account_id IN ( \
                  SELECT f.target_account_id FROM follow f \
                    JOIN account a2 ON a2.id = f.target_account_id \
                   WHERE f.account_id = $1 AND a2.followers_count >= $5) \
            AND s.deleted_at IS NULL AND s.visibility <> 'direct' \
            AND a.suspended_at IS NULL AND a.silenced_at IS NULL \
            AND NOT EXISTS (SELECT 1 FROM account_relation r WHERE r.account_id = $1 \
                            AND r.target_account_id = s.account_id AND r.kind = 'block') \
            AND ($2::text IS NULL OR s.id < $2) \
            AND ($3::text IS NULL OR s.id > $3) \
         ORDER BY id {order} LIMIT $4"
    );
    let rows = sqlx::query_as::<_, StatusRow>(&sql)
        .bind(account_id)
        .bind(max_id)
        .bind(lower_id)
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

#[derive(FromRow)]
struct DeletedOwned {
    in_reply_to_id: Option<String>,
    reblog_of_id: Option<String>,
    content: String,
    content_source: Option<String>,
}

/// Soft-deletes a status owned by `account_id`, removes its timeline entries, and
/// updates `statuses_count`, `replies_count`, and `reblogs_count` in one transaction.
pub async fn delete_owned(
    pool: &PgPool,
    status_id: &str,
    account_id: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let deleted = sqlx::query_as::<_, DeletedOwned>(
        "UPDATE status SET deleted_at = now() \
          WHERE id = $1 AND account_id = $2 AND deleted_at IS NULL \
          RETURNING in_reply_to_id, reblog_of_id, content, content_source",
    )
    .bind(status_id)
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(deleted) = deleted else {
        return Ok(false);
    };
    cleanup_deleted_status(
        &mut tx,
        status_id,
        deleted.in_reply_to_id.as_deref(),
        deleted.reblog_of_id.as_deref(),
    )
    .await?;
    // `statuses::reblog` does not increment `account.statuses_count`, whereas `statuses::create`
    // does (including Misskey notes/renotes, which always carry `content_source`).
    let counts_toward_statuses_count = deleted.reblog_of_id.is_none()
        || deleted.content_source.is_some()
        || !deleted.content.is_empty();
    if counts_toward_statuses_count {
        sqlx::query(
            "UPDATE account SET statuses_count = GREATEST(0, statuses_count - 1) WHERE id = $1",
        )
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(true)
}

/// Inserts a local status and returns it exactly as a timeline would.
pub async fn insert(pool: &PgPool, new: &NewStatus<'_>) -> Result<StatusRow, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let row = insert_row(&mut tx, new).await?;
    if let Some(parent_id) = new.in_reply_to_id {
        refresh_replies_count(&mut tx, parent_id).await?;
    }
    if let Some(original_id) = new.reblog_of_id {
        refresh_reblogs_count(&mut tx, original_id).await?;
    }
    tx.commit().await?;
    Ok(row)
}

async fn insert_row(
    conn: &mut sqlx::PgConnection,
    new: &NewStatus<'_>,
) -> Result<StatusRow, sqlx::Error> {
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
        .fetch_one(conn)
        .await
}

async fn refresh_replies_count(
    conn: &mut sqlx::PgConnection,
    parent_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE status SET replies_count = \
             (SELECT count(*) FROM status WHERE in_reply_to_id = $1 AND deleted_at IS NULL) \
         WHERE id = $1",
    )
    .bind(parent_id)
    .execute(conn)
    .await?;
    Ok(())
}

async fn refresh_reblogs_count(
    conn: &mut sqlx::PgConnection,
    original_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE status SET reblogs_count = \
             (SELECT count(*) FROM status WHERE reblog_of_id = $1 AND deleted_at IS NULL) \
         WHERE id = $1",
    )
    .bind(original_id)
    .execute(conn)
    .await?;
    Ok(())
}

async fn fan_out_home(
    conn: &mut sqlx::PgConnection,
    account_id: &str,
    status_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO timeline_entry (account_id, status_id, kind) \
         SELECT $1, $2, 'home' \
         UNION SELECT account_id, $2, 'home' FROM follow \
                WHERE target_account_id = $1 AND state = 'accepted' \
         ON CONFLICT DO NOTHING",
    )
    .bind(account_id)
    .bind(status_id)
    .execute(conn)
    .await?;
    Ok(())
}

async fn cleanup_deleted_status(
    conn: &mut sqlx::PgConnection,
    status_id: &str,
    in_reply_to_id: Option<&str>,
    reblog_of_id: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM timeline_entry WHERE status_id = $1")
        .bind(status_id)
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "DELETE FROM timeline_entry \
          WHERE status_id IN (SELECT id FROM status WHERE reblog_of_id = $1)",
    )
    .bind(status_id)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE status SET deleted_at = now() WHERE reblog_of_id = $1 AND deleted_at IS NULL",
    )
    .bind(status_id)
    .execute(&mut *conn)
    .await?;
    if let Some(parent_id) = in_reply_to_id {
        refresh_replies_count(&mut *conn, parent_id).await?;
    }
    if let Some(original_id) = reblog_of_id {
        refresh_reblogs_count(&mut *conn, original_id).await?;
    }
    Ok(())
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

/// The complete local write: status, media attachments, mentions, tags, timeline fan-out.
///
/// Fan-out is immediate here because a local follower timeline is a single indexed
/// insert. Remote delivery is a worker concern and must not hold this transaction.
pub async fn create(
    pool: &PgPool,
    new: &NewStatus<'_>,
    media_ids: &[String],
    mention_ids: &[String],
    tags: &[String],
) -> Result<StatusRow, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let row = insert_row(&mut tx, new).await?;

    if !media_ids.is_empty() {
        sqlx::query(
            "UPDATE media_attachment SET status_id = $1 \
             WHERE id = ANY($2) AND account_id = $3 AND status_id IS NULL",
        )
        .bind(new.id)
        .bind(media_ids)
        .bind(new.account_id)
        .execute(&mut *tx)
        .await?;
    }
    for mention in mention_ids {
        sqlx::query(
            "INSERT INTO status_mention (status_id, account_id) VALUES ($1, $2) \
             ON CONFLICT DO NOTHING",
        )
        .bind(new.id)
        .bind(mention)
        .execute(&mut *tx)
        .await?;
    }
    for tag in tags {
        sqlx::query(
            "INSERT INTO status_tag (status_id, tag) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(new.id)
        .bind(tag)
        .execute(&mut *tx)
        .await?;
    }
    if new.visibility != "direct" {
        fan_out_home(&mut tx, new.account_id, new.id).await?;
    }
    sqlx::query(
        "UPDATE account SET statuses_count = statuses_count + 1, last_status_at = now() \
         WHERE id = $1",
    )
    .bind(new.account_id)
    .execute(&mut *tx)
    .await?;
    if let Some(parent_id) = new.in_reply_to_id {
        refresh_replies_count(&mut tx, parent_id).await?;
    }
    if let Some(original_id) = new.reblog_of_id {
        refresh_reblogs_count(&mut tx, original_id).await?;
    }
    tx.commit().await?;
    Ok(row)
}

/// Copies a status into the booster's timeline.
pub async fn reblog(
    pool: &PgPool,
    account_id: &str,
    original_id: &str,
) -> Result<Option<StatusRow>, sqlx::Error> {
    Ok(reblog_status(pool, account_id, original_id)
        .await?
        .map(|(row, _created)| row))
}

/// Copies a status into the booster's timeline, returning the active reblog row and
/// whether it was newly created (`false` when an active reblog already existed).
pub async fn reblog_status(
    pool: &PgPool,
    account_id: &str,
    original_id: &str,
) -> Result<Option<(StatusRow, bool)>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let visibility: Option<String> = sqlx::query_scalar(
        "SELECT visibility FROM status WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(original_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(visibility) = visibility else {
        return Ok(None);
    };
    if visibility == "direct" {
        return Ok(None);
    }
    let existing_sql = format!(
        "SELECT {STATUS_COLUMNS_SIMPLE} FROM status \
          WHERE reblog_of_id = $1 AND account_id = $2 AND deleted_at IS NULL \
          LIMIT 1"
    );
    if let Some(existing) = sqlx::query_as::<_, StatusRow>(&existing_sql)
        .bind(original_id)
        .bind(account_id)
        .fetch_optional(&mut *tx)
        .await?
    {
        tx.commit().await?;
        return Ok(Some((existing, false)));
    }
    let id = nodus_server_core::Id::new().to_string();
    let sql = format!(
        "INSERT INTO status (id, account_id, content, content_html, content_format, \
                             visibility, reblog_of_id, local) \
         VALUES ($1, $2, '', '', 'html', $3, $4, true) \
         RETURNING {STATUS_COLUMNS_SIMPLE}"
    );
    let row = sqlx::query_as::<_, StatusRow>(&sql)
        .bind(&id)
        .bind(account_id)
        .bind(&visibility)
        .bind(original_id)
        .fetch_one(&mut *tx)
        .await?;
    refresh_reblogs_count(&mut tx, original_id).await?;
    fan_out_home(&mut tx, account_id, &id).await?;
    tx.commit().await?;
    Ok(Some((row, true)))
}

/// Removes `account_id`'s boost of `original_id`, refreshes `reblogs_count`, and returns
/// the updated original status if it still exists.
pub async fn unreblog(
    pool: &PgPool,
    account_id: &str,
    original_id: &str,
) -> Result<Option<StatusRow>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "DELETE FROM status WHERE reblog_of_id = $1 AND account_id = $2 AND deleted_at IS NULL",
    )
    .bind(original_id)
    .bind(account_id)
    .execute(&mut *tx)
    .await?;
    let sql = format!(
        "UPDATE status SET reblogs_count = \
             (SELECT count(*) FROM status WHERE reblog_of_id = $1 AND deleted_at IS NULL) \
         WHERE id = $1 AND deleted_at IS NULL \
         RETURNING {STATUS_COLUMNS_SIMPLE}"
    );
    let row = sqlx::query_as::<_, StatusRow>(&sql)
        .bind(original_id)
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(row)
}

/// Returns whether `account_id` is mentioned in `status_id`.
pub async fn is_mentioned(
    pool: &PgPool,
    status_id: &str,
    account_id: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM status_mention WHERE status_id = $1 AND account_id = $2)",
    )
    .bind(status_id)
    .bind(account_id)
    .fetch_one(pool)
    .await
}

/// Ancestors and descendants of a status, oldest first.
pub async fn context(
    pool: &PgPool,
    id: &str,
) -> Result<(Vec<StatusRow>, Vec<StatusRow>), sqlx::Error> {
    let ancestors = format!(
        "WITH RECURSIVE chain AS ( \
             SELECT {STATUS_COLUMNS} FROM status s WHERE s.id = \
                 (SELECT in_reply_to_id FROM status WHERE id = $1) \
               AND s.deleted_at IS NULL \
             UNION ALL \
             SELECT {STATUS_COLUMNS} FROM status s \
               JOIN chain c ON s.id = c.in_reply_to_id \
              WHERE s.deleted_at IS NULL \
         ) SELECT * FROM chain ORDER BY id ASC"
    );
    let descendants = format!(
        "WITH RECURSIVE tree AS ( \
             SELECT {STATUS_COLUMNS} FROM status s \
              WHERE s.in_reply_to_id = $1 AND s.deleted_at IS NULL \
             UNION ALL \
             SELECT {STATUS_COLUMNS} FROM status s \
               JOIN tree t ON s.in_reply_to_id = t.id \
              WHERE s.deleted_at IS NULL \
         ) SELECT * FROM tree ORDER BY id ASC"
    );
    let ancestors = sqlx::query_as::<_, StatusRow>(&ancestors)
        .bind(id)
        .fetch_all(pool)
        .await?;
    let descendants = sqlx::query_as::<_, StatusRow>(&descendants)
        .bind(id)
        .fetch_all(pool)
        .await?;
    Ok((ancestors, descendants))
}
