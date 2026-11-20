//! Statuses and the two timeline lanes.
//!
//! The home timeline is a union, not a single scan: statuses of ordinary accounts are
//! materialised into `timeline_entry` by the `fan_out` worker, while accounts above
//! [`BIG_ACCOUNT_THRESHOLD`] are merged at read time. Both lanes are ordered by the
//! same id and deduped, so a status that crosses the threshold never appears twice.

use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};

use nodus_server_core::limits::BIG_ACCOUNT_THRESHOLD;
use nodus_server_core::{PageOrder, PageParams, PageSize, Visibility};

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

pub(crate) const STATUS_COLUMNS: &str = "s.id, s.account_id, s.uri, s.content, s.content_html, \
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

/// One revision of a status, as `GET /api/v1/statuses/{id}/history` reports it.
#[derive(Debug, Clone, FromRow)]
pub struct StatusEditRow {
    pub content: String,
    pub spoiler_text: String,
    pub sensitive: bool,
    pub created_at: DateTime<Utc>,
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

/// The hashtags a status carries, alphabetically.
///
/// Tags live in `status_tag` rather than on the row, so every payload that shows a post
/// has to ask for them; without this a client renders `#tag` as plain text and a tag
/// timeline disagrees with the post that fed it.
pub async fn tags_of(pool: &PgPool, status_id: &str) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT tag::text FROM status_tag WHERE status_id = $1 ORDER BY tag")
        .bind(status_id)
        .fetch_all(pool)
        .await
}

/// The accounts a status mentions, so a client can link them instead of showing text.
pub async fn mentions_of(pool: &PgPool, status_id: &str) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT account_id FROM status_mention WHERE status_id = $1 ORDER BY account_id",
    )
    .bind(status_id)
    .fetch_all(pool)
    .await
}

/// Replaces the accounts a remote status mentions.
pub async fn replace_mentions(
    pool: &PgPool,
    status_id: &str,
    account_ids: &[String],
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM status_mention WHERE status_id = $1")
        .bind(status_id)
        .execute(&mut *tx)
        .await?;
    for account_id in account_ids {
        sqlx::query(
            "INSERT INTO status_mention (status_id, account_id) VALUES ($1, $2) \
             ON CONFLICT DO NOTHING",
        )
        .bind(status_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// A custom emoji a status uses, without the surrounding colons.
#[derive(Debug, Clone, FromRow)]
pub struct StatusEmoji {
    pub shortcode: String,
    pub url: String,
}

/// The custom emoji a status uses, in the order the peer sent them.
pub async fn emojis_of(pool: &PgPool, status_id: &str) -> Result<Vec<StatusEmoji>, sqlx::Error> {
    sqlx::query_as::<_, StatusEmoji>(
        "SELECT shortcode, url FROM status_emoji WHERE status_id = $1 ORDER BY position, shortcode",
    )
    .bind(status_id)
    .fetch_all(pool)
    .await
}

/// Replaces the custom emoji a remote status uses.
pub async fn replace_emojis(
    pool: &PgPool,
    status_id: &str,
    emojis: &[StatusEmoji],
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM status_emoji WHERE status_id = $1")
        .bind(status_id)
        .execute(&mut *tx)
        .await?;
    for (position, emoji) in emojis.iter().enumerate() {
        sqlx::query(
            "INSERT INTO status_emoji (status_id, shortcode, url, position) \
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(status_id)
        .bind(&emoji.shortcode)
        .bind(&emoji.url)
        .bind(i32::try_from(position).unwrap_or(i32::MAX))
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Replaces the hashtags a remote status carries.
pub async fn replace_tags(
    pool: &PgPool,
    status_id: &str,
    tags: &[String],
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM status_tag WHERE status_id = $1")
        .bind(status_id)
        .execute(&mut *tx)
        .await?;
    for tag in tags {
        sqlx::query(
            "INSERT INTO status_tag (status_id, tag) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(status_id)
        .bind(tag)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
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
    /// `public`, `unlisted`, `private` or `direct`, derived from the note's addressing.
    pub visibility: &'a str,
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
    // The previous version is read before the upsert so the history can tell a real
    // change from a peer repeating itself.
    let previous: Option<(String, String, bool)> =
        sqlx::query_as("SELECT content, spoiler_text, sensitive FROM status WHERE uri = $1")
            .bind(new.uri)
            .fetch_optional(&mut *tx)
            .await?;
    let sql = format!(
        "INSERT INTO status (id, account_id, uri, content, content_html, spoiler_text, \
             visibility, sensitive, in_reply_to_id, in_reply_to_account_id, local, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, false, $11) \
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
        .bind(new.visibility)
        .bind(new.sensitive)
        .bind(new.in_reply_to_id)
        .bind(new.in_reply_to_account_id)
        .bind(new.created_at)
        .fetch_one(&mut *tx)
        .await?;
    if let Some((old_content, old_spoiler, old_sensitive)) = previous {
        if old_content != new.content
            || old_spoiler != new.spoiler_text
            || old_sensitive != new.sensitive
        {
            record_edit(
                &mut tx,
                &row.id,
                new.content,
                new.spoiler_text,
                new.sensitive,
            )
            .await?;
        }
    }
    if let Some(parent_id) = new.in_reply_to_id {
        refresh_replies_count(&mut tx, parent_id).await?;
    }
    tx.commit().await?;
    Ok(row)
}

/// Refreshes a remote note from an edit by its author.
pub async fn update_remote_content(
    pool: &PgPool,
    uri: &str,
    account_id: &str,
    content: &str,
    content_html: &str,
    spoiler_text: &str,
    sensitive: bool,
) -> Result<Option<StatusRow>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    // The row's own text decides whether this is a revision: an Update that says what we
    // already have is not one.
    let previous: Option<(String, String, bool)> = sqlx::query_as(
        "SELECT content, spoiler_text, sensitive FROM status \
          WHERE uri = $1 AND account_id = $2 AND NOT local AND deleted_at IS NULL",
    )
    .bind(uri)
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await?;
    let sql = format!(
        "UPDATE status SET content = $3, content_html = $4, spoiler_text = $5, \
             sensitive = $6, edited_at = now() \
          WHERE uri = $1 AND account_id = $2 AND NOT local AND deleted_at IS NULL \
          RETURNING {STATUS_COLUMNS_SIMPLE}"
    );
    let row = sqlx::query_as::<_, StatusRow>(&sql)
        .bind(uri)
        .bind(account_id)
        .bind(content)
        .bind(content_html)
        .bind(spoiler_text)
        .bind(sensitive)
        .fetch_optional(&mut *tx)
        .await?;
    if let (Some((old_content, old_spoiler, old_sensitive)), Some(row)) = (previous, &row) {
        if old_content != content || old_spoiler != spoiler_text || old_sensitive != sensitive {
            record_edit(&mut tx, &row.id, content, spoiler_text, sensitive).await?;
        }
    }
    tx.commit().await?;
    Ok(row)
}

/// Appends one revision. The caller has already compared it with the previous text.
async fn record_edit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    status_id: &str,
    content: &str,
    spoiler_text: &str,
    sensitive: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO status_edit (status_id, content, spoiler_text, sensitive) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(status_id)
    .bind(content)
    .bind(spoiler_text)
    .bind(sensitive)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The revisions of a status, newest first. An unedited post has none.
pub async fn edits(pool: &PgPool, status_id: &str) -> Result<Vec<StatusEditRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT content, spoiler_text, sensitive, created_at FROM status_edit \
          WHERE status_id = $1 ORDER BY created_at DESC, id DESC",
    )
    .bind(status_id)
    .fetch_all(pool)
    .await
}

/// Soft-deletes a remote status by URI, scoped to its owning account.
pub async fn delete_remote(
    pool: &PgPool,
    uri: &str,
    account_id: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let deleted: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "UPDATE status SET deleted_at = now() \
          WHERE uri = $1 AND account_id = $2 AND NOT local AND deleted_at IS NULL \
          RETURNING id, in_reply_to_id, reblog_of_id",
    )
    .bind(uri)
    .bind(account_id)
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

/// Soft-deletes every live status one remote actor posted.
///
/// The account stays: a tombstoned post is enough to stop serving it, and keeping the row
/// makes a repeated `Delete` idempotent while replies still resolve their author.
pub async fn delete_remote_actor(pool: &PgPool, account_id: &str) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let rows: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "UPDATE status SET deleted_at = now() \
          WHERE account_id = $1 AND NOT local AND deleted_at IS NULL \
          RETURNING id, in_reply_to_id, reblog_of_id",
    )
    .bind(account_id)
    .fetch_all(&mut *tx)
    .await?;
    for (status_id, in_reply_to_id, reblog_of_id) in &rows {
        cleanup_deleted_status(
            &mut tx,
            status_id,
            in_reply_to_id.as_deref(),
            reblog_of_id.as_deref(),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(u64::try_from(rows.len()).unwrap_or_default())
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
/// `/api/v1/timelines/public`: public visibility only.
///
/// A paused domain is hidden here, not in `by_id`: a moderator opening a report must still
/// see the post. Unlike `instance_block` (permanent, severity-bearing), a pause expires on
/// its own and is not announced to the peer, so the predicate reads `expires_at` directly.
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
           AND s.quarantined_at IS NULL \
           AND a.suspended_at IS NULL AND a.silenced_at IS NULL \
           AND a.deleted_at IS NULL \
           AND NOT EXISTS (SELECT 1 FROM instance_block b WHERE b.domain = a.domain \
                           AND b.severity IN ('suspend', 'silence')) \
           AND NOT EXISTS (SELECT 1 FROM domain_pause p WHERE p.domain = a.domain \
                           AND (p.expires_at IS NULL OR p.expires_at > now())) \
           AND NOT EXISTS (SELECT 1 FROM remote_moderation m WHERE m.actor_uri = a.uri \
                           AND m.action IN ('silence', 'suspend') \
                           AND (m.expires_at IS NULL OR m.expires_at > now())) \
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
           JOIN account a ON a.id = s.account_id \
         WHERE s.account_id = $1 AND s.deleted_at IS NULL \
           AND s.quarantined_at IS NULL \
           AND a.deleted_at IS NULL \
           AND s.visibility IN ('public', 'unlisted') \
           AND NOT EXISTS (SELECT 1 FROM domain_pause p JOIN account a ON a.id = s.account_id \
                            WHERE p.domain = a.domain \
                              AND (p.expires_at IS NULL OR p.expires_at > now())) \
           AND NOT EXISTS (SELECT 1 FROM account a JOIN remote_moderation m \
                            ON m.actor_uri = a.uri \
                           WHERE a.id = s.account_id \
                             AND m.action IN ('silence', 'suspend') \
                             AND (m.expires_at IS NULL OR m.expires_at > now())) \
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

/// How many statuses one page of an account export may carry.
///
/// Larger than a timeline page because an export is read by a script, not a screen, and
/// bounded because the whole point is that a 50 000-post account streams through pages
/// instead of being assembled into one string.
pub const EXPORT_PAGE_MAX: u32 = 200;

/// A page of an account's own statuses for its data export, newest first.
///
/// Deliberately not `account_page`: that one is an outbox, so it hides direct posts, hides
/// the posts of a silenced actor and hides what moderation quarantined. An export is the
/// opposite reader — the account asking for what it wrote — so it filters on authorship
/// alone. Tombstones stay excluded because a deleted post is not a post the person has any
/// more, and the page is cursor-bounded because the export of a 50 000-post account must
/// not be assembled in memory in one query.
pub async fn export_page(
    pool: &PgPool,
    account_id: &str,
    max_id: Option<&str>,
    limit: i64,
) -> Result<StatusPage, sqlx::Error> {
    let size = PageSize::clamp(u32::try_from(limit).ok(), EXPORT_PAGE_MAX);
    let sql = format!(
        "SELECT {STATUS_COLUMNS} FROM status s \
         WHERE s.account_id = $1 AND s.deleted_at IS NULL \
           AND ($2::text IS NULL OR s.id < $2) \
         ORDER BY s.id DESC LIMIT $3"
    );
    let rows = sqlx::query_as::<_, StatusRow>(&sql)
        .bind(account_id)
        .bind(max_id)
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
            AND s.quarantined_at IS NULL \
            AND s.visibility <> 'direct' \
            AND a.suspended_at IS NULL AND a.silenced_at IS NULL \
            AND a.deleted_at IS NULL \
            AND NOT EXISTS (SELECT 1 FROM account_relation r WHERE r.account_id = $1 \
                            AND r.target_account_id = s.account_id \
                            AND r.kind IN ('block', 'mute')) \
            AND NOT EXISTS (SELECT 1 FROM domain_pause p WHERE p.domain = a.domain \
                            AND (p.expires_at IS NULL OR p.expires_at > now())) \
            AND NOT EXISTS (SELECT 1 FROM remote_moderation m WHERE m.actor_uri = a.uri \
                            AND m.action = 'suspend' \
                            AND (m.expires_at IS NULL OR m.expires_at > now())) \
            AND ($2::text IS NULL OR s.id < $2) \
            AND ($3::text IS NULL OR s.id > $3) \
         UNION \
         SELECT {STATUS_COLUMNS} FROM status s \
           JOIN account a ON a.id = s.account_id \
          WHERE s.account_id IN ( \
                  SELECT f.target_account_id FROM follow f \
                    JOIN account a2 ON a2.id = f.target_account_id \
                   WHERE f.account_id = $1 AND f.state = 'accepted' \
                     AND a2.followers_count >= $5) \
            AND s.deleted_at IS NULL AND s.quarantined_at IS NULL \
            AND s.visibility <> 'direct' \
            AND a.suspended_at IS NULL AND a.silenced_at IS NULL \
            AND a.deleted_at IS NULL \
            AND NOT EXISTS (SELECT 1 FROM account_relation r WHERE r.account_id = $1 \
                            AND r.target_account_id = s.account_id \
                            AND r.kind IN ('block', 'mute')) \
            AND NOT EXISTS (SELECT 1 FROM domain_pause p WHERE p.domain = a.domain \
                            AND (p.expires_at IS NULL OR p.expires_at > now())) \
            AND NOT EXISTS (SELECT 1 FROM remote_moderation m WHERE m.actor_uri = a.uri \
                            AND m.action = 'suspend' \
                            AND (m.expires_at IS NULL OR m.expires_at > now())) \
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

/// `/api/v1/timelines/list/{id}`: the statuses of one list's members.
///
/// `None` when the list is not the caller's: an id that names someone else's list must
/// answer like an id that names nothing, because a `403` would confirm the list exists.
/// Direct posts never appear (a list is a reading surface, not a mailbox), and a
/// followers-only post appears only when the reader actually follows its author — a list
/// can name an account the reader does not follow, and membership is not a visibility
/// grant.
pub async fn list_page(
    pool: &PgPool,
    account_id: &str,
    list_id: &str,
    params: PageParams,
) -> Result<Option<StatusPage>, sqlx::Error> {
    if crate::lists::list(pool, account_id, list_id)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let size = PageSize::default_max(params.limit);
    let (max_id, lower_id, order) = page_bounds(params);
    let sql = format!(
        "SELECT {STATUS_COLUMNS} FROM status s \
           JOIN account a ON a.id = s.account_id \
           JOIN list_account l ON l.account_id = s.account_id AND l.list_id = $2 \
         WHERE s.deleted_at IS NULL \
           AND s.quarantined_at IS NULL \
           AND s.visibility <> 'direct' \
           AND (s.visibility IN ('public', 'unlisted') \
                OR EXISTS (SELECT 1 FROM follow f WHERE f.account_id = $1 \
                            AND f.target_account_id = s.account_id \
                            AND f.state = 'accepted')) \
           AND a.suspended_at IS NULL AND a.silenced_at IS NULL \
           AND a.deleted_at IS NULL \
           AND NOT EXISTS (SELECT 1 FROM account_relation r WHERE r.account_id = $1 \
                           AND r.target_account_id = s.account_id \
                           AND r.kind IN ('block', 'mute')) \
           AND NOT EXISTS (SELECT 1 FROM domain_pause p WHERE p.domain = a.domain \
                           AND (p.expires_at IS NULL OR p.expires_at > now())) \
           AND NOT EXISTS (SELECT 1 FROM remote_moderation m WHERE m.actor_uri = a.uri \
                           AND m.action = 'suspend' \
                           AND (m.expires_at IS NULL OR m.expires_at > now())) \
           AND ($3::text IS NULL OR s.id < $3) \
           AND ($4::text IS NULL OR s.id > $4) \
         ORDER BY s.id {order} LIMIT $5"
    );
    let rows = sqlx::query_as::<_, StatusRow>(&sql)
        .bind(account_id)
        .bind(list_id)
        .bind(max_id)
        .bind(lower_id)
        .bind(size.as_i64() + 1)
        .fetch_all(pool)
        .await?;
    Ok(Some(finish(rows, size)))
}

/// `/api/v1/timelines/tag/{tag}`: public statuses carrying one hashtag.
///
/// The visibility predicate is [`public_page`]'s, because a tag page is a public
/// document in every Mastodon client; `status_tag.tag` is `citext`, so the match is
/// case-insensitive without lowering anything here.
pub async fn tag_page(
    pool: &PgPool,
    tag: &str,
    params: PageParams,
) -> Result<StatusPage, sqlx::Error> {
    let size = PageSize::default_max(params.limit);
    let (max_id, lower_id, order) = page_bounds(params);
    let sql = format!(
        "SELECT {STATUS_COLUMNS} FROM status s \
           JOIN account a ON a.id = s.account_id \
           JOIN status_tag t ON t.status_id = s.id \
         WHERE t.tag = $1::citext AND s.deleted_at IS NULL \
           AND s.visibility = 'public' \
           AND s.quarantined_at IS NULL \
           AND a.suspended_at IS NULL AND a.silenced_at IS NULL \
           AND a.deleted_at IS NULL \
           AND NOT EXISTS (SELECT 1 FROM instance_block b WHERE b.domain = a.domain \
                           AND b.severity IN ('suspend', 'silence')) \
           AND NOT EXISTS (SELECT 1 FROM domain_pause p WHERE p.domain = a.domain \
                           AND (p.expires_at IS NULL OR p.expires_at > now())) \
           AND NOT EXISTS (SELECT 1 FROM remote_moderation m WHERE m.actor_uri = a.uri \
                           AND m.action IN ('silence', 'suspend') \
                           AND (m.expires_at IS NULL OR m.expires_at > now())) \
           AND ($2::text IS NULL OR s.id < $2) \
           AND ($3::text IS NULL OR s.id > $3) \
         ORDER BY s.id {order} LIMIT $4"
    );
    let rows = sqlx::query_as::<_, StatusRow>(&sql)
        .bind(tag)
        .bind(max_id)
        .bind(lower_id)
        .bind(size.as_i64() + 1)
        .fetch_all(pool)
        .await?;
    Ok(finish(rows, size))
}

/// The accounts a status by `target_id` is materialised into, in keyset order.
///
/// The author is not included: the caller adds it, because the author's own entry exists
/// even when their follower count takes them out of the materialised lane. `after` is the
/// last account of the previous batch, so a 50 000-follower account streams instead of
/// being collected into one vector.
///
/// `max_followers` mirrors the cut-off in [`fan_out_home`]: at or above it the read path
/// merges the author's posts instead, nothing is materialised, and the caller pushes
/// nothing into a cache.
pub async fn home_fanout_accounts(
    pool: &PgPool,
    target_id: &str,
    after: Option<&str>,
    limit: i64,
    max_followers: Option<i64>,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT f.account_id FROM follow f \
           JOIN account a ON a.id = f.target_account_id \
          WHERE f.target_account_id = $1 AND f.state = 'accepted' \
            AND ($2::text IS NULL OR f.account_id > $2) \
            AND ($4::bigint IS NULL OR a.followers_count < $4) \
          ORDER BY f.account_id LIMIT $3",
    )
    .bind(target_id)
    .bind(after)
    .bind(limit)
    .bind(max_followers)
    .fetch_all(pool)
    .await
}

/// Whether the reader follows an account whose posts are merged at read time.
///
/// A home cache only ever holds the materialised lane, so a reader who follows a big
/// account cannot be served from it: those rows are merged by the SQL read.
pub async fn follows_big_account(
    pool: &PgPool,
    account_id: &str,
    threshold: i64,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM follow f \
           JOIN account a ON a.id = f.target_account_id \
          WHERE f.account_id = $1 AND f.state = 'accepted' \
            AND a.followers_count >= $2)",
    )
    .bind(account_id)
    .bind(threshold)
    .fetch_one(pool)
    .await
}

/// The rows of `ids` that a home timeline may still show, in no particular order.
///
/// The predicates are the materialised lane of [`home_page`], spelled out rather than
/// shared, because that query is a `UNION` with an alias per lane and this one is a plain
/// lookup by primary key. A cached read drops whatever this returns nothing for: a status
/// deleted or hidden since it was written to the cache.
pub async fn home_rows(
    pool: &PgPool,
    account_id: &str,
    ids: &[String],
) -> Result<Vec<StatusRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {STATUS_COLUMNS} FROM status s \
           JOIN account a ON a.id = s.account_id \
          WHERE s.id = ANY($2) AND s.deleted_at IS NULL \
            AND s.quarantined_at IS NULL \
            AND s.visibility <> 'direct' \
            AND a.suspended_at IS NULL AND a.silenced_at IS NULL \
            AND a.deleted_at IS NULL \
            AND NOT EXISTS (SELECT 1 FROM account_relation r WHERE r.account_id = $1 \
                            AND r.target_account_id = s.account_id \
                            AND r.kind IN ('block', 'mute')) \
            AND NOT EXISTS (SELECT 1 FROM domain_pause p WHERE p.domain = a.domain \
                            AND (p.expires_at IS NULL OR p.expires_at > now())) \
            AND NOT EXISTS (SELECT 1 FROM remote_moderation m WHERE m.actor_uri = a.uri \
                            AND m.action = 'suspend' \
                            AND (m.expires_at IS NULL OR m.expires_at > now()))"
    );
    sqlx::query_as::<_, StatusRow>(&sql)
        .bind(account_id)
        .bind(ids)
        .fetch_all(pool)
        .await
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
    // `cleanup_deleted_status` removes the timeline rows, so the live stream's recipients
    // have to be read first: after it, nobody knows who had this status any more.
    let home = home_recipients_in(&mut tx, status_id).await?;
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
    crate::live::status_deleted(account_id, status_id, &home);
    Ok(true)
}

/// The same read as [`home_recipients`], inside a transaction that is about to delete the
/// rows it reads.
async fn home_recipients_in(
    conn: &mut sqlx::PgConnection,
    status_id: &str,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT account_id FROM timeline_entry WHERE status_id = $1")
        .bind(status_id)
        .fetch_all(&mut *conn)
        .await
}

/// Marks a live status as sensitive.
///
/// Used when a scanner reports adult content the instance does not remove: the post keeps
/// its place on its author's profile, with its media behind a warning.
pub async fn mark_sensitive(pool: &PgPool, status_id: &str) -> Result<bool, sqlx::Error> {
    let updated = sqlx::query(
        "UPDATE status SET sensitive = true WHERE id = $1 AND deleted_at IS NULL AND NOT sensitive",
    )
    .bind(status_id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(updated > 0)
}

/// Takes a status out of the public timelines without deleting it.
///
/// `by_id` deliberately keeps returning it: a link someone already has still resolves, and
/// the moderator deciding about the report has to be able to open what it is about.
pub async fn quarantine(pool: &PgPool, status_id: &str) -> Result<bool, sqlx::Error> {
    let updated = sqlx::query(
        "UPDATE status SET quarantined_at = now() WHERE id = $1 AND quarantined_at IS NULL",
    )
    .bind(status_id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(updated > 0)
}

/// Puts a status back into the timelines; the caller decides when nothing is left hidden.
pub async fn release_quarantine(pool: &PgPool, status_id: &str) -> Result<bool, sqlx::Error> {
    let updated = sqlx::query(
        "UPDATE status SET quarantined_at = NULL WHERE id = $1 AND quarantined_at IS NOT NULL",
    )
    .bind(status_id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(updated > 0)
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

/// Inserts the status into the author's and accepted followers' home timelines.
///
/// `private` is materialised exactly like `public`, because "followers only" is precisely
/// the audience `timeline_entry` holds. `direct` is skipped: [`home_page`] excludes it and
/// the notification path is what carries it to the mentioned accounts, so a home row
/// would be a row no reader is ever allowed to see.
async fn fan_out_home(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    status_id: &str,
    visibility: &str,
) -> Result<(), sqlx::Error> {
    if !Visibility::from_str(visibility).is_ok_and(Visibility::in_home_timeline) {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO timeline_entry (account_id, status_id, kind) \
         SELECT $1, $2, 'home' \
         UNION SELECT f.account_id, $2, 'home' \
                 FROM follow f \
                 JOIN account a ON a.id = f.target_account_id \
                WHERE f.target_account_id = $1 \
                  AND f.state = 'accepted' \
                  AND a.followers_count < $3 \
         ON CONFLICT DO NOTHING",
    )
    .bind(account_id)
    .bind(status_id)
    .bind(BIG_ACCOUNT_THRESHOLD)
    .execute(&mut **tx)
    .await?;
    Ok(())
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
    create_with_poll(pool, new, media_ids, mention_ids, tags, None).await
}

/// Inserts a status and, when one was composed with it, its poll.
///
/// Both rows commit together: a status that survived without the poll the reader attached
/// would be a post whose question vanished between request and response.
pub async fn create_with_poll(
    pool: &PgPool,
    new: &NewStatus<'_>,
    media_ids: &[String],
    mention_ids: &[String],
    tags: &[String],
    poll: Option<&crate::polls::NewPoll<'_>>,
) -> Result<StatusRow, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let row = insert_row(&mut tx, new).await?;
    if let Some(poll) = poll {
        crate::polls::create_in_tx(&mut tx, poll).await?;
    }

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
    fan_out_home(&mut tx, new.account_id, new.id, new.visibility).await?;
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
    // Published after the commit, with the recipients `fan_out_home` wrote in the same
    // transaction: a stream must never show a status the database does not have.
    let home = home_recipients(pool, new.id).await;
    crate::live::status_created(new.account_id, new.id, new.visibility, mention_ids, &home);
    Ok(row)
}

/// The accounts `fan_out_home` put this status in, for the live stream.
///
/// A read failure yields an empty list: a missed live event is a stale timeline until the
/// next fetch, which is smaller than failing a status create after it already committed.
async fn home_recipients(pool: &PgPool, status_id: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT account_id FROM timeline_entry WHERE status_id = $1")
        .bind(status_id)
        .fetch_all(pool)
        .await
        .unwrap_or_default()
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
    if !Visibility::from_str(&visibility).is_ok_and(Visibility::boostable) {
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
    fan_out_home(&mut tx, account_id, &id, &visibility).await?;
    tx.commit().await?;
    let home = home_recipients(pool, &id).await;
    crate::live::status_created(account_id, &id, &visibility, &[], &home);
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

/// Who may appear in the accounts behind a status's favourites or reblogs.
///
/// The status row decides this, not the interaction: a private post lists only accepted
/// followers of its author, and a direct one only the people it was addressed to. The
/// author is always part of their own audience.
#[derive(Debug, Clone, Copy)]
pub enum InteractionAudience<'a> {
    Everyone,
    Followers(&'a str),
    Participants(&'a str),
}

/// The accounts that favourited a status, newest interaction first by account id.
///
/// The id is the cursor: account ids are ULIDs, so `max_id` is a stable page boundary
/// without a separate favourite id the client API never exposed.
pub async fn favourited_by(
    pool: &PgPool,
    status_id: &str,
    audience: InteractionAudience<'_>,
    max_id: Option<&str>,
    offset: i64,
    limit: i64,
) -> Result<Vec<crate::accounts::AccountRow>, sqlx::Error> {
    let (audience_clause, author) = audience_clause(audience, "f.account_id");
    let sql = format!(
        "SELECT {columns} FROM favourite f JOIN account a ON a.id = f.account_id \
          WHERE f.status_id = $1 \
            AND a.suspended_at IS NULL AND a.deleted_at IS NULL \
            AND ($2::text IS NULL OR a.id < $2) \
            AND {audience_clause} \
          ORDER BY a.id DESC LIMIT $4 OFFSET $5",
        columns = crate::accounts::ACCOUNT_COLUMNS_ALIASED,
    );
    sqlx::query_as(&sql)
        .bind(status_id)
        .bind(max_id)
        .bind(author)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
}

/// The accounts that boosted a status, newest boost first by account id.
pub async fn reblogged_by(
    pool: &PgPool,
    status_id: &str,
    audience: InteractionAudience<'_>,
    max_id: Option<&str>,
    offset: i64,
    limit: i64,
) -> Result<Vec<crate::accounts::AccountRow>, sqlx::Error> {
    let (audience_clause, author) = audience_clause(audience, "s.account_id");
    let sql = format!(
        "SELECT {columns} FROM status s JOIN account a ON a.id = s.account_id \
          WHERE s.reblog_of_id = $1 AND s.deleted_at IS NULL \
            AND a.suspended_at IS NULL AND a.deleted_at IS NULL \
            AND ($2::text IS NULL OR a.id < $2) \
            AND {audience_clause} \
          ORDER BY a.id DESC LIMIT $4 OFFSET $5",
        columns = crate::accounts::ACCOUNT_COLUMNS_ALIASED,
    );
    sqlx::query_as(&sql)
        .bind(status_id)
        .bind(max_id)
        .bind(author)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
}

/// The SQL fragment limiting an interaction list to the audience the status allows,
/// plus the author id it needs (bound as `$3`).
fn audience_clause<'a>(
    audience: InteractionAudience<'a>,
    actor: &str,
) -> (String, Option<&'a str>) {
    match audience {
        InteractionAudience::Everyone => ("TRUE".to_owned(), None),
        InteractionAudience::Followers(author) => (
            format!(
                "({actor} = $3 OR EXISTS ( \
                     SELECT 1 FROM follow ff WHERE ff.account_id = {actor} \
                       AND ff.target_account_id = $3 AND ff.state = 'accepted'))"
            ),
            Some(author),
        ),
        InteractionAudience::Participants(author) => (
            format!(
                "({actor} = $3 OR EXISTS ( \
                     SELECT 1 FROM status_mention m \
                      WHERE m.status_id = $1 AND m.account_id = {actor}))"
            ),
            Some(author),
        ),
    }
}
