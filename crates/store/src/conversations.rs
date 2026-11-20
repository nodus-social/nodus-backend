//! Direct-message threads.
//!
//! Mastodon keeps a `conversation` table and writes to it on every DM. We do not: a
//! conversation is exactly the set of direct statuses sharing a thread root, so it is
//! derived on read. The root is found by walking `in_reply_to_id` upwards until there
//! is no parent (or the parent is not ours, which happens when the thread started on
//! another instance).

use sqlx::{FromRow, PgPool};

/// One thread, with the newest status that belongs to it.
#[derive(Debug, Clone, FromRow)]
pub struct ConversationRow {
    pub root_id: String,
    pub last_status_id: String,
    pub last_author_id: String,
    pub status_count: i64,
    /// `None` means the reader has never opened this thread.
    pub last_read_id: Option<String>,
}

/// The threads a reader takes part in, most recently active first.
pub async fn page(
    pool: &PgPool,
    account_id: &str,
    max_id: Option<&str>,
    limit: i64,
) -> Result<Vec<ConversationRow>, sqlx::Error> {
    sqlx::query_as::<_, ConversationRow>(
        "WITH RECURSIVE involved AS ( \
             SELECT s.id, s.account_id, s.in_reply_to_id \
               FROM status s \
              WHERE s.deleted_at IS NULL AND s.visibility = 'direct' \
                AND (s.account_id = $1 \
                     OR EXISTS (SELECT 1 FROM status_mention m \
                                 WHERE m.status_id = s.id AND m.account_id = $1)) \
         ), thread AS ( \
             SELECT i.id AS leaf, i.id AS node, i.in_reply_to_id AS parent, 0 AS depth \
               FROM involved i \
             UNION ALL \
             SELECT t.leaf, s.id, s.in_reply_to_id, t.depth + 1 \
               FROM thread t JOIN status s ON s.id = t.parent \
              WHERE t.depth < 20 \
         ), roots AS ( \
             SELECT DISTINCT ON (leaf) leaf, node AS root_id FROM thread \
              ORDER BY leaf, depth DESC \
         ), grouped AS ( \
             SELECT r.root_id, \
                    MAX(s.id) AS last_status_id, \
                    COUNT(*)::bigint AS status_count \
               FROM roots r JOIN status s ON s.id = r.leaf \
              GROUP BY r.root_id \
         ) \
         SELECT g.root_id, g.last_status_id, s.account_id AS last_author_id, g.status_count, \
                cr.last_read_id \
           FROM grouped g \
           JOIN status s ON s.id = g.last_status_id \
           LEFT JOIN conversation_read cr \
                  ON cr.account_id = $1 AND cr.root_id = g.root_id \
          WHERE ($2::text IS NULL OR g.root_id < $2) \
          ORDER BY g.last_status_id DESC LIMIT $3",
    )
    .bind(account_id)
    .bind(max_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// The other people in these threads: every author and mention except the reader.
///
/// Returned as `(root_id, account_id)` pairs so the caller can group them without a
/// second join per conversation.
pub async fn participants(
    pool: &PgPool,
    account_id: &str,
    roots: &[String],
) -> Result<Vec<(String, String)>, sqlx::Error> {
    sqlx::query_as::<_, (String, String)>(
        "WITH RECURSIVE involved AS ( \
             SELECT s.id, s.account_id, s.in_reply_to_id \
               FROM status s \
              WHERE s.deleted_at IS NULL AND s.visibility = 'direct' \
                AND (s.account_id = $1 \
                     OR EXISTS (SELECT 1 FROM status_mention m \
                                 WHERE m.status_id = s.id AND m.account_id = $1)) \
         ), thread AS ( \
             SELECT i.id AS leaf, i.id AS node, i.in_reply_to_id AS parent, 0 AS depth \
               FROM involved i \
             UNION ALL \
             SELECT t.leaf, s.id, s.in_reply_to_id, t.depth + 1 \
               FROM thread t JOIN status s ON s.id = t.parent \
              WHERE t.depth < 20 \
         ), roots AS ( \
             SELECT DISTINCT ON (leaf) leaf, node AS root_id FROM thread \
              ORDER BY leaf, depth DESC \
         ) \
         SELECT DISTINCT r.root_id, p.account_id \
           FROM roots r \
           JOIN status s ON s.id = r.leaf \
           LEFT JOIN status_mention m ON m.status_id = s.id \
           CROSS JOIN LATERAL (VALUES (s.account_id), (m.account_id)) AS p(account_id) \
          WHERE r.root_id = ANY($2) AND p.account_id <> $1",
    )
    .bind(account_id)
    .bind(roots)
    .fetch_all(pool)
    .await
}

/// Silences one conversation, or unsilences it.
///
/// A muted conversation stays in the list; it stops counting as unread, which is what a
/// client shows when it hides one.
pub async fn set_muted(
    pool: &PgPool,
    account_id: &str,
    root_id: &str,
    muted: bool,
) -> Result<(), sqlx::Error> {
    if muted {
        sqlx::query(
            "INSERT INTO conversation_mute (account_id, root_id) VALUES ($1, $2) \
             ON CONFLICT (account_id, root_id) DO NOTHING",
        )
        .bind(account_id)
        .bind(root_id)
        .execute(pool)
        .await?;
    } else {
        sqlx::query("DELETE FROM conversation_mute WHERE account_id = $1 AND root_id = $2")
            .bind(account_id)
            .bind(root_id)
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// The root of the direct-message thread `status_id` belongs to, for the live
/// `conversation` event: the id Mastodon keys the conversation by.
pub async fn root_of(pool: &PgPool, status_id: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "WITH RECURSIVE thread AS ( \
             SELECT id, in_reply_to_id, 0 AS depth FROM status \
              WHERE id = $1 AND deleted_at IS NULL \
             UNION ALL \
             SELECT s.id, s.in_reply_to_id, t.depth + 1 \
               FROM thread t JOIN status s ON s.id = t.in_reply_to_id \
              WHERE t.depth < 20 \
         ) \
         SELECT id FROM thread ORDER BY depth DESC LIMIT 1",
    )
    .bind(status_id)
    .fetch_optional(pool)
    .await
}

/// The muted roots among `roots`, so a page of conversations can be filtered in one query.
pub async fn muted_roots(
    pool: &PgPool,
    account_id: &str,
    roots: &[String],
) -> Result<Vec<String>, sqlx::Error> {
    if roots.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_scalar::<_, String>(
        "SELECT root_id FROM conversation_mute WHERE account_id = $1 AND root_id = ANY($2)",
    )
    .bind(account_id)
    .bind(roots)
    .fetch_all(pool)
    .await
}
