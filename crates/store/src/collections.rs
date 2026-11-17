//! The statuses a reader kept: favourites, bookmarks, and the instance's own emoji.
//!
//! Unlike a timeline these are keyed by the reader's own row, so a page never needs a
//! visibility check: `favourite` and `bookmark` are only writable through the API, which
//! already refused anything the reader could not see.

use sqlx::{FromRow, PgPool};

use crate::statuses::{StatusRow, STATUS_COLUMNS};

/// A page of favourited statuses, newest favourite first is not possible — the join
/// orders by status id so a cursor stays meaningful across additions and removals.
pub async fn favourites(
    pool: &PgPool,
    account_id: &str,
    max_id: Option<&str>,
    limit: i64,
) -> Result<Vec<StatusRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {STATUS_COLUMNS} FROM favourite f JOIN status s ON s.id = f.status_id \
          WHERE f.account_id = $1 AND s.deleted_at IS NULL \
            AND ($2::text IS NULL OR s.id < $2) \
          ORDER BY s.id DESC LIMIT $3"
    );
    sqlx::query_as::<_, StatusRow>(&sql)
        .bind(account_id)
        .bind(max_id)
        .bind(limit)
        .fetch_all(pool)
        .await
}

/// A page of bookmarked statuses, oldest cursor first.
pub async fn bookmarks(
    pool: &PgPool,
    account_id: &str,
    max_id: Option<&str>,
    limit: i64,
) -> Result<Vec<StatusRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {STATUS_COLUMNS} FROM bookmark b JOIN status s ON s.id = b.status_id \
          WHERE b.account_id = $1 AND s.deleted_at IS NULL \
            AND ($2::text IS NULL OR s.id < $2) \
          ORDER BY s.id DESC LIMIT $3"
    );
    sqlx::query_as::<_, StatusRow>(&sql)
        .bind(account_id)
        .bind(max_id)
        .bind(limit)
        .fetch_all(pool)
        .await
}

/// One row of `custom_emoji`, in the shape Mastodon's payload expects.
#[derive(Debug, Clone, FromRow)]
pub struct CustomEmojiRow {
    pub shortcode: String,
    pub url: String,
    pub category: Option<String>,
    pub visible_in_picker: bool,
}

/// The emoji a picker should offer: local ones, plus remote ones already in use.
///
/// `visible_in_picker = false` rows are hidden but still renderable inside text, which
/// is why the caller gets them separately rather than as a filter on the query.
pub async fn custom_emojis(
    pool: &PgPool,
    local_only: bool,
) -> Result<Vec<CustomEmojiRow>, sqlx::Error> {
    sqlx::query_as::<_, CustomEmojiRow>(
        "SELECT shortcode, url, category, visible_in_picker FROM custom_emoji \
          WHERE visible_in_picker AND ($1 = false OR host = '') \
          ORDER BY shortcode ASC",
    )
    .bind(local_only)
    .fetch_all(pool)
    .await
}
