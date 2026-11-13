//! Instance announcements and per-account read state.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use sqlx::PgPool;

#[derive(Debug, Clone, FromRow)]
pub struct AnnouncementRow {
    pub id: String,
    pub content: String,
    pub published: bool,
    pub all_day: bool,
    pub starts_at: Option<DateTime<Utc>>,
    pub ends_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub read: bool,
}

#[derive(Debug, Clone)]
pub struct NewAnnouncement<'a> {
    pub content: &'a str,
    pub published: bool,
    pub all_day: bool,
    pub starts_at: Option<DateTime<Utc>>,
    pub ends_at: Option<DateTime<Utc>>,
}

const COLUMNS: &str = "a.id, a.content, a.published, a.all_day, a.starts_at, a.ends_at, \
     a.created_at, a.updated_at";
const RETURNING: &str = "id, content, published, all_day, starts_at, ends_at, created_at, updated_at";

/// Announcements visible to an account, with its read state.
pub async fn list_for(
    pool: &PgPool,
    account_id: Option<&str>,
    limit: i64,
) -> Result<Vec<AnnouncementRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS}, (r.read_at IS NOT NULL) AS read \
         FROM announcement a \
         LEFT JOIN announcement_read r ON r.announcement_id = a.id AND r.account_id = $1 \
         WHERE a.published AND (a.starts_at IS NULL OR a.starts_at <= now()) \
           AND (a.ends_at IS NULL OR a.ends_at > now()) \
         ORDER BY a.created_at DESC LIMIT $2"
    ))
    .bind(account_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Every announcement, published or not, for staff.
pub async fn list_all(pool: &PgPool, limit: i64) -> Result<Vec<AnnouncementRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {RETURNING}, false AS read FROM announcement \
         ORDER BY created_at DESC LIMIT $1"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn create(
    pool: &PgPool,
    entry: &NewAnnouncement<'_>,
) -> Result<AnnouncementRow, sqlx::Error> {
    sqlx::query_as(&format!(
        "INSERT INTO announcement (id, content, published, all_day, starts_at, ends_at) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING {RETURNING}, false AS read"
    ))
    .bind(nodus_server_core::id::Id::new().to_string())
    .bind(entry.content)
    .bind(entry.published)
    .bind(entry.all_day)
    .bind(entry.starts_at)
    .bind(entry.ends_at)
    .fetch_one(pool)
    .await
}

pub async fn update(
    pool: &PgPool,
    id: &str,
    entry: &NewAnnouncement<'_>,
) -> Result<Option<AnnouncementRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "UPDATE announcement SET content = $2, published = $3, all_day = $4, \
         starts_at = $5, ends_at = $6, updated_at = now() \
         WHERE id = $1 RETURNING {RETURNING}, false AS read"
    ))
    .bind(id)
    .bind(entry.content)
    .bind(entry.published)
    .bind(entry.all_day)
    .bind(entry.starts_at)
    .bind(entry.ends_at)
    .fetch_optional(pool)
    .await
}

pub async fn delete(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    let done = sqlx::query("DELETE FROM announcement WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() > 0)
}

pub async fn dismiss(pool: &PgPool, account_id: &str, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO announcement_read (account_id, announcement_id) VALUES ($1, $2) \
         ON CONFLICT (account_id, announcement_id) DO UPDATE SET read_at = now()",
    )
    .bind(account_id)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}
