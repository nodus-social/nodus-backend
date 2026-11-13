//! Uploaded media rows.
//!
//! Bytes live in the object store; this module owns only the catalogue. An
//! attachment is uploaded before the status it belongs to exists, so `status_id`
//! starts null and is claimed by the author when the status is created.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

/// A row of `media_attachment`.
#[derive(Debug, Clone, FromRow)]
pub struct MediaRow {
    pub id: String,
    pub account_id: String,
    pub status_id: Option<String>,
    pub digest: String,
    pub content_type: String,
    pub size: i64,
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub blurhash: Option<String>,
    pub description: String,
    pub sensitive: bool,
    pub created_at: DateTime<Utc>,
}

const MEDIA_COLUMNS: &str = "id, account_id, status_id, digest, content_type, size, width, \
     height, blurhash, description, sensitive, created_at";

/// Inserts an unattached upload.
pub async fn insert(pool: &PgPool, media: &MediaRow) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO media_attachment \
         (id, account_id, status_id, digest, content_type, size, width, height, blurhash, \
          description, sensitive, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(&media.id)
    .bind(&media.account_id)
    .bind(&media.status_id)
    .bind(&media.digest)
    .bind(&media.content_type)
    .bind(media.size)
    .bind(media.width)
    .bind(media.height)
    .bind(&media.blurhash)
    .bind(&media.description)
    .bind(media.sensitive)
    .bind(media.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// One attachment by id.
pub async fn by_id(pool: &PgPool, id: &str) -> Result<Option<MediaRow>, sqlx::Error> {
    let sql = format!("SELECT {MEDIA_COLUMNS} FROM media_attachment WHERE id = $1");
    sqlx::query_as::<_, MediaRow>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// Attachments for a status, oldest first.
pub async fn by_status(pool: &PgPool, status_id: &str) -> Result<Vec<MediaRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {MEDIA_COLUMNS} FROM media_attachment \
         WHERE status_id = $1 ORDER BY created_at ASC, id ASC"
    );
    sqlx::query_as::<_, MediaRow>(&sql)
        .bind(status_id)
        .fetch_all(pool)
        .await
}

/// Attachments by id, in the order requested.
pub async fn by_ids(pool: &PgPool, ids: &[String]) -> Result<Vec<MediaRow>, sqlx::Error> {
    let sql = format!("SELECT {MEDIA_COLUMNS} FROM media_attachment WHERE id = ANY($1)");
    sqlx::query_as::<_, MediaRow>(&sql)
        .bind(ids)
        .fetch_all(pool)
        .await
}

/// Attachments for several statuses in one query.
pub async fn by_statuses(
    pool: &PgPool,
    status_ids: &[String],
) -> Result<Vec<MediaRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {MEDIA_COLUMNS} FROM media_attachment \
         WHERE status_id = ANY($1) ORDER BY created_at ASC, id ASC"
    );
    sqlx::query_as::<_, MediaRow>(&sql)
        .bind(status_ids)
        .fetch_all(pool)
        .await
}

/// Claims unattached uploads for a status. Only the owner may attach them.
pub async fn attach(
    pool: &PgPool,
    ids: &[String],
    account_id: &str,
    status_id: &str,
) -> Result<u64, sqlx::Error> {
    if ids.is_empty() {
        return Ok(0);
    }
    let result = sqlx::query(
        "UPDATE media_attachment SET status_id = $1 \
         WHERE id = ANY($2) AND account_id = $3 AND status_id IS NULL",
    )
    .bind(status_id)
    .bind(ids)
    .bind(account_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Updates the author-controlled fields.
pub async fn update(
    pool: &PgPool,
    id: &str,
    account_id: &str,
    description: &str,
    sensitive: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE media_attachment SET description = $1, sensitive = $2 \
         WHERE id = $3 AND account_id = $4",
    )
    .bind(description)
    .bind(sensitive)
    .bind(id)
    .bind(account_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Stores the generated placeholder and dimensions.
pub async fn set_preview(
    pool: &PgPool,
    id: &str,
    blurhash: &str,
    width: i32,
    height: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE media_attachment SET blurhash = $1, width = $2, height = $3 WHERE id = $4")
        .bind(blurhash)
        .bind(width)
        .bind(height)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}
