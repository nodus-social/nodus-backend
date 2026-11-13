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
    pub lossless: bool,
    pub processing_state: String,
    pub processing_progress: i16,
    pub processing_error: Option<String>,
    pub original_pruned: bool,
    pub created_at: DateTime<Utc>,
}

const MEDIA_COLUMNS: &str = "id, account_id, status_id, digest, content_type, size, width, \
     height, blurhash, description, sensitive, lossless, processing_state, processing_progress, \
     processing_error, original_pruned, created_at";

/// Inserts an unattached upload.
pub async fn insert(pool: &PgPool, media: &MediaRow) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO media_attachment \
         (id, account_id, status_id, digest, content_type, size, width, height, blurhash, \
          description, sensitive, lossless, processing_state, processing_progress, \
          processing_error, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
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
    .bind(media.lossless)
    .bind(&media.processing_state)
    .bind(media.processing_progress)
    .bind(&media.processing_error)
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

/// A produced variant row.
#[derive(Debug, Clone, FromRow)]
pub struct VariantRow {
    pub media_id: String,
    pub layer: String,
    pub object_key: String,
    pub content_type: String,
    pub digest: String,
    pub size: i64,
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

const VARIANT_COLUMNS: &str = "media_id, layer, object_key, content_type, digest, size, width, \
     height, expires_at, created_at";

/// Replaces every generated variant for one attachment.
pub async fn replace_variants(
    pool: &PgPool,
    media_id: &str,
    variants: &[VariantRow],
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM media_variant WHERE media_id = $1")
        .bind(media_id)
        .execute(&mut *tx)
        .await?;
    for variant in variants {
        sqlx::query(
            "INSERT INTO media_variant (media_id, layer, object_key, content_type, digest, size, \
             width, height, expires_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(&variant.media_id)
        .bind(&variant.layer)
        .bind(&variant.object_key)
        .bind(&variant.content_type)
        .bind(&variant.digest)
        .bind(variant.size)
        .bind(variant.width)
        .bind(variant.height)
        .bind(variant.expires_at)
        .bind(variant.created_at)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await
}

/// One variant by layer.
pub async fn variant(
    pool: &PgPool,
    media_id: &str,
    layer: &str,
) -> Result<Option<VariantRow>, sqlx::Error> {
    let sql =
        format!("SELECT {VARIANT_COLUMNS} FROM media_variant WHERE media_id = $1 AND layer = $2");
    sqlx::query_as::<_, VariantRow>(&sql)
        .bind(media_id)
        .bind(layer)
        .fetch_optional(pool)
        .await
}

/// All variants for one attachment.
pub async fn variants(pool: &PgPool, media_id: &str) -> Result<Vec<VariantRow>, sqlx::Error> {
    let sql =
        format!("SELECT {VARIANT_COLUMNS} FROM media_variant WHERE media_id = $1 ORDER BY layer");
    sqlx::query_as::<_, VariantRow>(&sql)
        .bind(media_id)
        .fetch_all(pool)
        .await
}

/// Updates the processing status shown to the author.
pub async fn set_processing(
    pool: &PgPool,
    id: &str,
    state: &str,
    progress: i16,
    error: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE media_attachment SET processing_state = $1, processing_progress = $2, \
         processing_error = $3 WHERE id = $4",
    )
    .bind(state)
    .bind(progress.clamp(0, 100))
    .bind(error)
    .bind(id)
    .execute(pool)
    .await
    .map(drop)
}

/// Deletes expired variants and returns the files that are no longer referenced.
pub async fn delete_expired_variants(pool: &PgPool) -> Result<Vec<String>, sqlx::Error> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "DELETE FROM media_variant WHERE expires_at IS NOT NULL AND expires_at < now() \
         RETURNING digest",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(digest,)| digest).collect())
}

/// Deletes the untouched upload for posts that did not opt into lossless after the
/// decision window. Returns the digests removed.
pub async fn expired_originals(pool: &PgPool) -> Result<Vec<String>, sqlx::Error> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "WITH picked AS ( \
             SELECT m.id FROM media_attachment m WHERE m.lossless = false \
               AND m.status_id IS NOT NULL AND m.original_pruned = false \
               AND m.created_at < now() - interval '24 hours' \
               AND NOT EXISTS (SELECT 1 FROM media_variant v \
                                WHERE v.media_id = m.id AND v.layer = 'lossless') \
             LIMIT 200) \
         UPDATE media_attachment m SET original_pruned = true FROM picked \
          WHERE m.id = picked.id RETURNING m.digest",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(digest,)| digest).collect())
}

/// Whether any variant row still uses this content digest.
pub async fn variant_digest_referenced(pool: &PgPool, digest: &str) -> Result<bool, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT count(*) FROM media_variant WHERE digest = $1")
        .bind(digest)
        .fetch_one(pool)
        .await?;
    Ok(row.0 > 0)
}

/// Whether any attachment still points at this untouched original.
pub async fn original_digest_referenced(pool: &PgPool, digest: &str) -> Result<bool, sqlx::Error> {
    let row: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM media_attachment WHERE digest = $1 AND original_pruned = false",
    )
    .bind(digest)
    .fetch_one(pool)
    .await?;
    Ok(row.0 > 0)
}
