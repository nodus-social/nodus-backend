//! Uploaded media rows.
//!
//! Bytes live in the object store; this module owns only the catalogue. An
//! attachment is uploaded before the status it belongs to exists, so `status_id`
//! starts null and is claimed by the author when the status is created.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

/// A row of `media_attachment`.
/// The flags are a row's state, not a bag of options: whether the bytes stayed on the
/// peer, whether the author marked it sensitive, whether it is lossless, and whether the
/// original was pruned are four independent facts about one attachment.
#[allow(
    clippy::struct_excessive_bools,
    reason = "a database row, not an option struct"
)]
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
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
    /// True when the bytes stayed on the peer and only a link is stored here.
    pub remote: bool,
    /// Where a remote attachment lives when we never copied the bytes.
    pub remote_url: Option<String>,
    /// SHA-256 of the bytes as they arrived, lowercase hex; null until the check ran.
    pub content_hash: Option<String>,
    /// 64-bit dHash of the decoded image, 16 hex characters; null for anything that is
    /// not a picture we could decode.
    pub perceptual_hash: Option<String>,
    /// 'none', 'quarantined' or 'released'. See `0036_media_hashes.sql`.
    pub quarantine_state: String,
    /// The content set that matched, when one did.
    pub quarantine_set: Option<String>,
    pub created_at: DateTime<Utc>,
}

const MEDIA_COLUMNS: &str = "id, account_id, status_id, digest, content_type, size, width, \
     height, blurhash, description, sensitive, lossless, processing_state, processing_progress, \
     processing_error, original_pruned, remote, NULLIF(meta->>'url', '') AS remote_url, \
     content_hash, perceptual_hash, quarantine_state, quarantine_set, created_at";

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

/// An attachment a remote status points at.
#[derive(Debug, Clone)]
pub struct RemoteAttachment<'a> {
    pub url: &'a str,
    pub content_type: &'a str,
    pub description: &'a str,
    pub width: Option<i32>,
    pub height: Option<i32>,
    /// The peer's placeholder, when it sent one; the bytes were never decoded here.
    pub blurhash: Option<&'a str>,
}

/// Replaces the remote attachments of a status.
///
/// The bytes stay on the peer, so the row records only where they are; the digest is
/// synthetic because nothing was hashed here, and the state is `ready` because there is
/// no local processing to wait for.
pub async fn replace_remote(
    pool: &PgPool,
    status_id: &str,
    account_id: &str,
    sensitive: bool,
    attachments: &[RemoteAttachment<'_>],
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    // A moderator's release outlives the peer's edit: the state travels with the URL it was
    // decided about, so an `Update` that resends the same picture does not quarantine it
    // again. Without this the release would last until the author edited their post.
    let previous: Vec<(String, String)> = sqlx::query_as(
        "SELECT meta->>'url' AS url, quarantine_state FROM media_attachment \
         WHERE status_id = $1 AND remote AND meta->>'url' IS NOT NULL",
    )
    .bind(status_id)
    .fetch_all(&mut *tx)
    .await?;
    let carried: std::collections::HashMap<String, String> = previous.into_iter().collect();
    sqlx::query("DELETE FROM media_attachment WHERE status_id = $1 AND remote")
        .bind(status_id)
        .execute(&mut *tx)
        .await?;
    for (index, attachment) in attachments.iter().enumerate() {
        sqlx::query(
            "INSERT INTO media_attachment (id, account_id, status_id, digest, content_type, \
                 size, width, height, blurhash, description, sensitive, remote, \
                 processing_state, processing_progress, meta, quarantine_state, created_at) \
             VALUES ($1, $2, $3, $4, $5, 0, $6, $7, $8, $9, $10, true, 'ready', 100, \
                 jsonb_build_object('url', $11::text), $12, now())",
        )
        .bind(nodus_server_core::Id::new().to_string())
        .bind(account_id)
        .bind(status_id)
        .bind(format!("remote:{status_id}:{index}"))
        .bind(attachment.content_type)
        .bind(attachment.width)
        .bind(attachment.height)
        .bind(attachment.blurhash)
        .bind(attachment.description)
        .bind(sensitive)
        .bind(attachment.url)
        .bind(carried.get(attachment.url).map_or("none", String::as_str))
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
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
    pub max_edge: i64,
    pub object_key: String,
    pub content_type: String,
    pub digest: String,
    pub size: i64,
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

const VARIANT_COLUMNS: &str = "media_id, layer, max_edge, object_key, content_type, digest, size, \
     width, height, expires_at, created_at";

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
            "INSERT INTO media_variant (media_id, layer, max_edge, object_key, content_type, \
             digest, size, width, height, expires_at, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(&variant.media_id)
        .bind(&variant.layer)
        .bind(variant.max_edge)
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

/// One variant by layer (picking the highest-resolution rendition when a layer has several).
pub async fn variant(
    pool: &PgPool,
    media_id: &str,
    layer: &str,
) -> Result<Option<VariantRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {VARIANT_COLUMNS} FROM media_variant \
         WHERE media_id = $1 AND layer = $2 ORDER BY max_edge DESC LIMIT 1"
    );
    sqlx::query_as::<_, VariantRow>(&sql)
        .bind(media_id)
        .bind(layer)
        .fetch_optional(pool)
        .await
}

/// All variants for one attachment.
pub async fn variants(pool: &PgPool, media_id: &str) -> Result<Vec<VariantRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {VARIANT_COLUMNS} FROM media_variant WHERE media_id = $1 ORDER BY layer, max_edge"
    );
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

/// Digests removed when pruning expired unattached media uploads.
#[derive(Debug, Clone, Default)]
pub struct PrunedUnattached {
    pub original_digests: Vec<String>,
    pub variant_digests: Vec<String>,
}

/// Deletes unattached media uploads older than 24 hours along with their variants,
/// returning the original and variant digests that may now be unreferenced on disk.
///
/// An avatar or a header has no status either, so "unattached" cannot mean "no status":
/// a profile references its picture as `<media id>/<layer>` in `account.avatar_ref` and
/// `header_ref`, and pruning the row removes a face the account still points at.
pub async fn delete_expired_unattached(pool: &PgPool) -> Result<PrunedUnattached, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT m.id FROM media_attachment m \
         WHERE m.status_id IS NULL AND m.created_at < now() - interval '24 hours' \
           AND NOT EXISTS (SELECT 1 FROM account a \
                            WHERE split_part(a.avatar_ref, '/', 1) = m.id \
                               OR split_part(a.header_ref, '/', 1) = m.id) \
         LIMIT 200 \
         FOR UPDATE SKIP LOCKED",
    )
    .fetch_all(&mut *tx)
    .await?;
    if ids.is_empty() {
        tx.commit().await?;
        return Ok(PrunedUnattached::default());
    }
    let variant_digests: Vec<String> =
        sqlx::query_scalar("DELETE FROM media_variant WHERE media_id = ANY($1) RETURNING digest")
            .bind(&ids)
            .fetch_all(&mut *tx)
            .await?;
    let original_digests: Vec<String> =
        sqlx::query_scalar("DELETE FROM media_attachment WHERE id = ANY($1) RETURNING digest")
            .bind(&ids)
            .fetch_all(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(PrunedUnattached {
        original_digests,
        variant_digests,
    })
}

/// One page of catalogue digests, ordered by id, strictly after the previous page's last
/// id.
///
/// Keyset paging rather than `OFFSET`: the repair walk must not skip a row because a
/// deletion earlier in the list shifted everything after it. The digest is returned with
/// the id only because the id is what the next page is asked for.
pub async fn digest_page(
    pool: &PgPool,
    after: Option<&str>,
    limit: i64,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, digest FROM media_attachment \
          WHERE $1::text IS NULL OR id > $1 \
          ORDER BY id LIMIT $2",
    )
    .bind(after)
    .bind(limit)
    .fetch_all(pool)
    .await
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

/// Records what the accepted bytes hashed to.
///
/// Called once per attachment, right after the fetch that produced them; the hash is the
/// only thing kept, the bytes stay on the peer.
pub async fn set_hashes(
    pool: &PgPool,
    id: &str,
    content_hash: &str,
    perceptual_hash: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE media_attachment SET content_hash = $1, perceptual_hash = $2 WHERE id = $3",
    )
    .bind(content_hash)
    .bind(perceptual_hash)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Marks one attachment as matched by a named content set.
///
/// Only an unquarantined row moves: a second match on a picture a moderator already
/// released must not put it back in the queue. Returns whether this call changed
/// anything, so the caller can avoid opening a duplicate report.
pub async fn quarantine(pool: &PgPool, id: &str, set: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE media_attachment SET quarantine_state = 'quarantined', quarantine_set = $2 \
         WHERE id = $1 AND quarantine_state = 'none'",
    )
    .bind(id)
    .bind(set)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Clears a quarantine, keeping the record that one happened.
pub async fn release_quarantine(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE media_attachment SET quarantine_state = 'released' \
         WHERE id = $1 AND quarantine_state = 'quarantined'",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// How many attachments of a status are still hidden, so the status itself can be
/// un-hidden only when the last one is cleared.
pub async fn quarantined_count(pool: &PgPool, status_id: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*)::bigint FROM media_attachment \
         WHERE status_id = $1 AND quarantine_state = 'quarantined'",
    )
    .bind(status_id)
    .fetch_one(pool)
    .await
}

/// Every attachment a content set has acted on, newest first.
pub async fn quarantined(pool: &PgPool, limit: i64) -> Result<Vec<MediaRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {MEDIA_COLUMNS} FROM media_attachment \
         WHERE quarantine_state <> 'none' ORDER BY created_at DESC LIMIT $1"
    );
    sqlx::query_as::<_, MediaRow>(&sql)
        .bind(limit)
        .fetch_all(pool)
        .await
}

/// Removes an attachment row for good. Variants go with it (`ON DELETE CASCADE`); there is
/// no original to unlink, because a federated attachment never had one here.
pub async fn delete(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM media_attachment WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{self, NewAccount};
    use nodus_server_core::Id;

    #[sqlx::test(migrations = "./migrations")]
    async fn replace_variants_supports_multiple_compressed_video_renditions(pool: PgPool) {
        let pool = &pool;

        let username = format!("media_test_{}", Id::new());
        let account = accounts::insert(
            pool,
            &NewAccount {
                username: &username,
                display_name: "Media Test",
                note: "",
                bot: false,
                locked: false,
            },
        )
        .await
        .expect("insert account");

        let media_id = Id::new().to_string();
        let now = Utc::now();
        insert(
            pool,
            &MediaRow {
                id: media_id.clone(),
                account_id: account.id.clone(),
                status_id: None,
                digest: format!("digest-{media_id}"),
                content_type: "video/mp4".to_owned(),
                size: 1024,
                width: Some(1280),
                height: Some(720),
                blurhash: None,
                description: String::new(),
                sensitive: false,
                lossless: false,
                processing_state: "processing".to_owned(),
                processing_progress: 50,
                processing_error: None,
                original_pruned: false,
                remote: false,
                content_hash: None,
                perceptual_hash: None,
                quarantine_state: "none".to_owned(),
                quarantine_set: None,
                remote_url: None,
                created_at: now,
            },
        )
        .await
        .expect("insert media");

        let rows = vec![
            VariantRow {
                media_id: media_id.clone(),
                layer: "preview".to_owned(),
                max_edge: 1280,
                object_key: format!("media/{media_id}/preview/p"),
                content_type: "video/webm".to_owned(),
                digest: "digest-preview".to_owned(),
                size: 100,
                width: None,
                height: None,
                expires_at: None,
                created_at: now,
            },
            VariantRow {
                media_id: media_id.clone(),
                layer: "compressed".to_owned(),
                max_edge: 360,
                object_key: format!("media/{media_id}/compressed/360"),
                content_type: "video/webm".to_owned(),
                digest: "digest-360".to_owned(),
                size: 200,
                width: None,
                height: None,
                expires_at: Some(now + chrono::Duration::hours(72)),
                created_at: now,
            },
            VariantRow {
                media_id: media_id.clone(),
                layer: "compressed".to_owned(),
                max_edge: 720,
                object_key: format!("media/{media_id}/compressed/720"),
                content_type: "video/webm".to_owned(),
                digest: "digest-720".to_owned(),
                size: 400,
                width: None,
                height: None,
                expires_at: Some(now + chrono::Duration::hours(72)),
                created_at: now,
            },
            VariantRow {
                media_id: media_id.clone(),
                layer: "compressed".to_owned(),
                max_edge: 1080,
                object_key: format!("media/{media_id}/compressed/1080"),
                content_type: "video/webm".to_owned(),
                digest: "digest-1080".to_owned(),
                size: 800,
                width: None,
                height: None,
                expires_at: Some(now + chrono::Duration::hours(72)),
                created_at: now,
            },
            VariantRow {
                media_id: media_id.clone(),
                layer: "lossless".to_owned(),
                max_edge: i64::from(u32::MAX),
                object_key: format!("media/{media_id}/lossless/orig"),
                content_type: "video/mp4".to_owned(),
                digest: "digest-lossless".to_owned(),
                size: 1024,
                width: None,
                height: None,
                expires_at: None,
                created_at: now,
            },
        ];

        replace_variants(pool, &media_id, &rows)
            .await
            .expect("replace_variants should allow multiple compressed renditions");

        let stored = variants(pool, &media_id).await.expect("variants");
        assert_eq!(stored.len(), 5);
        let best_compressed = variant(pool, &media_id, "compressed")
            .await
            .expect("variant")
            .expect("compressed variant");
        assert_eq!(best_compressed.max_edge, 1080);
        assert_eq!(best_compressed.digest, "digest-1080");

        let _ = sqlx::query("DELETE FROM account WHERE id = $1")
            .bind(&account.id)
            .execute(pool)
            .await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_profile_picture_is_not_an_unattached_upload(pool: PgPool) {
        let pool = &pool;

        let username = format!("media_face_{}", Id::new());
        let account = accounts::insert(
            pool,
            &NewAccount {
                username: &username,
                display_name: "Face Test",
                note: "",
                bot: false,
                locked: false,
            },
        )
        .await
        .expect("insert account");

        let face = Id::new().to_string();
        let upload = Id::new().to_string();
        let old = Utc::now() - chrono::Duration::hours(48);
        for id in [&face, &upload] {
            insert(
                pool,
                &MediaRow {
                    id: id.clone(),
                    account_id: account.id.clone(),
                    status_id: None,
                    digest: format!("digest-{id}"),
                    content_type: "image/png".to_owned(),
                    size: 512,
                    width: Some(400),
                    height: Some(400),
                    blurhash: None,
                    description: String::new(),
                    sensitive: false,
                    lossless: false,
                    processing_state: "ready".to_owned(),
                    processing_progress: 100,
                    processing_error: None,
                    original_pruned: false,
                    remote: false,
                    content_hash: None,
                    perceptual_hash: None,
                    quarantine_state: "none".to_owned(),
                    quarantine_set: None,
                    remote_url: None,
                    created_at: old,
                },
            )
            .await
            .expect("insert media");
        }
        sqlx::query("UPDATE account SET avatar_ref = $1 WHERE id = $2")
            .bind(format!("{face}/preview"))
            .bind(&account.id)
            .execute(pool)
            .await
            .expect("set the avatar");

        let pruned = delete_expired_unattached(pool)
            .await
            .expect("delete_expired_unattached");

        assert_eq!(pruned.original_digests, vec![format!("digest-{upload}")]);
        assert!(
            by_id(pool, &face).await.expect("by_id").is_some(),
            "the picture the profile points at must survive the prune"
        );

        let _ = sqlx::query("DELETE FROM account WHERE id = $1")
            .bind(&account.id)
            .execute(pool)
            .await;
    }
}
