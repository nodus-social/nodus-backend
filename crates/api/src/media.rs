//! Media upload, metadata and byte serving.
//!
//! Uploads are content-addressed: the catalogue id is ours, the stored name is the
//! digest. That makes a retry idempotent at the object layer even though it creates a
//! second catalogue row.

use std::path::PathBuf;

use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use nodus_server_core::id::Id;
use nodus_server_core::limits::{IMAGE_SIZE_LIMIT, VIDEO_SIZE_LIMIT};
use nodus_server_media::{
    expires_in, plan_with_permissions, CachePolicy, Kind, Layer, LosslessPermissions, VariantSpec,
};
use nodus_server_store::media::{self, MediaRow, VariantRow};

use crate::auth::Auth;
use crate::dto::MediaAttachmentDto;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

const MAX_UPLOAD: usize = 40 * 1024 * 1024;
const MAX_DESCRIPTION: usize = 1_500;

/// `/api/v1/media`, `/api/v2/media`.
///
/// Uploads and their metadata. The bytes are served by `nodus-media`, which reads the same
/// catalogue.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/media", post(upload))
        .route("/api/v2/media", post(upload))
        .route("/api/v1/media/{id}", get(show).put(update))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD))
}

/// Where originals are kept: the deployment decides, the default is for a checkout.
fn storage_dir() -> PathBuf {
    std::env::var_os("NODUS_MEDIA_DIR").map_or_else(|| PathBuf::from("./media"), PathBuf::from)
}

/// Where generated variants are kept, beside the originals unless the deployment separates them.
fn variants_dir() -> PathBuf {
    std::env::var_os("NODUS_MEDIA_VARIANTS_DIR")
        .map_or_else(|| storage_dir().join("variants"), PathBuf::from)
}

/// Removes a digest's bytes for good, across the cluster when there is one.
///
/// The media service answers the delete and fans it out to every member, which is the only
/// way an old replica that stopped being the owner loses its copy. With no cluster token
/// there is no peer to ask, so the local copy is unlinked exactly as before; the same
/// unlink is the fallback when the media service does not confirm.
pub async fn delete_original(digest: &str) {
    let token = std::env::var("NODUS_MEDIA_CLUSTER_TOKEN")
        .ok()
        .filter(|token| !token.is_empty());
    if let Some(token) = token {
        let base = std::env::var("NODUS_MEDIA_INTERNAL_URL")
            .ok()
            .filter(|url| !url.is_empty())
            .unwrap_or_else(|| "http://127.0.0.1:3003".to_owned());
        if nodus_server_media::cluster::request_delete(&base, &token, digest).await {
            return;
        }
        tracing::warn!(%digest, %base, "the media service did not confirm a cluster delete");
    }
    remove_local_original(digest).await;
}

/// The single-node fallback: unlink this process's copy, tolerating absence.
async fn remove_local_original(digest: &str) {
    if !is_digest(digest) {
        return;
    }
    let path = storage_dir().join(digest);
    match tokio::fs::remove_file(&path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(%error, path = %path.display(), "could not remove a media original");
        }
    }
}

/// The digest becomes a file name, so only a lowercase SHA-256 hex string may reach it.
fn is_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// `POST /api/v1/media` — multipart `file`, `description`, `sensitive`.
#[allow(clippy::too_many_lines)]
pub async fn upload(
    State(state): State<AppState>,
    auth: Auth,
    mut multipart: Multipart,
) -> ApiResult<Json<MediaAttachmentDto>> {
    auth.require_scope("write")?;
    let mut bytes: Option<Vec<u8>> = None;
    let mut content_type = "application/octet-stream".to_owned();
    let mut description = String::new();
    let mut sensitive = false;
    let mut lossless = false;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| ApiError::unprocessable("Malformed multipart body"))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "file" => {
                if let Some(value) = field.content_type() {
                    content_type = value.to_owned();
                }
                bytes = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|_| ApiError::unprocessable("Could not read the upload"))?
                        .to_vec(),
                );
            }
            "description" => {
                description = field
                    .text()
                    .await
                    .map_err(|_| ApiError::unprocessable("Invalid description"))?;
            }
            "sensitive" => {
                sensitive = field
                    .text()
                    .await
                    .map_err(|_| ApiError::unprocessable("Invalid sensitive flag"))?
                    .parse()
                    .unwrap_or(false);
            }
            "lossless" => {
                lossless = field
                    .text()
                    .await
                    .map_err(|_| ApiError::unprocessable("Invalid lossless flag"))?
                    .parse()
                    .unwrap_or(false);
            }
            _ => {}
        }
    }

    let bytes = bytes.ok_or_else(|| ApiError::unprocessable("A file is required"))?;
    if bytes.is_empty() {
        return Err(ApiError::unprocessable("The upload is empty"));
    }
    if !(content_type.starts_with("image/")
        || content_type.starts_with("video/")
        || content_type.starts_with("audio/"))
    {
        return Err(ApiError::unprocessable("Unsupported media type"));
    }
    if description.chars().count() > MAX_DESCRIPTION {
        return Err(ApiError::unprocessable("The description is too long"));
    }

    let kind = Kind::from_content_type(&content_type);
    let size_limit = if kind == Kind::Video {
        VIDEO_SIZE_LIMIT
    } else {
        IMAGE_SIZE_LIMIT
    };
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > size_limit {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "The upload is too large",
        ));
    }
    let permissions = LosslessPermissions {
        images: auth.0.account.lossless_images_allowed,
        videos: auth.0.account.lossless_videos_allowed,
    };
    if lossless && !permissions.allows(kind) {
        return Err(ApiError::unprocessable(
            "Lossless media is not allowed for this account",
        ));
    }

    let digest = hex(&Sha256::digest(&bytes));
    let dir = storage_dir();
    tokio::fs::create_dir_all(&dir).await?;
    tokio::fs::create_dir_all(variants_dir()).await?;
    let source = dir.join(&digest);
    tokio::fs::write(&source, &bytes).await?;

    let id = Id::new().to_string();
    let mut row = MediaRow {
        id: id.clone(),
        account_id: auth.0.account.id.clone(),
        status_id: None,
        digest,
        content_type,
        size: i64::try_from(bytes.len()).unwrap_or(i64::MAX),
        width: None,
        height: None,
        blurhash: None,
        description,
        sensitive,
        lossless,
        processing_state: "pending".to_owned(),
        processing_progress: 0,
        processing_error: None,
        original_pruned: false,
        remote: false,
        content_hash: None,
        perceptual_hash: None,
        quarantine_state: "none".to_owned(),
        quarantine_set: None,
        remote_url: None,
        created_at: Utc::now(),
    };

    if row.content_type.starts_with("image/") {
        match nodus_server_media::blurhash(&bytes) {
            Ok(preview) => {
                row.blurhash = Some(preview.blurhash);
                row.width = i32::try_from(preview.width).ok();
                row.height = i32::try_from(preview.height).ok();
            }
            Err(error) => tracing::warn!(%error, "could not build a media placeholder"),
        }
    } else if kind == Kind::Video {
        if let Some((width, height)) = nodus_server_media::process::video_dimensions(&source).await
        {
            row.width = i32::try_from(width).ok();
            row.height = i32::try_from(height).ok();
        }
    }

    media::insert(state.store().pool(), &row).await?;

    let plan = plan_with_permissions(
        kind,
        u32::try_from(row.width.unwrap_or(1280)).unwrap_or(1280),
        u32::try_from(row.height.unwrap_or(720)).unwrap_or(720),
        lossless,
        permissions,
    )
    .map_err(|error| ApiError::unprocessable(error.to_string()))?;
    let pool = state.store().pool().clone();
    let media_id = id.clone();
    let source_digest = row.digest.clone();
    let content_type = row.content_type.clone();
    tokio::spawn(async move {
        process_upload(
            pool,
            media_id,
            source,
            source_digest,
            content_type,
            kind,
            plan,
            lossless,
        )
        .await;
    });

    Ok(Json(MediaAttachmentDto::from_row(&row, state.instance())))
}

#[allow(clippy::too_many_arguments)]
async fn process_upload(
    pool: PgPool,
    id: String,
    source: PathBuf,
    source_digest: String,
    source_content_type: String,
    kind: Kind,
    plan: Vec<VariantSpec>,
    lossless: bool,
) {
    process_upload_in(
        pool,
        id,
        source,
        source_digest,
        source_content_type,
        kind,
        plan,
        lossless,
        &variants_dir(),
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn process_upload_in(
    pool: PgPool,
    id: String,
    source: PathBuf,
    source_digest: String,
    source_content_type: String,
    kind: Kind,
    plan: Vec<VariantSpec>,
    lossless: bool,
    variant_dir: &std::path::Path,
) {
    if let Err(error) = media::set_processing(&pool, &id, "processing", 5, None).await {
        tracing::error!(%error, %id, "could not mark media processing");
        return;
    }
    let policy = CachePolicy::default();
    let mut rows = Vec::new();
    let total = plan.len().max(1);
    for (index, spec) in plan.iter().enumerate() {
        if spec.layer == Layer::Lossless && !lossless {
            continue;
        }
        match nodus_server_media::process::render_one(&source, kind, spec).await {
            Ok(rendered) => {
                let digest = hex(&Sha256::digest(&rendered.bytes));
                let path = variant_dir.join(&digest);
                if let Err(error) = tokio::fs::write(&path, &rendered.bytes).await {
                    fail(&pool, &id, &error.to_string()).await;
                    return;
                }
                rows.push(VariantRow {
                    media_id: id.clone(),
                    layer: spec.layer.as_str().to_owned(),
                    max_edge: i64::from(spec.max_edge),
                    object_key: nodus_server_media::object_key(&source_digest, &digest, spec.layer),
                    content_type: if spec.layer == Layer::Lossless {
                        source_content_type.clone()
                    } else {
                        rendered.content_type.to_owned()
                    },
                    digest,
                    size: i64::try_from(rendered.bytes.len()).unwrap_or(i64::MAX),
                    width: None,
                    height: None,
                    expires_at: expires_in(policy, spec).and_then(|ttl| {
                        chrono::Duration::from_std(ttl)
                            .ok()
                            .map(|ttl| Utc::now() + ttl)
                    }),
                    created_at: Utc::now(),
                });
            }
            Err(error) => {
                fail(&pool, &id, &error.to_string()).await;
                return;
            }
        }
        let progress = i16::try_from((index + 1) * 95 / total).unwrap_or(95);
        let _ = media::set_processing(&pool, &id, "processing", progress, None).await;
    }
    if let Err(error) = media::replace_variants(&pool, &id, &rows).await {
        fail(&pool, &id, &error.to_string()).await;
        return;
    }
    let _ = media::set_processing(&pool, &id, "ready", 100, None).await;
}

async fn fail(pool: &PgPool, id: &str, message: &str) {
    tracing::warn!(%id, %message, "media processing failed");
    let _ = media::set_processing(pool, id, "failed", 0, Some(message)).await;
}

/// `GET /api/v1/media/{id}` — processing state and metadata for the author.
pub async fn show(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<MediaAttachmentDto>> {
    let Some(row) = media::by_id(state.store().pool(), &id).await? else {
        return Err(ApiError::not_found("Record not found"));
    };
    if row.account_id != auth.0.account.id {
        return Err(ApiError::not_found("Record not found"));
    }
    Ok(Json(MediaAttachmentDto::from_row(&row, state.instance())))
}

#[derive(Debug, serde::Deserialize)]
pub struct MediaUpdate {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub sensitive: Option<bool>,
}

/// `PUT /api/v1/media/{id}` — author-controlled description and sensitivity.
pub async fn update(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(body): Json<MediaUpdate>,
) -> ApiResult<Json<MediaAttachmentDto>> {
    auth.require_scope("write")?;
    let Some(existing) = media::by_id(state.store().pool(), &id).await? else {
        return Err(ApiError::not_found("Record not found"));
    };
    if existing.account_id != auth.0.account.id {
        return Err(ApiError::not_found("Record not found"));
    }
    let description = body.description.unwrap_or(existing.description);
    if description.chars().count() > MAX_DESCRIPTION {
        return Err(ApiError::unprocessable("The description is too long"));
    }
    let sensitive = body.sensitive.unwrap_or(existing.sensitive);
    if !media::update(
        state.store().pool(),
        &id,
        &auth.0.account.id,
        &description,
        sensitive,
    )
    .await?
    {
        return Err(ApiError::not_found("Record not found"));
    }
    let row = media::by_id(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    Ok(Json(MediaAttachmentDto::from_row(&row, state.instance())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nodus_server_store::accounts::{self, NewAccount};

    #[sqlx::test(migrations = "../store/migrations")]
    async fn process_upload_succeeds_for_720p_video_with_multiple_compressed_renditions(
        pool: PgPool,
    ) {
        let dir = std::env::temp_dir().join(format!("nodus-api-video-test-{}", Id::new()));
        let variant_dir = dir.join("variants");
        tokio::fs::create_dir_all(&variant_dir).await.unwrap();

        let source = dir.join("source_video");
        let ffmpeg_bin =
            std::env::var_os("NODUS_FFMPEG").map_or_else(|| PathBuf::from("ffmpeg"), PathBuf::from);
        let status = tokio::process::Command::new(ffmpeg_bin)
            .arg("-v")
            .arg("error")
            .arg("-f")
            .arg("lavfi")
            .arg("-i")
            .arg("color=c=blue:size=1280x720:rate=1:duration=1")
            .arg("-frames:v")
            .arg("1")
            .arg("-f")
            .arg("mp4")
            .arg(&source)
            .status()
            .await
            .expect("ffmpeg must run");
        assert!(status.success(), "ffmpeg failed to synthesize 720p mp4");

        let bytes = tokio::fs::read(&source).await.unwrap();
        let source_digest = hex(&Sha256::digest(&bytes));
        let account = accounts::insert(
            &pool,
            &NewAccount {
                username: &format!("vidtest_{}", Id::new()),
                display_name: "Video Test",
                note: "",
                bot: false,
                locked: false,
            },
        )
        .await
        .unwrap();

        let media_id = Id::new().to_string();
        media::insert(
            &pool,
            &MediaRow {
                id: media_id.clone(),
                account_id: account.id.clone(),
                status_id: None,
                digest: source_digest.clone(),
                content_type: "video/mp4".to_owned(),
                size: i64::try_from(bytes.len()).unwrap(),
                width: Some(1280),
                height: Some(720),
                blurhash: None,
                description: String::new(),
                sensitive: false,
                lossless: false,
                processing_state: "pending".to_owned(),
                processing_progress: 0,
                processing_error: None,
                original_pruned: false,
                remote: false,
                content_hash: None,
                perceptual_hash: None,
                quarantine_state: "none".to_owned(),
                quarantine_set: None,
                remote_url: None,
                created_at: Utc::now(),
            },
        )
        .await
        .unwrap();

        let plan =
            plan_with_permissions(Kind::Video, 1280, 720, false, LosslessPermissions::none())
                .unwrap();
        assert_eq!(plan.len(), 3);

        process_upload_in(
            pool.clone(),
            media_id.clone(),
            source.clone(),
            source_digest,
            "video/mp4".to_owned(),
            Kind::Video,
            plan,
            false,
            &variant_dir,
        )
        .await;

        let row = media::by_id(&pool, &media_id)
            .await
            .unwrap()
            .expect("media row");
        assert_eq!(
            row.processing_state, "ready",
            "processing failed: {:?}",
            row.processing_error
        );
        assert_eq!(row.processing_progress, 100);
        assert_eq!(row.processing_error, None);

        let variants = media::variants(&pool, &media_id).await.unwrap();
        assert_eq!(variants.len(), 3);
        let compressed: Vec<i64> = variants
            .iter()
            .filter(|v| v.layer == "compressed")
            .map(|v| v.max_edge)
            .collect();
        assert_eq!(compressed, vec![360, 720]);
        for variant in &variants {
            assert!(variant_dir.join(&variant.digest).exists());
        }

        let best = media::variant(&pool, &media_id, "compressed")
            .await
            .unwrap()
            .expect("best compressed");
        assert_eq!(best.max_edge, 720);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
