//! Media upload, metadata and byte serving.
//!
//! Uploads are content-addressed: the catalogue id is ours, the stored name is the
//! digest. That makes a retry idempotent at the object layer even though it creates a
//! second catalogue row.

use std::path::PathBuf;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use nodus_server_core::id::Id;
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

/// `/api/v1/media`, `/api/v2/media`, `/media/{id}`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/media", post(upload))
        .route("/api/v2/media", post(upload))
        .route("/api/v1/media/{id}", get(show).put(update))
        .route("/media/{id}", get(serve))
        .route("/media/{id}/{layer}", get(serve_variant))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD))
}

fn storage_dir() -> PathBuf {
    std::env::var_os("NODUS_MEDIA_DIR").map_or_else(|| PathBuf::from("./media"), PathBuf::from)
}

fn variants_dir() -> PathBuf {
    std::env::var_os("NODUS_MEDIA_VARIANTS_DIR")
        .map_or_else(|| storage_dir().join("variants"), PathBuf::from)
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
    if bytes.len() > MAX_UPLOAD {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "The upload is too large",
        ));
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
                let path = variants_dir().join(&digest);
                if let Err(error) = tokio::fs::write(&path, &rendered.bytes).await {
                    fail(&pool, &id, &error.to_string()).await;
                    return;
                }
                rows.push(VariantRow {
                    media_id: id.clone(),
                    layer: spec.layer.as_str().to_owned(),
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

/// `GET /media/{id}` — original bytes, cached by digest.
pub async fn serve(State(state): State<AppState>, Path(id): Path<String>) -> ApiResult<Response> {
    let Some(row) = media::by_id(state.store().pool(), &id).await? else {
        return Err(ApiError::not_found("Record not found"));
    };
    if !row.original_pruned {
        if let Ok(bytes) = tokio::fs::read(storage_dir().join(&row.digest)).await {
            let content_type = HeaderValue::from_str(&row.content_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
            return Ok((
                [
                    (header::CONTENT_TYPE, content_type),
                    (
                        header::CACHE_CONTROL,
                        HeaderValue::from_static("public, max-age=31536000, immutable"),
                    ),
                ],
                Body::from(bytes),
            )
                .into_response());
        }
    }
    for layer in [Layer::Compressed, Layer::Preview] {
        if let Some(variant) = media::variant(state.store().pool(), &id, layer.as_str()).await? {
            return variant_response(variant, layer).await;
        }
    }
    Err(ApiError::not_found("Record not found"))
}

/// `GET /media/{id}/{layer}` — a generated preview/compressed/lossless variant.
pub async fn serve_variant(
    State(state): State<AppState>,
    Path((id, layer)): Path<(String, String)>,
) -> ApiResult<Response> {
    let layer = match layer.as_str() {
        "preview" => Layer::Preview,
        "compressed" => Layer::Compressed,
        "lossless" => Layer::Lossless,
        _ => return Err(ApiError::not_found("Record not found")),
    };
    if let Some(variant) = media::variant(state.store().pool(), &id, layer.as_str()).await? {
        return variant_response(variant, layer).await;
    }
    serve(State(state), Path(id)).await
}

async fn variant_response(variant: VariantRow, layer: Layer) -> ApiResult<Response> {
    let bytes = tokio::fs::read(variants_dir().join(&variant.digest))
        .await
        .map_err(|_| ApiError::not_found("Record not found"))?;
    let content_type = HeaderValue::from_str(&variant.content_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    let cache = CachePolicy::default().cache_control(layer);
    Ok((
        [
            (header::CONTENT_TYPE, content_type),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_str(&cache)
                    .unwrap_or_else(|_| HeaderValue::from_static("public, max-age=3600")),
            ),
        ],
        Body::from(bytes),
    )
        .into_response())
}
