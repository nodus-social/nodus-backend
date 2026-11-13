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
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::Utc;
use sha2::{Digest, Sha256};

use nodus_server_core::id::Id;
use nodus_server_store::media::{self, MediaRow};

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
        .route("/api/v1/media/{id}", put(update))
        .route("/media/{id}", get(serve))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD))
}

fn storage_dir() -> PathBuf {
    std::env::var_os("NODUS_MEDIA_DIR").map_or_else(|| PathBuf::from("./media"), PathBuf::from)
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

    let digest = hex(&Sha256::digest(&bytes));
    let dir = storage_dir();
    tokio::fs::create_dir_all(&dir).await?;
    tokio::fs::write(dir.join(&digest), &bytes).await?;

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
    }

    media::insert(state.store().pool(), &row).await?;
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
    let bytes = tokio::fs::read(storage_dir().join(&row.digest))
        .await
        .map_err(|_| ApiError::not_found("Record not found"))?;
    let content_type = HeaderValue::from_str(&row.content_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    Ok((
        [
            (header::CONTENT_TYPE, content_type),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            ),
        ],
        Body::from(bytes),
    )
        .into_response())
}
