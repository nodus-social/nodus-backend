//! Media upload, metadata and byte serving.
//!
//! Uploads are content-addressed: the catalogue id is ours, the stored name is the
//! digest. That makes a retry idempotent at the object layer even though it creates a
//! second catalogue row.

use std::path::PathBuf;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use nodus_server_core::id::Id;
use nodus_server_core::limits::{IMAGE_SIZE_LIMIT, VIDEO_SIZE_LIMIT};
use nodus_server_media::{
    expires_in, plan_with_permissions, CachePolicy, Kind, Layer, LosslessPermissions, VariantSpec,
};
use nodus_server_store::drive::{self, ProcessingState};
use nodus_server_store::media::{self, MediaRow, VariantRow};

use crate::auth::Auth;
use crate::dto::MediaAttachmentDto;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub(crate) const MAX_UPLOAD: usize = 40 * 1024 * 1024;
pub(crate) const MAX_DESCRIPTION: usize = 1_500;

/// `/api/v1/media`, `/api/v2/media`.
///
/// Uploads and their metadata. The bytes are served by `nodus-media`, which reads the same
/// catalogue.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/media", post(upload))
        .route("/api/v2/media", post(upload_deferred))
        .route("/api/v1/media/{id}", get(show).put(update))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD))
}

/// Where originals are kept: the deployment decides, the default is for a checkout.
pub(crate) fn storage_dir() -> PathBuf {
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

/// How long the API waits for a media node to accept an original.
///
/// The upload has not answered yet while this runs, so it is the user's wait: long enough
/// for a healthy node on the same network, short enough that a dead one becomes a local
/// write and a warning instead of a hung request.
const CLUSTER_PUT_TIMEOUT: Duration = Duration::from_secs(10);

/// The media cluster the API hands originals to, read from the environment.
///
/// Both halves are required: a URL without a token cannot address the internal routes, and
/// a token without a URL names no node. With either one missing this instance is
/// unclustered and the upload path is exactly what it was before the cluster existed.
#[derive(Debug, Clone)]
pub(crate) struct ClusterUpload {
    /// The node every original is written through. Caddy hashes the path onto one member,
    /// so this can be the same public name the website uses.
    base: String,
    token: String,
}

impl ClusterUpload {
    pub(crate) fn from_env() -> Option<Self> {
        let base = std::env::var("NODUS_MEDIA_CLUSTER_URL")
            .ok()
            .filter(|value| !value.is_empty())?;
        let token = std::env::var("NODUS_MEDIA_CLUSTER_TOKEN")
            .ok()
            .filter(|value| !value.is_empty())?;
        Some(Self {
            base: base.trim_end_matches('/').to_owned(),
            token,
        })
    }

    /// `PUT {base}/internal/media/{digest}`, bounded by [`CLUSTER_PUT_TIMEOUT`].
    ///
    /// The body is the original itself. A 2xx means a media node now owns the digest: it
    /// replicates it, repairs it, and serves it from then on.
    pub(crate) async fn put(&self, digest: &str, bytes: &[u8]) -> Result<(), String> {
        let url = format!("{}/internal/media/{digest}", self.base);
        let response = cluster_client()
            .put(&url)
            .header(nodus_server_media::cluster::TOKEN_HEADER, &self.token)
            .timeout(CLUSTER_PUT_TIMEOUT)
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(|error| error.to_string())?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(format!("the node answered {status}"))
        }
    }
}

/// One client for every cluster upload: a client owns the connection pool, and building
/// one per upload would throw that away on every request.
fn cluster_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(reqwest::Client::new)
}

/// Where an upload's original went, and where a renderer can read the bytes back.
enum Original {
    /// Written under `NODUS_MEDIA_DIR` and served from this host.
    Local(PathBuf),
    /// Accepted by a media node. This copy exists only for variant rendering, which needs a
    /// file, and is deleted once the variants are made.
    Scratch(PathBuf),
}

impl Original {
    fn path(&self) -> &PathBuf {
        match self {
            Self::Local(path) | Self::Scratch(path) => path,
        }
    }

    const fn is_scratch(&self) -> bool {
        matches!(self, Self::Scratch(_))
    }
}

/// Writes the original, through the cluster when one is configured.
///
/// A node that answers 2xx owns the digest, and the bytes are not written under
/// `NODUS_MEDIA_DIR` here at all. Every other answer — a 4xx, a 5xx, a connection that
/// never lands inside [`CLUSTER_PUT_TIMEOUT`] — falls back to the local write with a
/// warning: the user has already sent the bytes, and a media node that is down must not
/// turn that into a failed upload.
///
/// Variants stay local either way. This process renders them into
/// `NODUS_MEDIA_VARIANTS_DIR` from the bytes in hand, which is why a cluster upload keeps a
/// scratch copy while processing runs; a media node never generates variants, and on a read
/// miss it fetches the original from a peer, so the original is the only byte path the
/// cluster carries.
async fn store_original(
    dir: &std::path::Path,
    digest: &str,
    bytes: &[u8],
    cluster: Option<&ClusterUpload>,
) -> ApiResult<Original> {
    if let Some(cluster) = cluster {
        match cluster.put(digest, bytes).await {
            Ok(()) => {
                tracing::debug!(%digest, base = %cluster.base, "the media cluster accepted an original");
                let scratch = std::env::temp_dir().join(format!("nodus-upload-{}", Id::new()));
                tokio::fs::write(&scratch, bytes).await?;
                return Ok(Original::Scratch(scratch));
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    %digest,
                    base = %cluster.base,
                    "the media cluster did not accept an original; writing it locally"
                );
            }
        }
    }
    let path = dir.join(digest);
    tokio::fs::write(&path, bytes).await?;
    Ok(Original::Local(path))
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
///
/// Also accepts `stored_object_id` instead of `file`, which attaches bytes the drive
/// already holds: no second copy is written and the quota does not move.
pub async fn upload(
    State(state): State<AppState>,
    auth: Auth,
    multipart: Multipart,
) -> ApiResult<Response> {
    receive(state, auth, multipart, false).await
}

/// `POST /api/v2/media` — Mastodon's asynchronous upload.
///
/// The answer is `202` with an id to poll; the variants are rendered behind it. The
/// `id` is the same attachment `/api/v1/media/{id}` reports.
pub async fn upload_deferred(
    State(state): State<AppState>,
    auth: Auth,
    multipart: Multipart,
) -> ApiResult<Response> {
    receive(state, auth, multipart, true).await
}

/// The body both upload routes share. `deferred` only decides the shape of the answer:
/// v2 hands back an id before the variants exist, v1 answers with the full row.
async fn receive(
    state: AppState,
    auth: Auth,
    mut multipart: Multipart,
    deferred: bool,
) -> ApiResult<Response> {
    auth.require_scope("write")?;
    let mut bytes: Option<Vec<u8>> = None;
    let mut content_type = "application/octet-stream".to_owned();
    let mut description = String::new();
    let mut sensitive = false;
    let mut lossless = false;
    let mut filename = String::new();
    let mut stored_object_id: Option<String> = None;

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
                if let Some(name) = field.file_name() {
                    filename = name.to_owned();
                }
                bytes = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|_| ApiError::unprocessable("Could not read the upload"))?
                        .to_vec(),
                );
            }
            "stored_object_id" => {
                stored_object_id = Some(
                    field
                        .text()
                        .await
                        .map_err(|_| ApiError::unprocessable("Invalid stored_object_id"))?,
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

    // The zero-copy path: the bytes are already stored, so only the attachment is minted.
    if let Some(object_id) = stored_object_id {
        return attach_stored(&state, &auth, &object_id, &description, deferred).await;
    }

    let bytes = bytes.ok_or_else(|| ApiError::unprocessable("A file is required"))?;
    let row = ingest_upload(
        &state,
        &auth,
        UploadFile {
            bytes: &bytes,
            content_type: &content_type,
            filename: &filename,
            description: &description,
            sensitive,
            lossless,
        },
    )
    .await?;
    Ok(media_response(&row, state.instance(), deferred))
}

/// One uploaded file, before it has a catalogue row.
pub(crate) struct UploadFile<'a> {
    pub bytes: &'a [u8],
    pub content_type: &'a str,
    pub filename: &'a str,
    pub description: &'a str,
    pub sensitive: bool,
    pub lossless: bool,
}

/// Validates and stores one uploaded file, then starts its variant render.
///
/// This is the body of `POST /api/v1/media` once the multipart fields are read, and the
/// profile-picture form on `update_credentials` calls it with the same fields: a second
/// writer would have to repeat every limit and refusal and would drift from this one.
pub(crate) async fn ingest_upload(
    state: &AppState,
    auth: &Auth,
    upload: UploadFile<'_>,
) -> ApiResult<MediaRow> {
    let UploadFile {
        bytes,
        content_type,
        filename,
        description,
        sensitive,
        lossless,
    } = upload;
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

    let kind = Kind::from_content_type(content_type);
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

    let digest = hex(&Sha256::digest(bytes));
    let dir = storage_dir();
    tokio::fs::create_dir_all(&dir).await?;
    tokio::fs::create_dir_all(variants_dir()).await?;
    let cluster = ClusterUpload::from_env();
    let original = store_original(&dir, &digest, bytes, cluster.as_ref()).await?;
    let source = original.path().clone();
    // A cluster upload leaves no original here, so the copy the renderer reads is thrown
    // away as soon as the variants exist.
    let scratch = original.is_scratch().then(|| source.clone());

    let id = Id::new().to_string();
    let mut row = MediaRow {
        id: id.clone(),
        account_id: auth.0.account.id.clone(),
        status_id: None,
        digest,
        content_type: content_type.to_owned(),
        size: i64::try_from(bytes.len()).unwrap_or(i64::MAX),
        width: None,
        height: None,
        blurhash: None,
        description: description.to_owned(),
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
        match nodus_server_media::blurhash(bytes) {
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

    // The same bytes now have a drive row too, so an upload can be listed, renamed, or
    // shared like any other file. A failure here must not fail the upload: the bytes and
    // the catalogue row are already stored, and the attachment does not depend on it.
    let name = crate::drive::clean_filename(filename);
    let name = if name.is_empty() {
        "upload".to_owned()
    } else {
        name
    };
    let object_id = match drive::create_object(
        state.store().pool(),
        &auth.0.account.id,
        None,
        &name,
        &row.content_type,
        &row.digest,
        row.size,
    )
    .await
    {
        Ok(object) => Some(object.id),
        Err(error) => {
            tracing::warn!(%error, %id, "could not file an upload in the drive");
            None
        }
    };

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
    let account = auth.0.account.id.clone();
    tokio::spawn(async move {
        let outcome = process_upload(
            pool.clone(),
            media_id.clone(),
            source,
            source_digest,
            content_type,
            kind,
            plan,
            lossless,
        )
        .await;
        // The drive row is a projection of the media row, so it has to be written before
        // the media row publishes its verdict: a client that polls the attachment until
        // it is `ready` and then lists the drive must never see the older state.
        mirror_drive_state(&pool, &account, object_id, &outcome).await;
        publish_outcome(&pool, &media_id, &outcome).await;
        if let Some(path) = scratch {
            if let Err(error) = tokio::fs::remove_file(&path).await {
                tracing::warn!(%error, path = %path.display(), "could not remove an upload's scratch copy");
            }
        }
    });

    Ok(row)
}

/// Copies the pipeline's verdict onto the drive row, so a listing does not show a file
/// that will be "pending" forever.
async fn mirror_drive_state(
    pool: &PgPool,
    account: &str,
    object_id: Option<Uuid>,
    outcome: &UploadOutcome,
) {
    let Some(object_id) = object_id else {
        return;
    };
    let state = match outcome {
        UploadOutcome::Ready => ProcessingState::Ready,
        UploadOutcome::Failed(_) => ProcessingState::Failed,
    };
    if let Err(error) = drive::set_state(pool, account, object_id, state).await {
        tracing::warn!(%error, %object_id, "could not mirror a media state onto the drive");
    }
}

/// What a media route answers for a row.
///
/// A `202` is only honest while something is still running: once the row is `ready` or
/// `failed` the client gets the full attachment either way.
fn media_response(
    row: &MediaRow,
    instance: &crate::state::InstanceConfig,
    deferred: bool,
) -> Response {
    if deferred && MediaAttachmentDto::processing(&row.processing_state) == "pending" {
        return (StatusCode::ACCEPTED, Json(AcceptedMedia::from_row(row))).into_response();
    }
    Json(MediaAttachmentDto::from_row(row, instance)).into_response()
}

/// The `202` body Mastodon's asynchronous upload answers with: an id to poll, and the
/// fields a client reads unconditionally set to null because they do not exist yet.
#[derive(Debug, Serialize)]
struct AcceptedMedia {
    id: String,
    #[serde(rename = "type")]
    kind: &'static str,
    url: Option<String>,
    preview_url: Option<String>,
    description: Option<String>,
    blurhash: Option<String>,
    meta: serde_json::Value,
    processing: &'static str,
}

impl AcceptedMedia {
    fn from_row(row: &MediaRow) -> Self {
        Self {
            id: row.id.clone(),
            kind: MediaAttachmentDto::kind_name(&row.content_type),
            url: None,
            preview_url: None,
            description: (!row.description.is_empty()).then(|| row.description.clone()),
            blurhash: None,
            meta: serde_json::json!({}),
            processing: "pending",
        }
    }
}

/// Attaches bytes the drive already holds, without reading or writing a single byte.
///
/// TODO(3c): a drive object has no rendered variants, so the returned `url` and
/// `preview_url` point at `/media/{id}/compressed` and `/media/{id}/preview`, which the
/// media service answers with 404 until the attach path renders them. Naming the gap is
/// better than pretending: generating variants here would copy the file this route exists
/// to avoid copying.
async fn attach_stored(
    state: &AppState,
    auth: &Auth,
    object_id: &str,
    description: &str,
    deferred: bool,
) -> ApiResult<Response> {
    let Ok(object_id) = Uuid::parse_str(object_id.trim()) else {
        return Err(ApiError::unprocessable("stored_object_id is not an id"));
    };
    if description.chars().count() > MAX_DESCRIPTION {
        return Err(ApiError::unprocessable("The description is too long"));
    }
    let account = &auth.0.account.id;
    let pool = state.store().pool();
    if drive::object(pool, account, object_id).await?.is_none() {
        return Err(ApiError::not_found("Record not found"));
    }
    let Some(attachment_id) =
        drive::attach_object(pool, account, object_id, None, description, None, None).await?
    else {
        return Err(ApiError::not_found("Record not found"));
    };
    let Some(row) = media::by_id(pool, &attachment_id).await? else {
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not read the attachment back",
        ));
    };
    Ok(media_response(&row, state.instance(), deferred))
}

/// What the render step concluded, before anything publishes it.
///
/// The verdict is returned rather than written so the caller can project it onto the
/// drive row first: [`publish_outcome`] is then the only writer of the terminal media
/// state, which is what makes the projection causal.
#[derive(Debug)]
enum UploadOutcome {
    Ready,
    Failed(String),
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
) -> UploadOutcome {
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
    .await
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
) -> UploadOutcome {
    if let Err(error) = media::set_processing(&pool, &id, "processing", 5, None).await {
        tracing::error!(%error, %id, "could not mark media processing");
        return UploadOutcome::Failed(error.to_string());
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
                let dimensions = nodus_server_media::process::image_dimensions(&rendered.bytes);
                let path = variant_dir.join(&digest);
                if let Err(error) = tokio::fs::write(&path, &rendered.bytes).await {
                    return UploadOutcome::Failed(error.to_string());
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
                    width: dimensions.and_then(|(width, _)| i32::try_from(width).ok()),
                    height: dimensions.and_then(|(_, height)| i32::try_from(height).ok()),
                    expires_at: expires_in(policy, spec).and_then(|ttl| {
                        chrono::Duration::from_std(ttl)
                            .ok()
                            .map(|ttl| Utc::now() + ttl)
                    }),
                    created_at: Utc::now(),
                });
            }
            Err(error) => {
                return UploadOutcome::Failed(error.to_string());
            }
        }
        let progress = i16::try_from((index + 1) * 95 / total).unwrap_or(95);
        let _ = media::set_processing(&pool, &id, "processing", progress, None).await;
    }
    if let Err(error) = media::replace_variants(&pool, &id, &rows).await {
        return UploadOutcome::Failed(error.to_string());
    }
    UploadOutcome::Ready
}

/// Which profile picture a media id was chosen for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProfileSlot {
    Avatar,
    Header,
}

impl ProfileSlot {
    /// The layer that keeps the animation, and the name stored in the account row.
    pub(crate) const fn layer(self) -> Layer {
        match self {
            Self::Avatar => Layer::Avatar,
            Self::Header => Layer::Header,
        }
    }

    /// The layer name a profile reference ends in.
    pub(crate) const fn reference(self) -> &'static str {
        match self {
            Self::Avatar => "avatar",
            Self::Header => "header",
        }
    }
}

/// Renders a profile picture's variants behind the profile update.
///
/// The request stores the reference and answers; a picture already at the preview size
/// keeps working through the preview fallback until these land on the next request.
pub(crate) fn spawn_profile_render(state: &AppState, media_id: &str, slot: ProfileSlot) {
    let state = state.clone();
    let media_id = media_id.to_owned();
    tokio::spawn(async move {
        if let Err(error) = render_profile_variants(&state, &media_id, slot).await {
            tracing::warn!(
                %error,
                %media_id,
                slot = slot.reference(),
                "could not render a profile picture's variants"
            );
        }
    });
}

async fn render_profile_variants(
    state: &AppState,
    media_id: &str,
    slot: ProfileSlot,
) -> Result<(), String> {
    let row = media::by_id(state.store().pool(), media_id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "the media row is gone".to_owned())?;
    let kind = Kind::from_content_type(&row.content_type);
    let (source, scratch) = profile_source(&row).await?;
    let result = write_profile_variants(state, &row, kind, &source, slot).await;
    if scratch {
        let _ = tokio::fs::remove_file(&source).await;
    }
    result
}

async fn write_profile_variants(
    state: &AppState,
    row: &MediaRow,
    kind: Kind,
    source: &std::path::Path,
    slot: ProfileSlot,
) -> Result<(), String> {
    nodus_server_media::profile::write_layers(
        state.store().pool(),
        &variants_dir(),
        row,
        kind,
        source,
        slot.layer(),
    )
    .await
    .map(drop)
}

/// A local path to the original, fetching it from the media cluster when this host does
/// not hold it. The bool says the file is a scratch copy to remove afterwards.
async fn profile_source(row: &MediaRow) -> Result<(PathBuf, bool), String> {
    let local = storage_dir().join(&row.digest);
    if tokio::fs::metadata(&local).await.is_ok() {
        return Ok((local, false));
    }
    let Some(cluster) = ClusterUpload::from_env() else {
        return Err(
            "the original is not on this host and no media cluster is configured".to_owned(),
        );
    };
    let url = format!("{}/media/{}", cluster.base, row.id);
    let response = cluster_client()
        .get(&url)
        .timeout(CLUSTER_PUT_TIMEOUT)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("the media service answered {}", response.status()));
    }
    let bytes = response.bytes().await.map_err(|error| error.to_string())?;
    let scratch = std::env::temp_dir().join(format!("nodus-profile-{}", Id::new()));
    tokio::fs::write(&scratch, &bytes)
        .await
        .map_err(|error| error.to_string())?;
    Ok((scratch, true))
}

/// Writes the render's verdict to the media row — the last write of the pipeline.
async fn publish_outcome(pool: &PgPool, id: &str, outcome: &UploadOutcome) {
    match outcome {
        UploadOutcome::Ready => {
            let _ = media::set_processing(pool, id, "ready", 100, None).await;
        }
        UploadOutcome::Failed(message) => {
            tracing::warn!(%id, %message, "media processing failed");
            let _ = media::set_processing(pool, id, "failed", 0, Some(message)).await;
        }
    }
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
    use std::sync::Arc;

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

        let outcome = process_upload_in(
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
        assert!(
            matches!(outcome, UploadOutcome::Ready),
            "processing failed: {outcome:?}"
        );
        publish_outcome(&pool, &media_id, &outcome).await;

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

    /// A media node's internal `PUT`, reduced to what the upload tests assert on.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Put {
        path: String,
        token: String,
        body: Vec<u8>,
    }

    /// A one-route fake: reads a `PUT`, records it, and answers `status`.
    async fn fake_node(status: u16) -> (String, Arc<std::sync::Mutex<Vec<Put>>>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a fake media node");
        let base = format!("http://{}", listener.local_addr().expect("fake address"));
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let read = stream.read(&mut chunk).await.unwrap_or(0);
                        if read == 0 {
                            return;
                        }
                        buffer.extend_from_slice(&chunk[..read]);
                        let Some(head_end) = buffer.windows(4).position(|w| w == b"\r\n\r\n")
                        else {
                            continue;
                        };
                        let head = String::from_utf8_lossy(&buffer[..head_end]).to_owned();
                        let length = head
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if buffer.len() < head_end + 4 + length {
                            continue;
                        }
                        let request = head.lines().next().unwrap_or_default();
                        let path = request.split(' ').nth(1).unwrap_or_default().to_owned();
                        let token = head
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("x-nodus-cluster")
                                    .then(|| value.trim().to_owned())
                            })
                            .unwrap_or_default();
                        recorded.lock().expect("fake node state").push(Put {
                            path,
                            token,
                            body: buffer[head_end + 4..head_end + 4 + length].to_vec(),
                        });
                        let response = format!(
                            "HTTP/1.1 {status} fake\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        let _ = stream.shutdown().await;
                        return;
                    }
                });
            }
        });
        (base, seen)
    }

    fn scratch_dir() -> PathBuf {
        std::env::temp_dir().join(format!("nodus-api-media-test-{}", Id::new()))
    }

    /// The cluster owns the bytes: the node got the exact original, and this host has no
    /// copy under the digest's name, so there is nothing here for a peer to disagree with.
    #[tokio::test]
    async fn a_cluster_that_accepts_the_original_leaves_no_local_copy() {
        let (base, seen) = fake_node(201).await;
        let dir = scratch_dir();
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let bytes = b"an original the cluster takes".to_vec();
        let digest = hex(&Sha256::digest(&bytes));
        let cluster = ClusterUpload {
            base,
            token: "secret".to_owned(),
        };

        let original = store_original(&dir, &digest, &bytes, Some(&cluster))
            .await
            .expect("the cluster accepted the write");

        assert!(matches!(&original, Original::Scratch(_)));
        assert_eq!(tokio::fs::read(original.path()).await.unwrap(), bytes);
        assert!(
            !dir.join(&digest).exists(),
            "a cluster upload must not be written locally"
        );
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].path, format!("/internal/media/{digest}"));
        assert_eq!(seen[0].token, "secret");
        assert_eq!(seen[0].body, bytes);

        let _ = tokio::fs::remove_file(original.path()).await;
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    /// A node that answers 500 must not lose the upload: the local write happens, and the
    /// file is byte-for-byte the digest a read will look for.
    #[tokio::test]
    async fn a_cluster_that_answers_500_still_stores_the_original_locally() {
        let (base, seen) = fake_node(500).await;
        let dir = scratch_dir();
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let bytes = b"an original the cluster refuses".to_vec();
        let digest = hex(&Sha256::digest(&bytes));
        let cluster = ClusterUpload {
            base,
            token: "secret".to_owned(),
        };

        let original = store_original(&dir, &digest, &bytes, Some(&cluster))
            .await
            .expect("a refused upload falls back instead of failing");

        assert!(matches!(&original, Original::Local(_)));
        assert_eq!(original.path(), &dir.join(&digest));
        let stored = tokio::fs::read(dir.join(&digest)).await.unwrap();
        assert_eq!(
            hex(&Sha256::digest(&stored)),
            digest,
            "the fallback file must be the digest a read serves"
        );
        assert_eq!(seen.lock().unwrap().len(), 1, "the node was still asked");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    /// No cluster configured is the old path, untouched: no HTTP, just the write.
    #[tokio::test]
    async fn without_a_cluster_the_original_is_written_locally() {
        let dir = scratch_dir();
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let bytes = b"an unclustered original".to_vec();
        let digest = hex(&Sha256::digest(&bytes));

        let original = store_original(&dir, &digest, &bytes, None).await.unwrap();

        assert!(matches!(&original, Original::Local(_)));
        assert_eq!(tokio::fs::read(dir.join(&digest)).await.unwrap(), bytes);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
