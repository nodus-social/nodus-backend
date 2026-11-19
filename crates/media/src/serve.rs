//! Byte serving for the media surface.
//!
//! The catalogue lives in the database and the bytes live on disk, so serving is its own
//! router rather than a part of the API: an instance can then keep answering API requests
//! while a large file is read, and the media process can be restarted, resized or moved to
//! another host without touching the process that answers JSON.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::Router;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use nodus_server_store::media::{self, VariantRow};
use nodus_server_store::media_nodes;

use crate::cluster::{self, placement, Member};
use crate::hash::hex;
use crate::{CachePolicy, Layer};

/// The bytes a media catalogue id resolves to, and where they are kept.
#[derive(Clone)]
pub struct Serving {
    pool: PgPool,
    root: PathBuf,
    variants: PathBuf,
    /// This process's name in the membership table.
    node: String,
    /// Shared secret the peers present on the internal routes. `None` disables them.
    cluster_token: Option<String>,
}

impl Serving {
    /// Serve from this database and these directories.
    #[must_use]
    pub fn new(
        pool: PgPool,
        root: PathBuf,
        variants: PathBuf,
        node: String,
        cluster_token: Option<String>,
    ) -> Self {
        Self {
            pool,
            root,
            variants,
            node,
            cluster_token,
        }
    }

    /// Whether the `/internal/*` routes are registered at all.
    #[must_use]
    pub const fn cluster_enabled(&self) -> bool {
        self.cluster_token.is_some()
    }

    /// `/media/default-avatar.png`, `/media/{id}`, `/media/{id}/{layer}`.
    ///
    /// The `/internal/*` routes exist only when a cluster token is configured. With no
    /// token they are not registered at all, so they answer the same 404 an unknown path
    /// does rather than merely refusing the request.
    pub fn router(self: &Arc<Self>) -> Router {
        let public = Router::new()
            .route("/media/default-avatar.png", get(default_avatar))
            .route("/media/{id}", get(serve))
            .route("/media/{id}/{layer}", get(serve_variant))
            .with_state(self.clone());
        if self.cluster_token.is_none() {
            return public;
        }
        public.merge(self.internal_router())
    }

    fn internal_router(self: &Arc<Self>) -> Router {
        Router::new()
            .route(
                "/internal/media/{digest}",
                put(internal_put)
                    .get(internal_get)
                    .head(internal_head)
                    .delete(internal_delete),
            )
            .route("/internal/placement/{digest}", get(internal_placement))
            .layer(DefaultBodyLimit::max(MAX_INTERNAL_UPLOAD))
            .layer(middleware::from_fn_with_state(
                self.clone(),
                require_cluster_token,
            ))
            .with_state(self.clone())
    }
}

/// The picture an account shows before it chooses one.
const DEFAULT_AVATAR_SIZE: u32 = 400;
/// Neutral grey, so one picture works on both a light and a dark timeline.
const PLACEHOLDER_BACKGROUND: [u8; 4] = [214, 211, 209, 255];
const PLACEHOLDER_FIGURE: [u8; 4] = [168, 162, 158, 255];

/// `GET /media/default-avatar.png` — the picture every account starts with.
///
/// Generated rather than shipped as a file: the arithmetic is cheaper to keep correct than
/// a binary in the repository, and the shape can be tuned without a build-time image tool.
///
/// Only the picture has a default. An account with no banner answers an empty `header`, so
/// a client draws nothing there rather than a grey band pretending to be one.
pub async fn default_avatar() -> Response {
    static BYTES: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    let bytes = BYTES.get_or_init(render_default_avatar);
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("image/png")),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=604800"),
            ),
        ],
        Body::from(bytes.clone()),
    )
        .into_response()
}

/// A square grey tile with a lighter head-and-shoulders silhouette.
fn render_default_avatar() -> Vec<u8> {
    let size = DEFAULT_AVATAR_SIZE;
    let centre = f64::from(size) / 2.0;
    let head_radius = f64::from(size) * 0.16;
    let head_centre = (centre, f64::from(size) * 0.38);
    let shoulders: [f64; 3] = [centre, f64::from(size) * 0.92, f64::from(size) * 0.30];

    let mut pixels = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let point = (f64::from(x) + 0.5, f64::from(y) + 0.5);
            let in_head = distance(point, head_centre) <= head_radius;
            let in_shoulders = distance(point, (shoulders[0], shoulders[1])) <= shoulders[2];
            let colour = if in_head || in_shoulders {
                PLACEHOLDER_FIGURE
            } else {
                PLACEHOLDER_BACKGROUND
            };
            pixels.extend_from_slice(&colour);
        }
    }

    let mut out = Vec::new();
    let encoder = image::codecs::png::PngEncoder::new(&mut out);
    use image::ImageEncoder as _;
    encoder
        .write_image(&pixels, size, size, image::ExtendedColorType::Rgba8)
        .expect("a generated RGBA buffer is a valid image");
    out
}

fn distance(a: (f64, f64), b: (f64, f64)) -> f64 {
    ((a.0 - b.0).powi(2) + (a.1 - b.1).powi(2)).sqrt()
}

/// `GET /media/{id}` — original bytes, cached by digest.
pub async fn serve(State(serving): State<Arc<Serving>>, Path(id): Path<String>) -> Response {
    let Some(row) = catalogue(&serving, &id).await else {
        return not_found();
    };
    if suspended(&serving, &row.account_id).await {
        return not_found();
    }
    if !row.original_pruned {
        if let Ok(bytes) = tokio::fs::read(serving.root.join(&row.digest)).await {
            return with_cache(
                bytes,
                &row.content_type,
                "public, max-age=31536000, immutable",
            );
        }
    }
    for layer in [Layer::Compressed, Layer::Preview] {
        if let Some(variant) = variant(&serving, &id, layer.as_str()).await {
            return variant_response(&serving, variant, layer).await;
        }
    }
    not_found()
}

/// `GET /media/{id}/{layer}` — a generated preview/compressed/lossless variant.
pub async fn serve_variant(
    State(serving): State<Arc<Serving>>,
    Path((id, layer)): Path<(String, String)>,
) -> Response {
    let layer = match layer.as_str() {
        "preview" => Layer::Preview,
        "compressed" => Layer::Compressed,
        "lossless" => Layer::Lossless,
        _ => return not_found(),
    };
    // A variant is the same picture as its original, so a suspended account's media is
    // gone at every layer, not only at the one /media/{id} happens to answer.
    match catalogue(&serving, &id).await {
        Some(row) if suspended(&serving, &row.account_id).await => return not_found(),
        Some(_) => {}
        None => return not_found(),
    }
    if let Some(variant) = variant(&serving, &id, layer.as_str()).await {
        return variant_response(&serving, variant, layer).await;
    }
    serve(State(serving), Path(id)).await
}

async fn catalogue(serving: &Serving, id: &str) -> Option<media::MediaRow> {
    match media::by_id(&serving.pool, id).await {
        Ok(row) => row,
        Err(error) => {
            tracing::error!(%error, %id, "the media catalogue could not be read");
            None
        }
    }
}

/// Whether the account that posted this media is suspended, in which case the bytes are
/// not served at all — a suspended account's pictures are part of what it posted.
async fn suspended(serving: &Serving, account_id: &str) -> bool {
    match nodus_server_store::accounts::is_deleted(&serving.pool, account_id).await {
        Ok(true) => return true,
        Ok(false) => {}
        Err(error) => tracing::error!(%error, "the account table could not be read"),
    }
    match nodus_server_store::remote_moderation::action_for_account(&serving.pool, account_id).await
    {
        Ok(action) => action.as_deref() == Some(nodus_server_store::remote_moderation::SUSPEND),
        Err(error) => {
            tracing::error!(%error, "the remote moderation table could not be read");
            false
        }
    }
}

async fn variant(serving: &Serving, id: &str, layer: &str) -> Option<VariantRow> {
    match media::variant(&serving.pool, id, layer).await {
        Ok(row) => row,
        Err(error) => {
            tracing::error!(%error, %id, %layer, "the media variants could not be read");
            None
        }
    }
}

async fn variant_response(serving: &Serving, variant: VariantRow, layer: Layer) -> Response {
    let Ok(bytes) = tokio::fs::read(serving.variants.join(&variant.digest)).await else {
        return not_found();
    };
    let cache = CachePolicy::default().cache_control(layer);
    with_cache(bytes, &variant.content_type, &cache)
}

fn with_cache(bytes: Vec<u8>, content_type: &str, cache: &str) -> Response {
    let content_type = HeaderValue::from_str(content_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    let cache = HeaderValue::from_str(cache)
        .unwrap_or_else(|_| HeaderValue::from_static("public, max-age=3600"));
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, cache),
        ],
        Body::from(bytes),
    )
        .into_response()
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "Record not found").into_response()
}

/// The largest body an internal replica write will buffer. Originals are capped well
/// below this at upload; the limit here is defence against a peer that sends more.
const MAX_INTERNAL_UPLOAD: usize = 64 * 1024 * 1024;

/// What one digest resolves to, for an operator or a peer checking its own view.
///
/// `replicas` is the whole placement, best first, so it always starts with `owner`; with
/// `R = 2` it names the owner and the one node that should also hold the bytes. `local`
/// says whether this process is that owner.
#[derive(Debug, Serialize)]
struct PlacementView {
    owner: String,
    replicas: Vec<String>,
    local: bool,
}

/// Rejects anything but a lowercase SHA-256 hex digest.
///
/// The digest becomes a file name, so this is also what keeps `..` and a slash out of the
/// path: a peer cannot choose where a write lands.
fn is_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Constant-time comparison for the cluster token.
///
/// Length is compared first because a length difference is not a secret: the token's
/// length is fixed by configuration, not guessed byte by byte from the response time.
fn token_matches(expected: &str, presented: &str) -> bool {
    let (expected, presented) = (expected.as_bytes(), presented.as_bytes());
    if expected.len() != presented.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in expected.iter().zip(presented) {
        difference |= left ^ right;
    }
    difference == 0
}

/// Every `/internal/*` request carries the shared secret.
async fn require_cluster_token(
    State(serving): State<Arc<Serving>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let expected = serving.cluster_token.as_deref().unwrap_or_default();
    let presented = headers
        .get("x-nodus-cluster")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !token_matches(expected, presented) {
        return (StatusCode::UNAUTHORIZED, "Invalid cluster token").into_response();
    }
    next.run(request).await
}

/// `PUT /internal/media/{digest}` — a peer stores bytes this node owns.
///
/// The body is verified against the digest before anything is written, so a corrupt or
/// malicious send cannot occupy the address of content it does not match. The write lands
/// in the same directory as the target and is renamed into place, so a reader sees either
/// the previous state or the whole new file, never a partial one.
async fn internal_put(
    State(serving): State<Arc<Serving>>,
    Path(digest): Path<String>,
    body: Bytes,
) -> Response {
    if !is_digest(&digest) {
        return (
            StatusCode::BAD_REQUEST,
            "digest must be 64 lowercase hex characters",
        )
            .into_response();
    }
    if hex(&Sha256::digest(&body)) != digest {
        return (StatusCode::BAD_REQUEST, "digest does not match the body").into_response();
    }
    let target = serving.root.join(&digest);
    if tokio::fs::try_exists(&target).await.unwrap_or(false) {
        return StatusCode::OK.into_response();
    }
    if let Err(error) = tokio::fs::create_dir_all(&serving.root).await {
        tracing::error!(%error, path = %serving.root.display(), "could not create the media directory");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let staged = serving
        .root
        .join(format!(".{digest}.{}.part", ulid::Ulid::new()));
    if let Err(error) = tokio::fs::write(&staged, &body).await {
        let _ = tokio::fs::remove_file(&staged).await;
        tracing::error!(%error, %digest, "could not stage an internal media write");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    match tokio::fs::rename(&staged, &target).await {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(error) => {
            let _ = tokio::fs::remove_file(&staged).await;
            tracing::error!(%error, %digest, "could not commit an internal media write");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `GET /internal/media/{digest}` — raw bytes, with no catalogue check.
async fn internal_get(State(serving): State<Arc<Serving>>, Path(digest): Path<String>) -> Response {
    if !is_digest(&digest) {
        return not_found();
    }
    match tokio::fs::read(serving.root.join(&digest)).await {
        Ok(bytes) => (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            )],
            Body::from(bytes),
        )
            .into_response(),
        Err(_) => not_found(),
    }
}

/// `HEAD /internal/media/{digest}` — presence without reading the file.
async fn internal_head(
    State(serving): State<Arc<Serving>>,
    Path(digest): Path<String>,
) -> Response {
    if !is_digest(&digest) {
        return not_found();
    }
    match tokio::fs::metadata(serving.root.join(&digest)).await {
        Ok(metadata) if metadata.is_file() => StatusCode::OK.into_response(),
        _ => not_found(),
    }
}

/// `DELETE /internal/media/{digest}` — idempotent, because a peer may retry a delete and
/// the absence of the file is the outcome it wants either way.
async fn internal_delete(
    State(serving): State<Arc<Serving>>,
    Path(digest): Path<String>,
) -> Response {
    if is_digest(&digest) {
        match tokio::fs::remove_file(serving.root.join(&digest)).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(%error, %digest, "could not delete an internal media file");
            }
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

/// `GET /internal/placement/{digest}` — where this cluster thinks a digest belongs.
async fn internal_placement(
    State(serving): State<Arc<Serving>>,
    Path(digest): Path<String>,
) -> Response {
    let nodes = match media_nodes::members(&serving.pool, cluster::MEMBER_MAX_AGE).await {
        Ok(nodes) => nodes,
        Err(error) => {
            tracing::error!(%error, "the media membership could not be read");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let members: Vec<Member> = nodes
        .into_iter()
        .map(|node| Member {
            name: node.name,
            endpoint: node.endpoint,
        })
        .collect();
    let placed = placement(&digest, &members, cluster::REPLICAS);
    let owner = placed
        .first()
        .map_or_else(String::new, |member| member.name.clone());
    let local = owner == serving.node;
    axum::Json(PlacementView {
        owner,
        replicas: placed.iter().map(|member| member.name.clone()).collect(),
        local,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use tower::ServiceExt;

    use super::{
        default_avatar, Serving, DEFAULT_AVATAR_SIZE, PLACEHOLDER_BACKGROUND, PLACEHOLDER_FIGURE,
    };

    /// A serving state with no database: these tests assert routing and token handling, and
    /// the one route that reads membership is only asserted where it must refuse a request.
    fn serving(cluster_token: Option<&str>) -> Arc<Serving> {
        let store =
            nodus_server_store::Store::connect_lazy("postgres://nodus:nodus@127.0.0.1:1/nodus", 1);
        let root = std::env::temp_dir().join(format!("nodus-media-{}", ulid::Ulid::new()));
        Arc::new(Serving::new(
            store.pool().clone(),
            root.clone(),
            root.join("variants"),
            "test-node".to_owned(),
            cluster_token.map(str::to_owned),
        ))
    }

    async fn status_of(token: Option<&str>, request: HttpRequest<Body>) -> StatusCode {
        serving(token)
            .router()
            .oneshot(request)
            .await
            .expect("router response")
            .status()
    }

    #[tokio::test]
    async fn a_wrong_cluster_token_is_unauthorised() {
        let request = HttpRequest::builder()
            .uri("/internal/placement/00")
            .header("x-nodus-cluster", "not-the-token")
            .body(Body::empty())
            .expect("request");
        assert_eq!(
            status_of(Some("the-token"), request).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn a_missing_cluster_token_is_unauthorised() {
        let request = HttpRequest::builder()
            .uri("/internal/media/00")
            .body(Body::empty())
            .expect("request");
        assert_eq!(
            status_of(Some("the-token"), request).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn the_internal_routes_are_absent_without_a_token() {
        for uri in ["/internal/placement/00", "/internal/media/00"] {
            let request = HttpRequest::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("request");
            assert_eq!(
                status_of(None, request).await,
                StatusCode::NOT_FOUND,
                "{uri} must look like an unknown path"
            );
        }
    }

    /// The default picture is only useful if a client can decode it, so the test decodes it.
    #[tokio::test]
    async fn the_default_avatar_is_a_square_png_with_a_figure() {
        let response = default_avatar().await;
        let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .expect("body");
        let decoded = image::load_from_memory(&bytes).expect("decodable png");
        assert_eq!(decoded.width(), DEFAULT_AVATAR_SIZE);
        assert_eq!(decoded.height(), DEFAULT_AVATAR_SIZE);

        // A flat square would be indistinguishable from a failed load, so check the figure
        // is actually drawn: the middle of the head is the figure colour, the corner is not.
        let picture = decoded.to_rgba8();
        let head = picture.get_pixel(DEFAULT_AVATAR_SIZE / 2, 156);
        let corner = picture.get_pixel(2, 2);
        assert_eq!([head[0], head[1], head[2]], PLACEHOLDER_FIGURE[..3]);
        assert_eq!(
            [corner[0], corner[1], corner[2]],
            PLACEHOLDER_BACKGROUND[..3]
        );
    }

    #[tokio::test]
    async fn the_avatar_route_answers_a_png() {
        let response = default_avatar().await;
        assert_eq!(response.status(), 200);
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok());
        assert_eq!(content_type, Some("image/png"));
    }
}
