//! Byte serving for the media surface.
//!
//! The catalogue lives in the database and the bytes live on disk, so serving is its own
//! router rather than a part of the API: an instance can then keep answering API requests
//! while a large file is read, and the media process can be restarted, resized or moved to
//! another host without touching the process that answers JSON.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use sqlx::PgPool;

use nodus_server_store::media::{self, VariantRow};

use crate::{CachePolicy, Layer};

/// The bytes a media catalogue id resolves to, and where they are kept.
#[derive(Clone)]
pub struct Serving {
    pool: PgPool,
    root: PathBuf,
    variants: PathBuf,
}

impl Serving {
    /// Serve from this database and these directories.
    #[must_use]
    pub fn new(pool: PgPool, root: PathBuf, variants: PathBuf) -> Self {
        Self {
            pool,
            root,
            variants,
        }
    }

    /// `/media/default-avatar.png`, `/media/{id}`, `/media/{id}/{layer}`.
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/media/default-avatar.png", get(default_avatar))
            .route("/media/{id}", get(serve))
            .route("/media/{id}/{layer}", get(serve_variant))
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

#[cfg(test)]
mod tests {
    use super::{default_avatar, DEFAULT_AVATAR_SIZE, PLACEHOLDER_BACKGROUND, PLACEHOLDER_FIGURE};

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
