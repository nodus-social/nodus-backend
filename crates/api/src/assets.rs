//! The instance's own icon.
//!
//! An instance has no uploaded avatar of its own: the icon is part of the build, so every
//! deployment has one and no admin has to find a square image before the site looks
//! finished. `assets/icon.svg` is the source; `assets/icon.png` is the raster fallback that
//! the Mastodon `Instance` entity has always pointed at.

use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use crate::state::AppState;

const SVG: &str = include_str!("../assets/icon.svg");
const PNG: &[u8] = include_bytes!("../assets/icon.png");

/// A week: the bytes only change when the binary does, and a stale icon is invisible
/// anyway, so this is chosen to keep the request off the wire rather than to stay fresh.
const CACHE: &str = "public, max-age=604800, immutable";

/// The raster icon's path. A push payload names this rather than inventing an absolute
/// URL: the service worker resolves it against the instance it was loaded from.
pub const ICON_PATH: &str = "/icon.png";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/icon.svg", get(svg))
        .route(ICON_PATH, get(png))
        .route("/favicon.ico", get(png))
        // `Instance.thumbnail` has always advertised this path; serving the icon here makes
        // that field true instead of a broken link.
        .route("/media/thumbnail.png", get(png))
}

async fn svg() -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("image/svg+xml"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static(CACHE)),
        ],
        SVG,
    )
        .into_response()
}

async fn png() -> Response {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("image/png")),
            (header::CACHE_CONTROL, HeaderValue::from_static(CACHE)),
        ],
        PNG,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A guard against a truncated or re-encoded asset: the PNG signature is the one thing
    /// every consumer checks before it tries to decode.
    #[test]
    fn the_png_is_a_png() {
        assert_eq!(&PNG[..8], b"\x89PNG\r\n\x1a\n");
    }

    #[test]
    fn the_svg_is_an_svg() {
        assert!(SVG.contains("<svg"));
        assert!(SVG.contains("viewBox=\"0 0 512 512\""));
    }
}
