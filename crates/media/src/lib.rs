//! Media variants and cache lifetimes.
//!
//! Federation must not grow an unbounded archive of remote originals. The
//! instance keeps a small downscaled variant for as long as the post exists,
//! serves a compressed full-size variant from a short-lived cache, and keeps a
//! lossless layer only when the author marked the media as art.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The three cache layers, cheapest and longest-lived first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    /// Compressed preview, always kept while the status exists.
    Preview,
    /// Compressed full-size web copy, short-lived.
    Compressed,
    /// Original bytes, only for media marked lossless.
    Lossless,
}

impl Layer {
    /// Stable name used in object keys and the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preview => "preview",
            Self::Compressed => "compressed",
            Self::Lossless => "lossless",
        }
    }

    /// Whether this layer survives the short cache window.
    #[must_use]
    pub const fn is_long_lived(self) -> bool {
        !matches!(self, Self::Compressed)
    }
}

impl fmt::Display for Layer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Cache lifetimes. The compressed layer is deliberately bounded to 72 hours;
/// the other layers are semi-permanent and pruned with their status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachePolicy {
    pub preview: Duration,
    pub compressed: Duration,
    pub lossless: Duration,
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self {
            preview: Duration::from_hours(720),
            compressed: Duration::from_hours(72),
            lossless: Duration::from_hours(720),
        }
    }
}

impl CachePolicy {
    /// Lifetime for one layer.
    #[must_use]
    pub const fn ttl(self, layer: Layer) -> Duration {
        match layer {
            Layer::Preview => self.preview,
            Layer::Compressed => self.compressed,
            Layer::Lossless => self.lossless,
        }
    }

    /// `Cache-Control` for a content-addressed variant. CDNs may cache the
    /// short-lived compressed layer even when the origin evicts it sooner.
    #[must_use]
    pub fn cache_control(self, layer: Layer) -> String {
        let seconds = self.ttl(layer).as_secs();
        if layer.is_long_lived() {
            format!("public, max-age={seconds}, s-maxage={seconds}, immutable")
        } else {
            format!("public, max-age={seconds}, s-maxage={seconds}")
        }
    }
}

/// One generated variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VariantSpec {
    pub layer: Layer,
    pub max_edge: u32,
    pub quality: u8,
    pub lossless: bool,
}

/// Why a variant plan was rejected.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("image dimensions must be positive")]
    EmptyDimensions,
    #[error("quality must be between 1 and 100")]
    Quality,
}

/// Preview longest edge. The variant is downscaled and recompressed;
/// larger sources are reduced, smaller ones are not upscaled.
pub const DOWNSCALED_EDGE: u32 = 1280;
/// Compressed full-size longest edge. This is a cache cap, not an upscale.
pub const COMPRESSED_EDGE: u32 = 4096;

/// Plan the variants for one attachment.
///
/// `lossless` is an author opt-in for art. Without it the original bytes are not
/// retained beyond the short compressed window.
pub fn plan(width: u32, height: u32, lossless: bool) -> Result<Vec<VariantSpec>, Error> {
    if width == 0 || height == 0 {
        return Err(Error::EmptyDimensions);
    }
    let mut variants = Vec::with_capacity(if lossless { 3 } else { 2 });
    variants.push(VariantSpec {
        layer: Layer::Preview,
        max_edge: DOWNSCALED_EDGE,
        quality: 82,
        lossless: false,
    });
    variants.push(VariantSpec {
        layer: Layer::Compressed,
        max_edge: COMPRESSED_EDGE,
        quality: 88,
        lossless: false,
    });
    if lossless {
        variants.push(VariantSpec {
            layer: Layer::Lossless,
            max_edge: u32::MAX,
            quality: 100,
            lossless: true,
        });
    }
    Ok(variants)
}

/// Content-addressed object key. The digest is the source bytes; the variant
/// digest is the produced bytes, so a recompression never overwrites a cached
/// object that a CDN is still serving.
#[must_use]
pub fn object_key(source_digest: &str, variant_digest: &str, layer: Layer) -> String {
    format!("media/{source_digest}/{}/{variant_digest}", layer.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_normal_image_has_two_layers() {
        let variants = plan(2400, 1600, false).expect("plan");
        assert_eq!(variants.len(), 2);
        assert_eq!(variants[0].layer, Layer::Preview);
        assert_eq!(variants[1].layer, Layer::Compressed);
    }

    #[test]
    fn lossless_art_gets_a_third_layer() {
        let variants = plan(2400, 1600, true).expect("plan");
        assert_eq!(variants.len(), 3);
        assert_eq!(variants[2].layer, Layer::Lossless);
        assert!(variants[2].lossless);
    }

    #[test]
    fn the_compressed_layer_is_short_lived_and_the_preview_is_not() {
        let policy = CachePolicy::default();
        assert!(policy.ttl(Layer::Compressed) <= Duration::from_hours(72));
        assert!(policy.ttl(Layer::Preview) > policy.ttl(Layer::Compressed));
        assert!(policy
            .cache_control(Layer::Compressed)
            .contains("s-maxage="));
        assert!(policy.cache_control(Layer::Preview).contains("immutable"));
    }

    #[test]
    fn object_keys_are_content_addressed_per_layer() {
        assert_eq!(
            object_key("aa", "bb", Layer::Preview),
            "media/aa/preview/bb"
        );
    }

    #[test]
    fn empty_dimensions_are_rejected() {
        assert_eq!(plan(0, 10, false), Err(Error::EmptyDimensions));
    }
}
