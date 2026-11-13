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

pub mod process;

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
    /// Original kept after upload so the author can still opt in after posting.
    pub lossless_pending: Duration,
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self {
            preview: Duration::from_hours(720),
            compressed: Duration::from_hours(72),
            lossless: Duration::from_hours(720),
            lossless_pending: Duration::from_hours(24),
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

/// What the uploaded media actually is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A still image. Always re-encoded to `WebP`.
    Image,
    /// An animated image (GIF or animated `WebP`/PNG). Re-encoded to animated `WebP`.
    AnimatedImage,
    /// A video. Re-encoded to multi-resolution `WebM`.
    Video,
}

impl Kind {
    /// Classify by the uploaded content type. Unknown types are treated as
    /// still images so they still receive a safe preview.
    #[must_use]
    pub fn from_content_type(content_type: &str) -> Self {
        match content_type.split(';').next().unwrap_or_default().trim() {
            "image/gif" | "image/apng" => Self::AnimatedImage,
            "video/mp4" | "video/webm" | "video/quicktime" | "video/ogg" => Self::Video,
            _ => Self::Image,
        }
    }

    /// Output container for this kind.
    #[must_use]
    pub const fn format(self) -> Format {
        match self {
            Self::Video => Format::Webm,
            Self::Image | Self::AnimatedImage => Format::Webp,
        }
    }
}

/// Output format of a generated variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Webp,
    Webm,
    /// The untouched upload. Only used by the lossless layer.
    Original,
}

/// One generated variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VariantSpec {
    pub layer: Layer,
    pub format: Format,
    pub max_edge: u32,
    pub quality: u8,
    pub lossless: bool,
    /// Whether this variant survives after the lossless decision window.
    pub retain: bool,
}

/// Why a variant plan was rejected.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("image dimensions must be positive")]
    EmptyDimensions,
    #[error("quality must be between 1 and 100")]
    Quality,
    #[error("lossless media is not allowed for this account")]
    LosslessNotAllowed,
    #[error("the upload is not a decodable image")]
    Image,
    #[error("media processing failed: {0}")]
    Io(String),
    #[error("encoder failed: {0}")]
    Process(String),
    #[error("this layer has no encoder")]
    Unsupported,
}

/// Which lossless layers an account is permitted to request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LosslessPermissions {
    pub images: bool,
    pub videos: bool,
}

impl LosslessPermissions {
    /// No lossless uploads.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            images: false,
            videos: false,
        }
    }

    /// Both kinds.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            images: true,
            videos: true,
        }
    }

    /// Whether this permission covers a media kind.
    #[must_use]
    pub const fn allows(self, kind: Kind) -> bool {
        match kind {
            Kind::Image | Kind::AnimatedImage => self.images,
            Kind::Video => self.videos,
        }
    }
}

/// Preview longest edge. The variant is downscaled and recompressed;
/// larger sources are reduced, smaller ones are not upscaled.
pub const PREVIEW_EDGE: u32 = 1280;
/// Compressed full-size longest edge. This is a cache cap, not an upscale.
pub const COMPRESSED_EDGE: u32 = 4096;

/// Plan the variants for one attachment.
///
/// `lossless` is an author opt-in for art. Without it the original bytes are not
/// retained beyond the short compressed window.
pub fn plan(width: u32, height: u32, lossless: bool) -> Result<Vec<VariantSpec>, Error> {
    plan_for(Kind::Image, width, height, lossless)
}

/// Content-addressed object key. The digest is the source bytes; the variant
/// digest is the produced bytes, so a recompression never overwrites a cached
/// object that a CDN is still serving.
#[must_use]
pub fn object_key(source_digest: &str, variant_digest: &str, layer: Layer) -> String {
    format!("media/{source_digest}/{}/{variant_digest}", layer.as_str())
}

/// Plan variants for a classified upload. Images and GIFs become `WebP`, video
/// becomes `WebM` at every rendition; the original is kept only when asked.
pub fn plan_for(
    kind: Kind,
    width: u32,
    height: u32,
    lossless: bool,
) -> Result<Vec<VariantSpec>, Error> {
    plan_with_permissions(kind, width, height, lossless, LosslessPermissions::all())
}

/// Plan variants under an account's lossless permissions. A requested lossless
/// layer that the account may not use is an error, not a silent downgrade.
pub fn plan_with_permissions(
    kind: Kind,
    width: u32,
    height: u32,
    lossless: bool,
    permissions: LosslessPermissions,
) -> Result<Vec<VariantSpec>, Error> {
    if width == 0 || height == 0 {
        return Err(Error::EmptyDimensions);
    }
    if lossless && !permissions.allows(kind) {
        return Err(Error::LosslessNotAllowed);
    }
    let lossless = lossless && permissions.allows(kind);
    let format = kind.format();
    let mut variants = Vec::with_capacity(if lossless { 5 } else { 4 });
    variants.push(VariantSpec {
        layer: Layer::Preview,
        format,
        max_edge: PREVIEW_EDGE,
        quality: 82,
        lossless: false,
        retain: true,
    });
    if matches!(kind, Kind::Video) {
        let mut rendered = false;
        for (edge, quality) in [(360, 76), (720, 80), (1080, 84), (2160, 86)] {
            if height >= edge {
                rendered = true;
                variants.push(VariantSpec {
                    layer: Layer::Compressed,
                    format,
                    max_edge: edge,
                    quality,
                    lossless: false,
                    retain: true,
                });
            }
        }
        if !rendered {
            variants.push(VariantSpec {
                layer: Layer::Compressed,
                format,
                max_edge: height,
                quality: 80,
                lossless: false,
                retain: true,
            });
        }
    } else {
        variants.push(VariantSpec {
            layer: Layer::Compressed,
            format,
            max_edge: COMPRESSED_EDGE,
            quality: 88,
            lossless: false,
            retain: true,
        });
    }
    if (matches!(kind, Kind::Image | Kind::AnimatedImage) && permissions.allows(kind)) || lossless {
        variants.push(VariantSpec {
            layer: Layer::Lossless,
            format: Format::Original,
            max_edge: u32::MAX,
            quality: 100,
            lossless: true,
            retain: lossless,
        });
    }
    Ok(variants)
}

/// When a variant may be pruned. `None` means it lives with the status.
#[must_use]
pub fn expires_in(policy: CachePolicy, variant: &VariantSpec) -> Option<Duration> {
    match variant.layer {
        Layer::Preview => None,
        Layer::Compressed => Some(policy.compressed),
        Layer::Lossless if variant.retain => None,
        Layer::Lossless => Some(policy.lossless_pending),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_normal_image_keeps_a_temporary_lossless_candidate() {
        let variants = plan(2400, 1600, false).expect("plan");
        assert_eq!(variants.len(), 3);
        assert_eq!(variants[0].layer, Layer::Preview);
        assert_eq!(variants[1].layer, Layer::Compressed);
        assert_eq!(variants[2].layer, Layer::Lossless);
        assert!(!variants[2].retain);
        assert_eq!(
            expires_in(CachePolicy::default(), &variants[2]),
            Some(Duration::from_hours(24))
        );
    }

    #[test]
    fn lossless_art_gets_a_third_layer() {
        let variants = plan(2400, 1600, true).expect("plan");
        assert_eq!(variants.len(), 3);
        assert_eq!(variants[2].layer, Layer::Lossless);
        assert!(variants[2].lossless);
        assert!(variants[2].retain);
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
    fn a_gif_becomes_animated_webp() {
        assert_eq!(Kind::from_content_type("image/gif"), Kind::AnimatedImage);
        let variants = plan_for(Kind::AnimatedImage, 600, 400, false).expect("plan");
        assert!(variants
            .iter()
            .filter(|variant| variant.layer != Layer::Lossless)
            .all(|variant| variant.format == Format::Webp));
    }

    #[test]
    fn a_video_gets_multiple_webm_renditions() {
        assert_eq!(Kind::from_content_type("video/mp4"), Kind::Video);
        let variants = plan_for(Kind::Video, 1920, 1080, false).expect("plan");
        assert!(variants.len() >= 3);
        assert!(variants
            .iter()
            .all(|variant| variant.format == Format::Webm));
        assert!(variants.iter().any(|variant| variant.max_edge == 720));
        assert!(variants.iter().any(|variant| variant.max_edge == 1080));
    }

    #[test]
    fn lossless_video_keeps_the_original_after_the_webm_renditions() {
        let variants = plan_for(Kind::Video, 1920, 1080, true).expect("plan");
        let last = variants.last().expect("variant");
        assert_eq!(last.layer, Layer::Lossless);
        assert!(last.lossless);
    }

    #[test]
    fn an_account_without_image_permission_cannot_request_lossless() {
        assert_eq!(
            plan_with_permissions(
                Kind::Image,
                800,
                600,
                true,
                LosslessPermissions {
                    images: false,
                    videos: true
                }
            ),
            Err(Error::LosslessNotAllowed)
        );
    }

    #[test]
    fn video_permission_does_not_grant_image_lossless() {
        let variants = plan_with_permissions(
            Kind::Video,
            1920,
            1080,
            true,
            LosslessPermissions {
                images: false,
                videos: true,
            },
        )
        .expect("plan");
        assert_eq!(
            variants.last().map(|variant| variant.layer),
            Some(Layer::Lossless)
        );
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

/// A generated placeholder and the source dimensions that clients need for layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preview {
    pub blurhash: String,
    pub width: u32,
    pub height: u32,
}

/// Decodes an uploaded image and produces a blurhash placeholder.
///
/// This runs on the unmodified upload, before any preview is generated, so a
/// post can render its placeholder while the worker is still re-encoding.
pub fn blurhash(bytes: &[u8]) -> Result<Preview, Error> {
    let source = image::load_from_memory(bytes).map_err(|_| Error::Image)?;
    let (width, height) = (source.width(), source.height());
    if width == 0 || height == 0 {
        return Err(Error::EmptyDimensions);
    }
    let small = source.resize(32, 32, image::imageops::FilterType::Triangle);
    let rgba = small.to_rgba8();
    let hash = blurhash::encode(4, 3, rgba.width(), rgba.height(), &rgba.into_raw())
        .map_err(|_| Error::Image)?;
    Ok(Preview {
        blurhash: hash,
        width,
        height,
    })
}

#[cfg(test)]
mod preview_tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn an_image_gets_a_placeholder_and_its_source_dimensions() {
        let image = image::RgbaImage::from_pixel(8, 4, image::Rgba([220, 30, 90, 255]));
        let mut png = Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(image)
            .write_to(&mut png, image::ImageFormat::Png)
            .expect("png");
        let preview = blurhash(png.into_inner().as_slice()).expect("blurhash");
        assert!((4..=120).contains(&preview.blurhash.len()));
        assert_eq!((preview.width, preview.height), (8, 4));
    }

    #[test]
    fn a_non_image_is_rejected() {
        assert_eq!(blurhash(b"not an image"), Err(Error::Image));
    }
}
