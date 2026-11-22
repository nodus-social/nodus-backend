//! Turning an upload into the variants planned for it.
//!
//! The encoders are external so the server keeps a small dependency surface and can
//! swap codecs without rebuilding the storage layer. A missing encoder is a failed
//! job, never a dropped post: the original remains servable while processing is
//! retried.

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::process::Command;

use crate::{Error, Format, Kind, Layer, VariantSpec};

/// Why an animated image was rendered as its first frame instead.
///
/// The note is logged and carried back on the render, so an operator can tell a still
/// avatar from a GIF that was deliberately degraded rather than from one that lost its
/// animation by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StillReason {
    /// More than [`crate::MAX_ANIMATION_FRAMES`] frames.
    Frames,
    /// Longer than [`crate::MAX_ANIMATION_SECONDS`] seconds.
    Duration,
    /// More than [`crate::MAX_ANIMATION_PIXELS`] source pixels.
    Pixels,
    /// The probe could not say how big the animation is, so it was not animated unbounded.
    Unmeasured,
}

impl StillReason {
    /// Stable phrase used in the log line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Frames => "animation has too many frames",
            Self::Duration => "animation is too long",
            Self::Pixels => "animation frames are too large",
            Self::Unmeasured => "animation size could not be measured",
        }
    }
}

/// One encoded variant, ready to be written to the object store.
#[derive(Debug, Clone)]
pub struct Rendered {
    pub spec: VariantSpec,
    pub bytes: Vec<u8>,
    pub content_type: &'static str,
    /// Set when an animated source was rendered as a still because it exceeded a bound.
    pub still_reason: Option<StillReason>,
}

/// Encodes one planned variant from `source`.
///
/// # Errors
///
/// Returns [`Error::Io`] when the source cannot be read, [`Error::Process`] when the
/// encoder exits non-zero, and [`Error::Unsupported`] for a layer/format combination
/// that has no encoder.
pub async fn render_one(source: &Path, kind: Kind, spec: &VariantSpec) -> Result<Rendered, Error> {
    if spec.layer == Layer::Lossless {
        let bytes = tokio::fs::read(source).await.map_err(io)?;
        return Ok(Rendered {
            spec: *spec,
            bytes,
            content_type: content_type(spec.format),
            still_reason: None,
        });
    }

    if spec.format == Format::Webp && kind == Kind::Image {
        return render_still(source, spec).await;
    }
    // A `*_static` layer is a still by definition; an animated layer is a still when the
    // source is past the bounds. Either way the encoder writes one frame.
    let (animate, still_reason) = animated_or_still(source, kind, spec).await;
    let extension = match spec.format {
        Format::Webp => "webp",
        Format::Webm => "webm",
        Format::Original => return Err(Error::Unsupported),
    };
    let output = temporary_path(source, spec, extension);
    let mut command = Command::new(ffmpeg());
    command
        .arg("-v")
        .arg("error")
        .arg("-y")
        .arg("-i")
        .arg(source);
    if spec.format == Format::Webp {
        command
            .arg("-vf")
            .arg(webp_scale_filter(spec.max_edge))
            .arg("-c:v")
            .arg(if animate { "libwebp_anim" } else { "libwebp" })
            .arg("-lossless")
            .arg(if spec.lossless { "1" } else { "0" })
            .arg("-quality")
            .arg(spec.quality.to_string());
        if animate {
            command.arg("-loop").arg("0");
        } else {
            command.arg("-frames:v").arg("1");
        }
    } else {
        command
            .arg("-vf")
            .arg(if spec.layer == Layer::Preview {
                scale_filter(spec.max_edge)
            } else {
                height_filter(spec.max_edge)
            })
            .arg("-c:v")
            .arg("libvpx-vp9")
            .arg("-crf")
            .arg((100_u8.saturating_sub(spec.quality)).to_string())
            .arg("-b:v")
            .arg("0")
            .arg("-row-mt")
            .arg("1")
            .arg("-an");
    }
    command.arg("-f").arg(extension).arg(&output);
    let bytes = run_ffmpeg(command, &output).await?;
    Ok(Rendered {
        spec: *spec,
        bytes,
        content_type: content_type(spec.format),
        still_reason,
    })
}

/// Whether this variant animates, and why it does not when it was expected to.
///
/// A degradation is logged here, once, at the point where the encoder is about to write
/// the first frame instead of every frame.
async fn animated_or_still(
    source: &Path,
    kind: Kind,
    spec: &VariantSpec,
) -> (bool, Option<StillReason>) {
    if kind != Kind::AnimatedImage || spec.layer.is_still() {
        return (false, None);
    }
    match animation_within_bounds(source).await {
        Ok(()) => (true, None),
        Err(reason) => {
            tracing::warn!(
                path = %source.display(),
                reason = reason.as_str(),
                "animation degraded to its first frame"
            );
            (false, Some(reason))
        }
    }
}

/// Whether an animated source is inside the documented bounds.
///
/// A probe that cannot answer counts as over the bound: failing to measure is not a
/// licence to animate without one, and a still is still the picture. The upload itself
/// never fails on this path.
async fn animation_within_bounds(source: &Path) -> Result<(), StillReason> {
    let output = Command::new(ffprobe())
        .arg("-v")
        .arg("error")
        .arg("-select_streams")
        .arg("v:0")
        .arg("-count_frames")
        .arg("-show_entries")
        .arg("stream=nb_read_frames,width,height:format=duration")
        .arg("-of")
        .arg("default=nw=1")
        .arg(source)
        .output()
        .await
        .map_err(|_| StillReason::Unmeasured)?;
    if !output.status.success() {
        return Err(StillReason::Unmeasured);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut frames = None;
    let mut seconds = None;
    let mut width = None;
    let mut height = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "nb_read_frames" => frames = value.trim().parse::<u64>().ok(),
            "duration" => seconds = value.trim().parse::<f64>().ok(),
            "width" => width = value.trim().parse::<u64>().ok(),
            "height" => height = value.trim().parse::<u64>().ok(),
            _ => {}
        }
    }
    if frames.is_none() && seconds.is_none() {
        return Err(StillReason::Unmeasured);
    }
    if frames.is_some_and(|frames| frames > crate::MAX_ANIMATION_FRAMES) {
        return Err(StillReason::Frames);
    }
    if seconds.is_some_and(|seconds| seconds > crate::MAX_ANIMATION_SECONDS) {
        return Err(StillReason::Duration);
    }
    if let (Some(width), Some(height)) = (width, height) {
        if width.saturating_mul(height) > crate::MAX_ANIMATION_PIXELS {
            return Err(StillReason::Pixels);
        }
    }
    Ok(())
}

async fn run_ffmpeg(mut command: Command, output: &Path) -> Result<Vec<u8>, Error> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let result = command.output().await.map_err(io)?;
    if !result.status.success() {
        let _ = tokio::fs::remove_file(output).await;
        let message = String::from_utf8_lossy(&result.stderr);
        return Err(Error::Process(message.trim().to_owned()));
    }
    let bytes = tokio::fs::read(output).await.map_err(io)?;
    let _ = tokio::fs::remove_file(output).await;
    if bytes.is_empty() {
        return Err(Error::Process("encoder produced an empty file".to_owned()));
    }
    Ok(bytes)
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the scaled dimensions are bounded by the source dimensions"
)]
async fn render_still(source: &Path, spec: &VariantSpec) -> Result<Rendered, Error> {
    if !spec.lossless {
        if !(1..=100).contains(&spec.quality) {
            return Err(Error::Quality);
        }
        tokio::fs::metadata(source).await.map_err(io)?;
        let output = temporary_path(source, spec, "webp");
        let mut command = Command::new(ffmpeg());
        command
            .arg("-v")
            .arg("error")
            .arg("-y")
            .arg("-i")
            .arg(source)
            .arg("-vf")
            .arg(webp_scale_filter(spec.max_edge))
            .arg("-c:v")
            .arg("libwebp")
            .arg("-lossless")
            .arg("0")
            .arg("-quality")
            .arg(spec.quality.to_string())
            .arg("-frames:v")
            .arg("1")
            .arg("-f")
            .arg("webp")
            .arg(&output);
        let bytes = run_ffmpeg(command, &output).await?;
        return Ok(Rendered {
            spec: *spec,
            bytes,
            content_type: "image/webp",
            still_reason: None,
        });
    }

    let bytes = tokio::fs::read(source).await.map_err(io)?;
    let image = image::load_from_memory(&bytes).map_err(|_| Error::Image)?;
    let (width, height) = (image.width(), image.height());
    let longest = width.max(height);
    let image = if longest > spec.max_edge {
        let scale = f64::from(spec.max_edge) / f64::from(longest);
        image.resize(
            (f64::from(width) * scale).round().max(1.0) as u32,
            (f64::from(height) * scale).round().max(1.0) as u32,
            image::imageops::FilterType::Lanczos3,
        )
    } else {
        image
    };
    let mut output = Vec::new();
    if image.color().has_alpha() {
        let rgba = image.to_rgba8();
        image::codecs::webp::WebPEncoder::new_lossless(Cursor::new(&mut output))
            .encode(
                rgba.as_raw(),
                rgba.width(),
                rgba.height(),
                image::ExtendedColorType::Rgba8,
            )
            .map_err(|_| Error::Image)?;
    } else {
        let rgb = image.to_rgb8();
        image::codecs::webp::WebPEncoder::new_lossless(Cursor::new(&mut output))
            .encode(
                rgb.as_raw(),
                rgb.width(),
                rgb.height(),
                image::ExtendedColorType::Rgb8,
            )
            .map_err(|_| Error::Image)?;
    }
    Ok(Rendered {
        spec: *spec,
        bytes: output,
        content_type: "image/webp",
        still_reason: None,
    })
}

fn webp_scale_filter(edge: u32) -> String {
    format!("scale='min({edge},iw)':'min({edge},ih)':force_original_aspect_ratio=decrease")
}

fn scale_filter(edge: u32) -> String {
    format!(
        "scale=w='min(iw,{edge})':h='min(ih,{edge})':force_original_aspect_ratio=decrease:force_divisible_by=2"
    )
}

fn height_filter(edge: u32) -> String {
    format!("scale=-2:'min(ih,{edge})'")
}

fn ffmpeg() -> PathBuf {
    std::env::var_os("NODUS_FFMPEG").map_or_else(|| PathBuf::from("ffmpeg"), PathBuf::from)
}

fn content_type(format: Format) -> &'static str {
    match format {
        Format::Webp => "image/webp",
        Format::Webm => "video/webm",
        Format::Original => "application/octet-stream",
    }
}

fn temporary_path(source: &Path, spec: &VariantSpec, extension: &str) -> PathBuf {
    let mut name = source.as_os_str().to_os_string();
    name.push(format!(
        ".{}.{}.{}.{}",
        spec.layer.as_str(),
        spec.max_edge,
        ulid::Ulid::new(),
        extension
    ));
    PathBuf::from(name)
}

#[allow(clippy::needless_pass_by_value)]
fn io(error: std::io::Error) -> Error {
    Error::Io(error.to_string())
}

/// Probes video dimensions with `ffprobe`. Images use the decoder in [`crate::blurhash`].
pub async fn video_dimensions(source: &Path) -> Option<(u32, u32)> {
    let output = Command::new(ffprobe())
        .arg("-v")
        .arg("error")
        .arg("-select_streams")
        .arg("v:0")
        .arg("-show_entries")
        .arg("stream=width,height")
        .arg("-of")
        .arg("csv=s=x:p=0")
        .arg(source)
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let (width, height) = text.trim().split_once('x')?;
    Some((width.parse().ok()?, height.parse().ok()?))
}

fn ffprobe() -> PathBuf {
    std::env::var_os("NODUS_FFPROBE").map_or_else(|| PathBuf::from("ffprobe"), PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_still_smaller_than_the_preview_is_not_upscaled() {
        let path = std::env::temp_dir().join(format!("nodus-media-{}.png", std::process::id()));
        let image = image::RgbImage::from_pixel(8, 4, image::Rgb([20, 40, 60]));
        image.save(&path).unwrap();
        let spec = VariantSpec {
            layer: Layer::Preview,
            format: Format::Webp,
            max_edge: 1280,
            quality: 82,
            lossless: false,
            retain: true,
        };
        let rendered = render_still(&path, &spec).await.unwrap();
        let _ = tokio::fs::remove_file(&path).await;
        let decoded = image::load_from_memory(&rendered.bytes).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (8, 4));
    }

    /// A real GIF from the test machine's ffmpeg, or `None` when it has none.
    async fn animated_gif(rate: u32, seconds: u32) -> Option<std::path::PathBuf> {
        let path = std::env::temp_dir().join(format!(
            "nodus-media-anim-{}-{}.gif",
            std::process::id(),
            ulid::Ulid::new()
        ));
        let status = Command::new(ffmpeg())
            .args(["-v", "error", "-y", "-f", "lavfi", "-i"])
            .arg(format!("testsrc=size=64x64:rate={rate}"))
            .args(["-t", &seconds.to_string(), "-loop", "0"])
            .arg(&path)
            .status()
            .await
            .ok()?;
        status.success().then_some(path)
    }

    fn profile_spec(layer: Layer) -> VariantSpec {
        VariantSpec {
            layer,
            format: Format::Webp,
            max_edge: crate::AVATAR_EDGE,
            quality: 82,
            lossless: false,
            retain: true,
        }
    }

    #[tokio::test]
    async fn a_short_gif_keeps_its_animation_in_the_avatar_layer() {
        let Some(path) = animated_gif(10, 2).await else {
            return;
        };
        let rendered = render_one(&path, Kind::AnimatedImage, &profile_spec(Layer::Avatar))
            .await
            .expect("render");
        let _ = tokio::fs::remove_file(&path).await;
        assert!(has_webp_chunk(&rendered.bytes, *b"ANMF"));
        assert_eq!(rendered.still_reason, None);
    }

    #[tokio::test]
    async fn a_gif_past_the_duration_bound_comes_back_still_with_a_reason() {
        // 16 frames over 16 seconds: few frames, too long. The bounds are independent.
        let Some(path) = animated_gif(1, 16).await else {
            return;
        };
        let rendered = render_one(&path, Kind::AnimatedImage, &profile_spec(Layer::Avatar))
            .await
            .expect("render");
        let _ = tokio::fs::remove_file(&path).await;
        assert!(!has_webp_chunk(&rendered.bytes, *b"ANMF"));
        assert_eq!(rendered.still_reason, Some(StillReason::Duration));
    }

    #[tokio::test]
    async fn a_static_layer_of_a_gif_is_a_still_without_a_reason() {
        let Some(path) = animated_gif(10, 2).await else {
            return;
        };
        let rendered = render_one(
            &path,
            Kind::AnimatedImage,
            &profile_spec(Layer::AvatarStatic),
        )
        .await
        .expect("render");
        let _ = tokio::fs::remove_file(&path).await;
        assert!(!has_webp_chunk(&rendered.bytes, *b"ANMF"));
        assert_eq!(rendered.still_reason, None);
    }

    #[test]
    fn the_video_rendition_filter_caps_height_without_upscaling() {
        assert_eq!(height_filter(240), "scale=-2:'min(ih,240)'");
    }

    #[test]
    fn the_video_scale_filter_never_upscales() {
        let filter = scale_filter(1280);
        assert!(filter.contains("min(iw,1280)"));
        assert!(filter.contains("min(ih,1280)"));
        assert!(filter.contains("force_original_aspect_ratio=decrease"));
    }

    fn has_webp_chunk(bytes: &[u8], chunk: [u8; 4]) -> bool {
        if bytes.len() < 12 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WEBP" {
            return false;
        }
        let mut offset = 12;
        while offset + 8 <= bytes.len() {
            if bytes[offset..offset + 4] == chunk {
                return true;
            }
            let size = u32::from_le_bytes([
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]) as usize;
            let padded = size + (size & 1);
            offset = offset.saturating_add(8).saturating_add(padded);
        }
        false
    }

    #[tokio::test]
    async fn render_still_uses_lossy_webp_with_quality_when_not_lossless() {
        let path = std::env::temp_dir().join(format!(
            "nodus-media-quality-{}-{}.png",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut img = image::RgbImage::new(256, 256);
        for (x, y, pixel) in img.enumerate_pixels_mut() {
            let r = u8::try_from((x * 37 + y * 13 + ((x ^ y) * 7)) % 256).unwrap();
            let g = u8::try_from((x * 19 + y * 53 + ((x.wrapping_mul(y)) % 251)) % 256).unwrap();
            let b = u8::try_from((x * 71 + y * 29 + ((x + y * 3) * 11)) % 256).unwrap();
            *pixel = image::Rgb([r, g, b]);
        }
        img.save(&path).unwrap();

        let low_quality = VariantSpec {
            layer: Layer::Preview,
            format: Format::Webp,
            max_edge: 256,
            quality: 20,
            lossless: false,
            retain: true,
        };
        let high_quality = VariantSpec {
            layer: Layer::Compressed,
            format: Format::Webp,
            max_edge: 256,
            quality: 88,
            lossless: false,
            retain: true,
        };
        let lossless = VariantSpec {
            layer: Layer::Preview,
            format: Format::Webp,
            max_edge: 256,
            quality: 100,
            lossless: true,
            retain: true,
        };

        let low = render_still(&path, &low_quality).await.unwrap();
        let high = render_still(&path, &high_quality).await.unwrap();
        let loss = render_still(&path, &lossless).await.unwrap();
        let _ = tokio::fs::remove_file(&path).await;

        assert!(
            has_webp_chunk(&low.bytes, *b"VP8 "),
            "expected lossy VP8 chunk for !lossless"
        );
        assert!(
            !has_webp_chunk(&low.bytes, *b"VP8L"),
            "unexpected lossless VP8L chunk for !lossless"
        );
        assert!(
            has_webp_chunk(&loss.bytes, *b"VP8L"),
            "expected lossless VP8L chunk for lossless"
        );
        assert!(
            low.bytes.len() < high.bytes.len(),
            "expected quality=20 ({}) < quality=88 ({})",
            low.bytes.len(),
            high.bytes.len()
        );
        assert!(
            high.bytes.len() < loss.bytes.len(),
            "expected lossy quality=88 ({}) < lossless ({})",
            high.bytes.len(),
            loss.bytes.len()
        );
    }

    #[tokio::test]
    async fn render_still_downscales_larger_images_in_lossy_mode() {
        let path = std::env::temp_dir().join(format!(
            "nodus-media-scale-{}-{}.png",
            std::process::id(),
            ulid::Ulid::new()
        ));
        let image = image::RgbImage::from_pixel(200, 100, image::Rgb([10, 120, 200]));
        image.save(&path).unwrap();
        let spec = VariantSpec {
            layer: Layer::Preview,
            format: Format::Webp,
            max_edge: 100,
            quality: 82,
            lossless: false,
            retain: true,
        };
        let rendered = render_still(&path, &spec).await.unwrap();
        let _ = tokio::fs::remove_file(&path).await;
        let decoded = image::load_from_memory(&rendered.bytes).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (100, 50));
    }

    #[test]
    fn temporary_path_includes_max_edge_and_unique_ulid() {
        let source = Path::new("/tmp/media/deadbeef");
        let spec_360 = VariantSpec {
            layer: Layer::Compressed,
            format: Format::Webm,
            max_edge: 360,
            quality: 76,
            lossless: false,
            retain: true,
        };
        let spec_720 = VariantSpec {
            max_edge: 720,
            quality: 80,
            ..spec_360
        };

        let first = temporary_path(source, &spec_360, "webm");
        let second = temporary_path(source, &spec_720, "webm");
        let third = temporary_path(source, &spec_720, "webm");

        assert_ne!(first, second);
        assert_ne!(second, third);
        let first_str = first.to_string_lossy();
        let second_str = second.to_string_lossy();
        assert!(first_str.starts_with("/tmp/media/deadbeef.compressed.360."));
        assert!(first_str.ends_with(".webm"));
        assert!(second_str.starts_with("/tmp/media/deadbeef.compressed.720."));
        assert!(second_str.ends_with(".webm"));
    }

    #[tokio::test]
    async fn concurrent_render_one_calls_on_same_source_do_not_collide() {
        let path = std::env::temp_dir().join(format!(
            "nodus-media-concurrent-{}-{}",
            std::process::id(),
            ulid::Ulid::new()
        ));
        let image = image::RgbImage::from_pixel(160, 120, image::Rgb([50, 90, 130]));
        let mut png = Vec::new();
        image::DynamicImage::ImageRgb8(image)
            .write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        tokio::fs::write(&path, png).await.unwrap();

        let spec_a = VariantSpec {
            layer: Layer::Compressed,
            format: Format::Webp,
            max_edge: 120,
            quality: 80,
            lossless: false,
            retain: true,
        };
        let spec_b = VariantSpec {
            max_edge: 120,
            quality: 80,
            ..spec_a
        };

        let (res_a, res_b) = tokio::join!(
            render_one(&path, Kind::Image, &spec_a),
            render_one(&path, Kind::Image, &spec_b),
        );
        let _ = tokio::fs::remove_file(&path).await;
        assert!(res_a.is_ok(), "first concurrent render failed: {res_a:?}");
        assert!(res_b.is_ok(), "second concurrent render failed: {res_b:?}");
    }
}
