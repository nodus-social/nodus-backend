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

/// One encoded variant, ready to be written to the object store.
#[derive(Debug, Clone)]
pub struct Rendered {
    pub spec: VariantSpec,
    pub bytes: Vec<u8>,
    pub content_type: &'static str,
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
        });
    }

    if spec.format == Format::Webp && kind == Kind::Image {
        return render_still(source, spec).await;
    }
    let extension = match spec.format {
        Format::Webp => "webp",
        Format::Webm => "webm",
        Format::Original => return Err(Error::Unsupported),
    };
    let output = temporary_path(source, spec.layer, extension);
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
            .arg(format!(
                "scale='min({edge},iw)':'min({edge},ih)':force_original_aspect_ratio=decrease",
                edge = spec.max_edge
            ))
            .arg("-c:v")
            .arg(if kind == Kind::AnimatedImage {
                "libwebp_anim"
            } else {
                "libwebp"
            })
            .arg("-quality")
            .arg(spec.quality.to_string());
        if kind == Kind::AnimatedImage {
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
    command
        .arg("-f")
        .arg(extension)
        .arg(&output)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let result = command.output().await.map_err(io)?;
    if !result.status.success() {
        let _ = tokio::fs::remove_file(&output).await;
        let message = String::from_utf8_lossy(&result.stderr);
        return Err(Error::Process(message.trim().to_owned()));
    }
    let bytes = tokio::fs::read(&output).await.map_err(io)?;
    let _ = tokio::fs::remove_file(&output).await;
    if bytes.is_empty() {
        return Err(Error::Process("encoder produced an empty file".to_owned()));
    }
    Ok(Rendered {
        spec: *spec,
        bytes,
        content_type: content_type(spec.format),
    })
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the scaled dimensions are bounded by the source dimensions"
)]
async fn render_still(source: &Path, spec: &VariantSpec) -> Result<Rendered, Error> {
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
    })
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

fn temporary_path(source: &Path, layer: Layer, extension: &str) -> PathBuf {
    let mut name = source.as_os_str().to_os_string();
    name.push(format!(".{}.{}", layer.as_str(), extension));
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
}
