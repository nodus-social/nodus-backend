//! The two digests the instance keeps about bytes it accepted.
//!
//! An exact hash answers "is this the same file"; a perceptual one answers "is this the
//! same picture", which is what a re-encode, a crop or a resize leaves behind. Content
//! sets carry both (see `crates/api/src/guard.rs`), so both are computed at the same
//! moment, from the same bytes, and both are stored as lowercase hex.

use image::imageops::{self, FilterType};
use sha2::{Digest, Sha256};

/// dHash samples a 9x8 grayscale copy: eight rows of eight left/right comparisons,
/// sixty-four bits. Small enough to compare with a XOR and a popcount, wide enough that a
/// different photograph is unlikely to land within ten flips of another.
const DHASH_WIDTH: u32 = 9;
const DHASH_HEIGHT: u32 = 8;

/// What one attachment hashed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hashes {
    /// SHA-256 of the bytes as they arrived, 64 lowercase hex characters.
    pub content_hash: String,
    /// 64-bit dHash as 16 lowercase hex characters; `None` when the bytes are not an image
    /// this build can decode (a video, an audio file, a malformed picture).
    pub perceptual_hash: Option<String>,
}

impl Hashes {
    /// Hashes bytes that were just accepted.
    ///
    /// `decode_image` is the caller's knowledge of the content type: a video is hashed for
    /// its bytes and never handed to the decoder, because decoding six megabytes of MP4 to
    /// learn it is not an image wastes the ingest budget.
    #[must_use]
    pub fn of_bytes(bytes: &[u8], decode_image: bool) -> Self {
        let content_hash = hex(&Sha256::digest(bytes));
        let perceptual_hash = if decode_image {
            perceptual_bits(bytes).map(|bits| format!("{bits:016x}"))
        } else {
            None
        };
        Self {
            content_hash,
            perceptual_hash,
        }
    }

    /// The perceptual hash as bits, when there is one.
    #[must_use]
    pub fn perceptual_bits(&self) -> Option<u64> {
        self.perceptual_hash
            .as_deref()
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
    }
}

/// The dHash of a decodable image: each bit says whether a pixel is brighter than the one
/// to its right, so the value survives a change of format, quality or size.
#[must_use]
pub fn perceptual_bits(bytes: &[u8]) -> Option<u64> {
    let decoded = image::load_from_memory(bytes).ok()?;
    let small = imageops::resize(
        &decoded.to_luma8(),
        DHASH_WIDTH,
        DHASH_HEIGHT,
        FilterType::Triangle,
    );
    let mut bits = 0u64;
    for y in 0..DHASH_HEIGHT {
        for x in 0..DHASH_WIDTH - 1 {
            let left = small.get_pixel(x, y).0[0];
            let right = small.get_pixel(x + 1, y).0[0];
            bits = (bits << 1) | u64::from(left > right);
        }
    }
    Some(bits)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing into a String cannot fail, and the capacity is already reserved.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A picture the `image` crate can decode without a fixture file: a PNG built in
    /// memory, bright on the left, dark on the right, so its dHash is not all zeroes.
    fn sample_png(shift: u32) -> Vec<u8> {
        let mut canvas = image::GrayImage::new(32, 32);
        for (x, _, pixel) in canvas.enumerate_pixels_mut() {
            let value = u8::try_from((x + shift) % 32 * 8).unwrap_or(0);
            *pixel = image::Luma([value]);
        }
        let mut png = Vec::new();
        image::DynamicImage::ImageLuma8(canvas)
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .expect("encode png");
        png
    }

    #[test]
    fn the_same_bytes_hash_the_same_way() {
        let png = sample_png(0);
        let first = Hashes::of_bytes(&png, true);
        let second = Hashes::of_bytes(&png, true);
        assert_eq!(first, second);
        assert_eq!(first.content_hash.len(), 64);
        assert!(first.perceptual_hash.is_some());
    }

    #[test]
    fn the_hash_is_stable_across_a_re_encode() {
        let png = sample_png(0);
        let jpeg = {
            let decoded = image::load_from_memory(&png).expect("decode");
            let mut out = Vec::new();
            decoded
                .write_to(
                    &mut std::io::Cursor::new(&mut out),
                    image::ImageFormat::Jpeg,
                )
                .expect("encode jpeg");
            out
        };
        let a = Hashes::of_bytes(&png, true);
        let b = Hashes::of_bytes(&jpeg, true);
        // The bytes differ, which is the whole point of the second hash.
        assert_ne!(a.content_hash, b.content_hash);
        let distance =
            (a.perceptual_bits().expect("png") ^ b.perceptual_bits().expect("jpeg")).count_ones();
        assert!(distance < 6, "re-encode drifted {distance} bits");
    }

    #[test]
    fn a_video_gets_only_the_byte_hash() {
        let hashes = Hashes::of_bytes(b"\x00\x00\x00\x18ftypmp42not really a video", false);
        assert_eq!(hashes.content_hash.len(), 64);
        assert!(hashes.perceptual_hash.is_none());
        assert!(hashes.perceptual_bits().is_none());
    }
}
