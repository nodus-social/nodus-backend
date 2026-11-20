//! The storage contract: a digest in, bytes out, and the range syntax over them.

use thiserror::Error;

/// A byte range as an HTTP `Range` header spells it.
///
/// `start` and `end` are inclusive, matching both the header and the way a caller
/// slicing a buffer reads them. The suffix form (`bytes=-3`, "the last three bytes")
/// cannot be resolved without the length, so [`ByteRange::parse`] keeps it in `suffix`
/// and [`ByteRange::resolve`] turns it into offsets once the length is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// First byte offset; `0` for a suffix range, where `suffix` carries the intent.
    pub start: u64,
    /// Last byte offset, inclusive. `None` means "to the end of the object".
    pub end: Option<u64>,
    /// For `bytes=-n`, the number of trailing bytes wanted.
    pub suffix: Option<u64>,
}

impl ByteRange {
    /// Parses the value of a `Range` header: `bytes=a-b`, `bytes=a-` or `bytes=-n`.
    ///
    /// Multi-range requests (`bytes=0-1,5-6`) are not supported in this phase and are
    /// reported as [`RangeError::Malformed`], along with anything else that is not one
    /// of the three shapes above.
    pub fn parse(value: &str) -> Result<Self, RangeError> {
        let spec = value
            .strip_prefix("bytes=")
            .ok_or(RangeError::Malformed)?
            .trim();
        if spec.contains(',') {
            return Err(RangeError::Malformed);
        }
        let (head, tail) = spec.split_once('-').ok_or(RangeError::Malformed)?;
        if head.is_empty() {
            // `bytes=-n`: the last n bytes.
            if tail.is_empty() {
                return Err(RangeError::Malformed);
            }
            let n: u64 = tail.parse().map_err(|_| RangeError::Malformed)?;
            if n == 0 {
                // `bytes=-0` asks for nothing, which no object can satisfy.
                return Err(RangeError::Unsatisfiable);
            }
            return Ok(Self {
                start: 0,
                end: None,
                suffix: Some(n),
            });
        }
        let start: u64 = head.parse().map_err(|_| RangeError::Malformed)?;
        if tail.is_empty() {
            return Ok(Self {
                start,
                end: None,
                suffix: None,
            });
        }
        let end: u64 = tail.parse().map_err(|_| RangeError::Malformed)?;
        if end < start {
            // Well formed, but asks for a stretch that cannot exist.
            return Err(RangeError::Unsatisfiable);
        }
        Ok(Self {
            start,
            end: Some(end),
            suffix: None,
        })
    }

    /// Resolves this range against an object of `len` bytes, as inclusive offsets.
    ///
    /// An end past the object is clamped rather than refused, as HTTP requires: a
    /// client that asks for more than there is gets what there is.
    pub fn resolve(&self, len: u64) -> Result<(u64, u64), RangeError> {
        if let Some(n) = self.suffix {
            if n == 0 || len == 0 {
                return Err(RangeError::Unsatisfiable);
            }
            return Ok((len.saturating_sub(n), len - 1));
        }
        if self.start >= len {
            return Err(RangeError::Unsatisfiable);
        }
        let end = self.end.map_or(len - 1, |end| end.min(len - 1));
        Ok((self.start, end))
    }
}

/// Why a `Range` header could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RangeError {
    /// The header was not one of `bytes=a-b`, `bytes=a-`, `bytes=-n`.
    #[error("the range header is not a form this store understands")]
    Malformed,
    /// The header parsed, but names no byte of this object.
    #[error("the range names no byte of this object")]
    Unsatisfiable,
}

/// What a `put` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Put {
    /// The bytes were written.
    Created,
    /// The digest was already stored, so nothing was written.
    Existed,
}

/// Why a blob operation failed.
#[derive(Debug, Error)]
pub enum BlobError {
    /// No bytes are stored under this digest.
    #[error("no bytes are stored under {0}")]
    NotFound(String),
    /// The digest handed in does not name the bytes handed in.
    #[error("digest {expected} does not match the bytes, which hash to {actual}")]
    DigestMismatch {
        /// The digest the caller claimed.
        expected: String,
        /// The digest the bytes actually hash to.
        actual: String,
    },
    /// A range parsed, but names no byte of the object.
    #[error(transparent)]
    Range(#[from] RangeError),
    /// The backing store failed.
    #[error("blob store i/o failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Content-addressed bytes, keyed by `hex(sha256(bytes))`.
///
/// Every method takes the digest as text because that is what a URL carries; the store
/// is responsible for rejecting anything that cannot be one (a path fragment, an
/// uppercase hex string, the wrong length) before it touches a filesystem or a bucket.
#[allow(
    async_fn_in_trait,
    reason = "one implementation ships in this phase; a boxed future buys nothing yet"
)]
pub trait BlobStore: Send + Sync {
    /// Whether bytes are stored under `digest`.
    async fn has(&self, digest: &str) -> bool;

    /// The stored length, or `None` when nothing is stored under `digest`.
    async fn size(&self, digest: &str) -> Option<u64>;

    /// Reads `digest`, optionally sliced to `range`.
    ///
    /// The whole object is held in memory in this phase; the streaming variant arrives
    /// with the CDN work, and callers should not assume these bytes stay small forever.
    async fn read(&self, digest: &str, range: Option<ByteRange>) -> Result<Vec<u8>, BlobError>;

    /// Stores `bytes` under `digest`, after checking that `digest` names them.
    ///
    /// A digest is an address, so the check is not optional: bytes that do not hash to
    /// the digest they were sent as are rejected and leave nothing behind, or two
    /// different byte strings could both answer to one URL.
    async fn put(&self, digest: &str, bytes: &[u8]) -> Result<Put, BlobError>;

    /// Removes `digest`, treating "already gone" as success.
    async fn delete(&self, digest: &str) -> Result<(), BlobError>;
}
