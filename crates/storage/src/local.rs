//! A blob store over a plain directory: `root/<digest>`.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::blob::{BlobError, BlobStore, ByteRange, Put};

/// Blobs as files in one directory, named by their digest.
///
/// The layout is the one `crates/media` already uses (`root.join(digest)`), so the media
/// surface can keep serving these files directly and this store can take over writing
/// them without a migration. A digest is not a path a caller may shape freely, so
/// anything that is not 64 lowercase hex characters is refused before it reaches the
/// filesystem — `..` and `/` cannot become a directory traversal.
#[derive(Debug, Clone)]
pub struct LocalDiskBlobStore {
    root: PathBuf,
}

impl LocalDiskBlobStore {
    /// Stores blobs under `root`, which is created on first write.
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// The directory blobs live in.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl BlobStore for LocalDiskBlobStore {
    async fn has(&self, digest: &str) -> bool {
        is_digest(digest)
            && tokio::fs::try_exists(self.root.join(digest))
                .await
                .unwrap_or(false)
    }

    async fn size(&self, digest: &str) -> Option<u64> {
        if !is_digest(digest) {
            return None;
        }
        tokio::fs::metadata(self.root.join(digest))
            .await
            .ok()
            .map(|metadata| metadata.len())
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "both offsets come from a buffer length, so they fit a usize"
    )]
    async fn read(&self, digest: &str, range: Option<ByteRange>) -> Result<Vec<u8>, BlobError> {
        if !is_digest(digest) {
            return Err(BlobError::NotFound(digest.to_owned()));
        }
        let bytes = match tokio::fs::read(self.root.join(digest)).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(BlobError::NotFound(digest.to_owned()));
            }
            Err(error) => return Err(BlobError::Io(error)),
        };
        let Some(range) = range else {
            return Ok(bytes);
        };
        let len = bytes.len() as u64;
        let (start, end) = range.resolve(len)?;
        // `resolve` guarantees start <= end < len, so the slice is in bounds.
        Ok(bytes[start as usize..=end as usize].to_vec())
    }

    async fn put(&self, digest: &str, bytes: &[u8]) -> Result<Put, BlobError> {
        let actual = hex(&Sha256::digest(bytes));
        if actual != digest {
            // Rejected before anything is written, so a bad digest leaves no file behind
            // and cannot occupy the address of bytes it does not name.
            return Err(BlobError::DigestMismatch {
                expected: digest.to_owned(),
                actual,
            });
        }
        if self.has(digest).await {
            return Ok(Put::Existed);
        }
        write_atomically(&self.root, digest, bytes).await?;
        // Two writers racing on one digest both stage the same bytes and both rename;
        // the second rename is a no-op replacement, and either may report `Created`.
        Ok(Put::Created)
    }

    async fn delete(&self, digest: &str) -> Result<(), BlobError> {
        if !is_digest(digest) {
            // Nothing that could exist under this name, so deleting it is already done.
            return Ok(());
        }
        match tokio::fs::remove_file(self.root.join(digest)).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(BlobError::Io(error)),
        }
    }
}

/// Writes bytes beside the target and renames them into place.
///
/// The staging file is in the same directory as the target, so the rename is atomic: a
/// reader (this process, a peer fetching from it, or `crates/media` serving the same
/// directory) sees either the previous state or the whole file, never a half-written one
/// under the digest's own name. A failed write removes the staging file rather than
/// leaving a partial one behind.
async fn write_atomically(root: &Path, digest: &str, bytes: &[u8]) -> std::io::Result<()> {
    tokio::fs::create_dir_all(root).await?;
    let staged = root.join(format!(".{digest}.{}.part", ulid::Ulid::new()));
    if let Err(error) = tokio::fs::write(&staged, bytes).await {
        cleanup(&staged).await;
        return Err(error);
    }
    if let Err(error) = tokio::fs::rename(&staged, root.join(digest)).await {
        cleanup(&staged).await;
        return Err(error);
    }
    Ok(())
}

/// Removes a staging file that will not be renamed, without masking the real error.
async fn cleanup(staged: &Path) {
    if let Err(error) = tokio::fs::remove_file(staged).await {
        tracing::warn!(%error, path = %staged.display(), "could not remove a staged blob");
    }
}

/// Whether `digest` is the lowercase hex SHA-256 this store's layout assumes.
fn is_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Lowercase hex, the spelling every digest in this tree uses.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}
