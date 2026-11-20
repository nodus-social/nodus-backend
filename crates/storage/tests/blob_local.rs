//! The blob store's contract, exercised on a real directory.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use nodus_storage::{BlobError, BlobStore, ByteRange, LocalDiskBlobStore, Put};
use sha2::{Digest, Sha256};

/// Eleven bytes: enough to make `5-9` and `-3` distinguishable from "all of it".
const ELEVEN: &[u8] = b"hello world";

/// A fresh directory under the system temp dir, removed when the test ends.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "nodus-storage-{name}-{}-{nanos}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("scratch directory");
        Self { root }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn digest_of(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn store(name: &str) -> (Scratch, LocalDiskBlobStore, String) {
    let scratch = Scratch::new(name);
    let store = LocalDiskBlobStore::new(scratch.root.clone());
    (scratch, store, digest_of(ELEVEN))
}

#[tokio::test]
async fn a_closed_range_returns_exactly_those_bytes() {
    let (scratch, store, digest) = store("closed");
    assert_eq!(store.put(&digest, ELEVEN).await.unwrap(), Put::Created);

    let range = ByteRange::parse("bytes=5-9").unwrap();
    let bytes = store.read(&digest, Some(range)).await.unwrap();
    assert_eq!(bytes, b" worl");
    assert_eq!(bytes.len(), 5);
    assert_eq!(store.size(&digest).await, Some(11));
    drop(scratch);
}

#[tokio::test]
async fn an_open_range_runs_to_the_end() {
    let (scratch, store, digest) = store("open");
    store.put(&digest, ELEVEN).await.unwrap();

    let range = ByteRange::parse("bytes=0-").unwrap();
    let bytes = store.read(&digest, Some(range)).await.unwrap();
    assert_eq!(bytes, ELEVEN);
    assert_eq!(bytes.len(), 11);
    drop(scratch);
}

#[tokio::test]
async fn a_suffix_range_is_the_last_n_bytes() {
    let (scratch, store, digest) = store("suffix");
    store.put(&digest, ELEVEN).await.unwrap();

    let range = ByteRange::parse("bytes=-3").unwrap();
    let bytes = store.read(&digest, Some(range)).await.unwrap();
    assert_eq!(bytes, b"rld");
    assert_eq!(bytes.len(), 3);
    drop(scratch);
}

#[tokio::test]
async fn a_range_past_the_end_is_unsatisfiable() {
    let (scratch, store, digest) = store("unsatisfiable");
    store.put(&digest, ELEVEN).await.unwrap();

    let range = ByteRange::parse("bytes=999-").unwrap();
    match store.read(&digest, Some(range)).await {
        Err(BlobError::Range(nodus_storage::RangeError::Unsatisfiable)) => {}
        other => panic!("expected Unsatisfiable, got {other:?}"),
    }
    drop(scratch);
}

#[tokio::test]
async fn a_range_that_does_not_parse_is_malformed() {
    let (scratch, store, digest) = store("malformed");
    store.put(&digest, ELEVEN).await.unwrap();

    let error = ByteRange::parse("bytes=x").unwrap_err();
    assert_eq!(error, nodus_storage::RangeError::Malformed);
    assert_eq!(
        ByteRange::parse("bytes=9-5").unwrap_err(),
        nodus_storage::RangeError::Unsatisfiable
    );
    // Asking to read with a malformed range cannot even be built, so no read happens.
    assert!(store.has(&digest).await);
    drop(scratch);
}

#[tokio::test]
async fn a_put_of_the_wrong_digest_is_rejected_and_leaves_no_file() {
    let (scratch, store, _) = store("mismatch");
    let wrong = digest_of(b"something else");
    match store.put(&wrong, ELEVEN).await {
        Err(BlobError::DigestMismatch { expected, actual }) => {
            assert_eq!(expected, wrong);
            assert_eq!(actual, digest_of(ELEVEN));
        }
        other => panic!("expected DigestMismatch, got {other:?}"),
    }
    assert!(!store.has(&wrong).await);
    assert!(!store.has(&digest_of(ELEVEN)).await);
    let entries: Vec<_> = std::fs::read_dir(&scratch.root)
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert!(entries.is_empty(), "a rejected put left {entries:?} behind");
    drop(scratch);
}

#[tokio::test]
async fn deleting_twice_is_fine_and_removes_the_bytes() {
    let (scratch, store, digest) = store("delete");
    store.put(&digest, ELEVEN).await.unwrap();
    assert!(store.has(&digest).await);

    store.delete(&digest).await.unwrap();
    assert!(!store.has(&digest).await);
    // The second delete is a no-op rather than an error: the caller asked for the bytes
    // to be gone, and they are.
    store.delete(&digest).await.unwrap();
    assert_eq!(store.size(&digest).await, None);
    match store.read(&digest, None).await {
        Err(BlobError::NotFound(_)) => {}
        other => panic!("expected NotFound, got {other:?}"),
    }
    drop(scratch);
}

#[tokio::test]
async fn a_put_of_bytes_already_stored_reports_existed() {
    let (scratch, store, digest) = store("existed");
    assert_eq!(store.put(&digest, ELEVEN).await.unwrap(), Put::Created);
    assert_eq!(store.put(&digest, ELEVEN).await.unwrap(), Put::Existed);
    assert_eq!(store.read(&digest, None).await.unwrap(), ELEVEN);
    drop(scratch);
}

#[tokio::test]
async fn a_digest_that_is_not_a_digest_never_reaches_the_filesystem() {
    let (scratch, store, _) = store("traversal");
    assert!(!store.has("../escape").await);
    assert_eq!(store.size("../escape").await, None);
    assert!(matches!(
        store.read("../escape", None).await,
        Err(BlobError::NotFound(_))
    ));
    // Deleting something that cannot exist is already done, not an error.
    store.delete("../escape").await.unwrap();
    assert_eq!(std::fs::read_dir(&scratch.root).unwrap().count(), 0);
    drop(scratch);
}
