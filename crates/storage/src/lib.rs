//! Where the bytes live, and who is allowed to ask for them.
//!
//! Two pieces, deliberately independent of the API surface:
//!
//! - [`blob::BlobStore`] — content-addressed storage keyed by the lowercase hex
//!   SHA-256 of the bytes. The bytes are addressed by what they *are*, so a digest
//!   either names exactly one byte string or nothing at all.
//! - [`token::Capability`] — a short-lived, signed permission to read one digest in one
//!   variant. Nothing else can be granted with it, so a leaked URL is worth only the
//!   one rendition it was minted for, until it expires.
//!
//! The object store and the token signer share the digest as their only join: the store
//! never checks a token and the token never reads a disk. That is what lets a CDN, a
//! peer node or a future S3 backend stand in for [`local::LocalDiskBlobStore`] without
//! touching the signing code.

pub mod blob;
pub mod local;
pub mod token;

pub use blob::{BlobError, BlobStore, ByteRange, Put, RangeError};
pub use local::LocalDiskBlobStore;
pub use token::{Capability, Claims, TokenError};
