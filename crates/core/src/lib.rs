#![allow(clippy::doc_markdown)]

//! Ids, visibility and the arithmetic that pagination depends on.
//!
//! Nothing here performs I/O and nothing here is async, so every rule that decides
//! what a client receives is testable without a database.

pub mod client_metadata;
pub mod content;
pub mod id;
pub mod instance;
pub mod limits;
pub mod pagination;
pub mod visibility;

pub use client_metadata::ClientMetadataError;
pub use content::ContentFormat;
pub use id::Id;
pub use pagination::{PageOrder, PageParams, PageSize};
pub use visibility::Visibility;
