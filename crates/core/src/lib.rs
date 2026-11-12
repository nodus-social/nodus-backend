#![allow(clippy::doc_markdown)]

//! Ids, visibility and the arithmetic that pagination depends on.
//!
//! Nothing here performs I/O and nothing here is async, so every rule that decides
//! what a client receives is testable without a database.

pub mod content;
pub mod id;
pub mod limits;
pub mod pagination;
pub mod visibility;

pub use content::ContentFormat;
pub use id::Id;
pub use pagination::{PageParams, PageSize};
pub use visibility::Visibility;
