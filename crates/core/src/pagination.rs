//! Cursor pagination, as Mastodon's client API defines it.
//!
//! The rules that bite are ordering (`min_id` pages *forward*, everything else
//! backward) and the fact that `since_id` and `min_id` are not interchangeable: one
//! returns the newest N since a point, the other returns the oldest N after it.

use std::fmt::Write as _;

use crate::id::Id;
use crate::limits::{PAGE_DEFAULT, PAGE_MAX};

/// Which way a page is ordered on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageOrder {
    /// Newest first: `max_id`, `since_id`, or no cursor.
    NewestFirst,
    /// Oldest first: `min_id` only.
    OldestFirst,
}

/// A validated page size: never zero, never above the endpoint's maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageSize(u32);

impl PageSize {
    /// Clamps a requested size instead of rejecting it, which is what apps expect.
    #[must_use]
    pub fn clamp(requested: Option<u32>, max: u32) -> Self {
        Self(requested.unwrap_or(PAGE_DEFAULT).clamp(1, max))
    }

    /// The common case: the endpoint uses [`PAGE_MAX`].
    #[must_use]
    pub fn default_max(requested: Option<u32>) -> Self {
        Self::clamp(requested, PAGE_MAX)
    }

    #[must_use]
    pub fn get(self) -> u32 {
        self.0
    }

    #[must_use]
    pub fn as_i64(self) -> i64 {
        i64::from(self.0)
    }
}

/// The cursors a client sent, before they are turned into SQL.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PageParams {
    pub max_id: Option<Id>,
    pub since_id: Option<Id>,
    pub min_id: Option<Id>,
    pub limit: Option<u32>,
}

/// Two cursors that cannot both be honoured.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PageError {
    #[error("min_id and max_id cannot be combined")]
    MinAndMax,
    #[error("min_id and since_id cannot be combined")]
    MinAndSince,
}

impl PageParams {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `max_id`: strictly older than this id.
    #[must_use]
    pub fn with_max_id(mut self, id: Option<Id>) -> Self {
        self.max_id = id;
        self
    }

    /// `since_id`: the newest `limit` items newer than this id.
    #[must_use]
    pub fn with_since_id(mut self, id: Option<Id>) -> Self {
        self.since_id = id;
        self
    }

    /// `min_id`: the oldest `limit` items newer than this id.
    #[must_use]
    pub fn with_min_id(mut self, id: Option<Id>) -> Self {
        self.min_id = id;
        self
    }

    #[must_use]
    pub fn with_limit(mut self, limit: Option<u32>) -> Self {
        self.limit = limit;
        self
    }

    /// Mastodon rejects a page that asks two different directions at once.
    pub fn validate(self) -> Result<Self, PageError> {
        if self.min_id.is_some() && self.max_id.is_some() {
            return Err(PageError::MinAndMax);
        }
        if self.min_id.is_some() && self.since_id.is_some() {
            return Err(PageError::MinAndSince);
        }
        Ok(self)
    }

    /// The order rows must be returned in.
    #[must_use]
    pub fn order(self) -> PageOrder {
        if self.min_id.is_some() {
            PageOrder::OldestFirst
        } else {
            PageOrder::NewestFirst
        }
    }

    /// The exclusive bound to filter on, and whether it is an upper bound.
    ///
    /// `since_id` and `max_id` are both upper bounds; the difference is only how many
    /// rows the limit is applied to (from the top vs. the newest `limit`).
    #[must_use]
    pub fn bound(self) -> Option<(Id, bool)> {
        if let Some(id) = self.max_id {
            return Some((id, true));
        }
        if let Some(id) = self.since_id {
            return Some((id, true));
        }
        self.min_id.map(|id| (id, false))
    }

    /// The `Link: <…>; rel="next"` a client uses to continue, or `None` on the last
    /// page.
    ///
    /// `path` is the request path and unchanged query, e.g. `/api/v1/timelines/home`.
    #[must_use]
    pub fn next_link(self, path: &str, next: Option<Id>, size: PageSize) -> Option<String> {
        let next = next?;
        let mut url = String::with_capacity(path.len() + 48);
        let _ = write!(url, "{path}?max_id={next}&limit={}", size.get());
        Some(format!("<{url}>; rel=\"next\""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_requested_size_is_clamped_not_rejected() {
        assert_eq!(PageSize::default_max(Some(0)).get(), 1);
        assert_eq!(PageSize::default_max(Some(1_000)).get(), PAGE_MAX);
        assert_eq!(PageSize::default_max(None).get(), PAGE_DEFAULT);
        assert_eq!(PageSize::default_max(Some(15)).get(), 15);
    }

    #[test]
    fn min_id_turns_the_page_around() {
        let params = PageParams::new().with_min_id(Some(Id::new()));
        assert_eq!(params.order(), PageOrder::OldestFirst);
        let params = PageParams::new().with_max_id(Some(Id::new()));
        assert_eq!(params.order(), PageOrder::NewestFirst);
        assert_eq!(PageParams::new().order(), PageOrder::NewestFirst);
    }

    #[test]
    fn opposite_cursors_are_rejected() {
        let id = Id::new();
        assert_eq!(
            PageParams::new()
                .with_min_id(Some(id))
                .with_max_id(Some(id))
                .validate(),
            Err(PageError::MinAndMax)
        );
        assert!(PageParams::new()
            .with_min_id(Some(id))
            .with_since_id(Some(id))
            .validate()
            .is_err());
        assert!(PageParams::new().with_max_id(Some(id)).validate().is_ok());
    }

    #[test]
    fn the_next_link_is_absolute_path_plus_max_id() {
        let next = Id::new();
        let link = PageParams::new()
            .next_link("/api/v1/timelines/home", Some(next), PageSize::default_max(None))
            .expect("a page with a next id");
        assert_eq!(
            link,
            format!("</api/v1/timelines/home?max_id={next}&limit={PAGE_DEFAULT}>; rel=\"next\"")
        );
        // The last page must not advertise a link: a client that follows it would
        // loop on an empty page.
        assert!(PageParams::new()
            .next_link("/api/v1/timelines/home", None, PageSize::default_max(None))
            .is_none());
    }

    #[test]
    fn an_upper_bound_is_reported_as_such() {
        let id = Id::new();
        assert_eq!(PageParams::new().with_max_id(Some(id)).bound(), Some((id, true)));
        assert_eq!(PageParams::new().with_min_id(Some(id)).bound(), Some((id, false)));
        assert_eq!(PageParams::new().bound(), None);
    }
}
