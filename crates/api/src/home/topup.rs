//! Filling a cached home page that the sorted set cannot complete.
//!
//! The set is a copy of the newest materialised entries, not the timeline: a set built
//! after history existed, or one that missed a fan-out, holds fewer ids than the account
//! has entries in `timeline_entry`. A short set must narrow the page, never define it, so
//! the read merges the database page for the same cursors into what the set answered.

use std::collections::HashSet;

use nodus_server_core::pagination::{PageOrder, PageSize};
use nodus_server_store::statuses::{StatusPage, StatusRow};

/// Merges `cached` (already in the set's order, already hydrated) with the database page
/// read under the same cursors, deduplicating by id.
///
/// `cached` keeps the order its scores gave it while it is the whole page, which is the
/// contract `home_timeline.rs` pins: a scripted cache may order ids differently from their
/// ULID timestamps. Once rows join from the database there are two sources, so the union
/// is ordered by id — the same order `statuses::finish` would give an uncached page.
pub(crate) fn merge(
    mut cached: Vec<StatusRow>,
    sql: StatusPage,
    size: PageSize,
    order: PageOrder,
) -> StatusPage {
    let limit = usize::try_from(size.get()).unwrap_or(usize::from(u16::MAX));
    let seen: HashSet<&str> = cached.iter().map(|row| row.id.as_str()).collect();
    let extras: Vec<StatusRow> = sql
        .items
        .into_iter()
        .filter(|row| !seen.contains(row.id.as_str()))
        .collect();
    if !extras.is_empty() {
        cached.extend(extras);
        cached.sort_by(|left, right| match order {
            PageOrder::NewestFirst => right.id.cmp(&left.id),
            PageOrder::OldestFirst => left.id.cmp(&right.id),
        });
    }
    let next_max_id = if cached.len() > limit {
        // One extra row is what says "there is more", exactly as `statuses::finish`.
        cached.truncate(limit);
        cached.last().map(|row| row.id.clone())
    } else if sql.next_max_id.is_some() {
        // A full union with no extra row: the database rows beyond this page are ones
        // the set already supplied. The cursor still has to be handed out.
        cached.last().map(|row| row.id.clone())
    } else {
        None
    };
    StatusPage {
        items: cached,
        next_max_id,
    }
}
