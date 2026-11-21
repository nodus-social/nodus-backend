//! Dialect ids and the page's decoration reads, batched at the edge.
//!
//! A Misskey note names its author and itself with `external_id` rows. Reading them one
//! row at a time made a page's cost grow with its length, so the page read asks for the
//! whole page's status and account ids in one statement. A single-note endpoint still
//! calls [`dialect_id`] directly; it has no page to batch.

use std::hash::{DefaultHasher, Hash, Hasher};

use chrono::{DateTime, Utc};

use nodus_server_sdk::misskey::api::User;
use nodus_server_sdk::misskey::Aid;
use nodus_server_store::accounts::AccountRow;
use nodus_server_store::external_ids;
use nodus_server_store::media::MediaRow;
use nodus_server_store::statuses::ReactionCount;
use nodus_server_store::{BatchOutcome, ExternalIds, RowMap, StatusDecorations};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Reaction chips, attachments, decorations and dialect ids for a whole page of notes.
pub(crate) struct PageReads {
    pub(crate) reactions: RowMap<Vec<ReactionCount>>,
    pub(crate) media: RowMap<Vec<MediaRow>>,
    pub(crate) decorations: RowMap<StatusDecorations>,
    pub(crate) external: ExternalIds,
}

impl PageReads {
    pub(crate) fn from_outcome(outcome: BatchOutcome) -> Self {
        Self {
            reactions: outcome.reactions.unwrap_or_default(),
            media: outcome.media_by_status,
            decorations: outcome.decorations,
            external: outcome.external_ids,
        }
    }
}

/// Reads a page's reactions, attachments, decorations and dialect ids in one batch.
///
/// The reaction op is optional by design: a page that cannot read reaction counts still
/// renders, with no chips, rather than failing as a whole.
pub(crate) async fn page_reads(
    state: &AppState,
    ids: &[String],
    author_ids: &[String],
) -> ApiResult<PageReads> {
    let outcome = state
        .store()
        .batch()
        .media_by_status(ids)
        .reactions(ids)
        .decorations(ids)
        .external_ids(ids, author_ids)
        .run()
        .await?;
    Ok(PageReads::from_outcome(outcome))
}

/// The dialect id for a row: the page's parked read when it has one, otherwise the
/// create-if-missing path.
///
/// Absence from the parked read is not a cache miss — the page asked for this id — so it
/// means the mapping has never been allocated, which is a write.
pub(crate) async fn page_dialect_id(
    state: &AppState,
    kind: &str,
    local_id: &str,
    created_at: DateTime<Utc>,
    reads: Option<&PageReads>,
) -> ApiResult<String> {
    if let Some(existing) = reads.and_then(|reads| reads.external.get(kind, local_id)) {
        return Ok(existing.clone());
    }
    dialect_id(state, kind, local_id, created_at).await
}

async fn dialect_id(
    state: &AppState,
    kind: &str,
    local_id: &str,
    created_at: DateTime<Utc>,
) -> ApiResult<String> {
    let pool = state.store().pool();
    if let Some(existing) = external_ids::by_local(pool, kind, local_id).await? {
        return Ok(existing);
    }
    let timestamp_ms = u64::try_from(created_at.timestamp_millis()).unwrap_or_default();
    for attempt in 0..8_u16 {
        let mut hasher = DefaultHasher::new();
        local_id.hash(&mut hasher);
        attempt.hash(&mut hasher);
        let candidate = Aid::from_parts(
            timestamp_ms,
            u16::try_from(hasher.finish() % 1000).unwrap_or_default(),
        )
        .as_str();
        if let Some(id) = external_ids::get_or_create(pool, kind, local_id, &candidate).await? {
            return Ok(id);
        }
    }
    Err(ApiError::new(
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "Could not allocate an external id",
    ))
}

/// A single-row user payload, for endpoints that do not read a page.
pub(crate) async fn user_for(state: &AppState, account: &AccountRow) -> ApiResult<User> {
    user_for_with(state, account, None).await
}

/// A user payload whose dialect id may already be on the page.
pub(crate) async fn user_for_with(
    state: &AppState,
    account: &AccountRow,
    reads: Option<&PageReads>,
) -> ApiResult<User> {
    let id = page_dialect_id(state, "account", &account.id, account.created_at, reads).await?;
    Ok(User {
        id,
        username: account.username.clone(),
        name: Some(account.display_name.clone()).filter(|name| !name.is_empty()),
        host: account.domain.clone(),
        description: Some(account.note.clone()).filter(|note| !note.is_empty()),
        avatar_url: account.avatar_ref.clone(),
        banner_url: account.header_ref.clone(),
        is_bot: account.bot,
        is_cat: false,
        is_admin: false,
        is_moderator: false,
        is_locked: account.locked,
        is_suspended: account.suspended_at.is_some(),
        followers_count: u64::try_from(account.followers_count).unwrap_or_default(),
        following_count: u64::try_from(account.following_count).unwrap_or_default(),
        notes_count: u64::try_from(account.statuses_count).unwrap_or_default(),
        created_at: Some(account.created_at.to_rfc3339()),
        uri: account.uri.clone(),
        moved_to_uri: account.moved_to.clone(),
        also_known_as: account.also_known_as.clone(),
    })
}
