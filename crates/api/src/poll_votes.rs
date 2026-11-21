//! Poll votes from either door.
//!
//! The HTTP vote handler and a federated `Create` must write the same row and send the
//! same `Update`; otherwise a tally would depend on how a reader voted. Both paths meet
//! here so the validation, the store call and the announcement stay one implementation.
//!
//! Federation has no `choices[]` body. A peer votes by replying to one option of the
//! `Question` we served, naming it as `{status_uri}#option-{index}`. That reply is
//! consumed here and never stored as a status: it has no content a reader came for, and
//! storing it would show the same act twice in the thread (once as a reply, once as a
//! tally). A reply that does not name one of our options is an ordinary note and is left
//! untouched.

use chrono::Utc;

use nodus_server_store::accounts::AccountRow;
use nodus_server_store::polls::{self, PollRow};
use nodus_server_store::social;
use nodus_server_store::statuses::{self, StatusRow};

use crate::error::ApiResult;
use crate::state::AppState;

/// Why a reply that named an option did not become a vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VoteRefusal {
    /// The poll was federated in; only the instance that owns it counts its votes.
    RemotePoll,
    /// The option was named after `endTime`.
    PollEnded,
    /// The fragment named an option the poll does not have.
    UnknownOption,
    /// The status has no poll, so the fragment cannot be a vote.
    NoPoll,
}

impl VoteRefusal {
    /// A stable phrase for logs and for telling the refusals apart.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::RemotePoll => "the poll belongs to another instance",
            Self::PollEnded => "the poll has ended",
            Self::UnknownOption => "the option index does not exist",
            Self::NoPoll => "the status has no poll",
        }
    }
}

/// What happened to a reply that might have been a vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VoteReply {
    /// It did not name an option on a status we know; ingest it as an ordinary note.
    NotAVote,
    /// It named an option. `counted` is false when the same actor had already chosen it.
    Counted { counted: bool },
    /// It named an option but was refused; it is still not stored as a reply.
    Refused(VoteRefusal),
}

/// Counts an HTTP vote and announces it.
pub(crate) async fn record_choices(
    state: &AppState,
    poll: &PollRow,
    account_id: &str,
    choices: &[i32],
) -> ApiResult<bool> {
    let counted = polls::vote(state.store().pool(), &poll.id, account_id, choices).await?;
    if counted {
        announce(state, poll, account_id).await?;
    }
    Ok(counted)
}

/// Reads a reply and, when it names one of our poll's options, counts it.
///
/// The index is the option's position in the `oneOf`/`anyOf` array we served, so it stays
/// valid without a lookup table. Every reply shaped like an option id is consumed even
/// when it is refused; only a status we have never stored falls through as an ordinary
/// reply, because there is nothing here to count it against.
pub(crate) async fn consume_reply(
    state: &AppState,
    voter: &AccountRow,
    in_reply_to: &str,
) -> ApiResult<VoteReply> {
    let Some((status_uri, index)) = option_target(in_reply_to) else {
        return Ok(VoteReply::NotAVote);
    };
    let Some(status) = status_for_uri(state, status_uri).await? else {
        return Ok(VoteReply::NotAVote);
    };
    let Some(poll) = polls::by_status(state.store().pool(), &status.id).await? else {
        return Ok(VoteReply::Refused(VoteRefusal::NoPoll));
    };
    if !poll.local {
        return Ok(VoteReply::Refused(VoteRefusal::RemotePoll));
    }
    if poll.expires_at.is_some_and(|at| at <= Utc::now()) {
        return Ok(VoteReply::Refused(VoteRefusal::PollEnded));
    }
    if index >= poll.options.0.len() {
        return Ok(VoteReply::Refused(VoteRefusal::UnknownOption));
    }
    let Ok(index) = i32::try_from(index) else {
        return Ok(VoteReply::Refused(VoteRefusal::UnknownOption));
    };
    let counted =
        polls::vote_option(state.store().pool(), &poll.id, &voter.id, index).await?;
    if counted {
        announce(state, &poll, &voter.id).await?;
    }
    Ok(VoteReply::Counted { counted })
}

/// Splits `{status_uri}#option-{index}` into the base URI and the option index.
fn option_target(in_reply_to: &str) -> Option<(&str, usize)> {
    let (status_uri, fragment) = in_reply_to.rsplit_once('#')?;
    if status_uri.is_empty() {
        return None;
    }
    let index = fragment.strip_prefix("option-")?.parse().ok()?;
    Some((status_uri, index))
}

/// Finds the status an option id points at, accepting both a stored URI and the canonical
/// local status URL of a row whose `uri` is null.
async fn status_for_uri(state: &AppState, uri: &str) -> ApiResult<Option<StatusRow>> {
    let pool = state.store().pool();
    if let Some(row) = statuses::by_uri(pool, uri).await? {
        return Ok(Some(row));
    }
    let Some(id) = local_status_id(state, uri) else {
        return Ok(None);
    };
    let Some(row) = statuses::by_id(pool, id).await? else {
        return Ok(None);
    };
    // A local status with a non-null `uri` is served under that URI, not the generated
    // one; both spellings must resolve to the same row or the option id could be forged.
    Ok((row.local && crate::activitypub::status_url(state, &row) == uri).then_some(row))
}

/// The id part of our own `/statuses/{id}` URL, if `uri` has that shape.
fn local_status_id<'a>(state: &AppState, uri: &'a str) -> Option<&'a str> {
    uri.strip_prefix(&state.instance().url("/statuses/"))
        .filter(|id| !id.is_empty() && !id.contains('/'))
}

/// Tells the poll's author and the peers about a tally that changed.
async fn announce(state: &AppState, poll: &PollRow, voter_id: &str) -> ApiResult<()> {
    let Some(status) = statuses::by_id(state.store().pool(), &poll.status_id).await? else {
        return Ok(());
    };
    // The line is only useful to an author who can still open the poll; a deleted or
    // moderated-away status has nobody to show it to.
    let author_can_see = crate::statuses::can_view_for_viewer(
        state,
        Some(status.account_id.as_str()),
        &status,
    )
    .await?;
    if author_can_see {
        // A vote on your own poll is a notification like a favourite; the store
        // aggregates every voter into one line naming the latest one.
        social::notify(
            state.store().pool(),
            &status.account_id,
            "poll",
            voter_id,
            Some(&status.id),
        )
        .await?;
    }
    // The peer's copy of the poll has votes now; an `Update` carries the tally through
    // the same outbox that delivered the original `Question`.
    crate::outbox::deliver_update(state, &status.account_id, &status).await;
    Ok(())
}
