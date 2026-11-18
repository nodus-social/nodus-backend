//! Outbound federation: turning what the reader did into activities other instances hear.
//!
//! Two rules hold this together. Nothing is sent from inside a handler, because a peer that
//! is down must not be able to fail a post; and every activity is written down first, so an
//! instance that was unreachable for an hour still learns about the post an hour later.
//! The worker below is the only thing that talks to a peer's inbox.
//!
//! A note on addresses: inbox URLs come from actor documents that were already fetched
//! through `remote::client_for`, which refuses private addresses unless the operator named
//! the host. They are not re-checked here, because a shared inbox is usually not the host
//! the actor lives on and a second guess would only reject valid peers.

use chrono::Utc;
use nodus_server_core::Id;
use reqwest::header::{HeaderValue, ACCEPT, CONTENT_TYPE};
use serde_json::{json, Value};

use nodus_server_sdk::activitypub::{Activity, ActivityKind};
use nodus_server_store::statuses::StatusRow;

use crate::error::ApiResult;
use crate::state::AppState;

/// How many deliveries one round of the worker takes.
const BATCH: i64 = 20;

/// How often the worker looks for work.
const TICK: std::time::Duration = std::time::Duration::from_secs(20);

/// The actor document URL of a local account, as peers fetch it.
pub fn actor_of(state: &AppState, username: &str, uri: Option<&str>) -> String {
    uri.map_or_else(
        || state.instance().url(&format!("/users/{username}")),
        std::borrow::ToOwned::to_owned,
    )
}

/// Serialises an activity and gives it an id when it needs one.
///
/// Mastodon peers deduplicate by id, so an activity without one is an activity they may act
/// on twice; the id is minted here rather than at the call site so no caller can forget.
fn identified(value: Value, actor: &str, kind: &str) -> Value {
    let mut value = value;
    if let Some(map) = value.as_object_mut() {
        if map.get("id").is_none_or(serde_json::Value::is_null) {
            map.insert(
                "id".to_owned(),
                Value::String(format!("{actor}#{kind}/{}", Id::new())),
            );
        }
    }
    value
}

/// A `Follow`, `Like` or `Announce`: one actor naming one object.
///
/// The id is derived from the relationship rather than minted, because a withdrawal has to
/// name the very activity being withdrawn: a peer matches the `Undo` by its object's id, and
/// a fresh id per attempt would leave the original standing on their side.
fn pointing(kind: ActivityKind, label: &str, actor: &str, object: &str) -> Value {
    let activity = Activity::new(kind, actor, object);
    let mut value = serde_json::to_value(&activity).unwrap_or_else(|_| json!({}));
    if let Some(map) = value.as_object_mut() {
        map.insert(
            "id".to_owned(),
            Value::String(format!("{actor}#{label}/{object}")),
        );
    }
    value
}

/// An `Undo` wrapping another activity, which is how a follow or a favourite is withdrawn.
fn undoing(actor: &str, inner: Value) -> Value {
    let activity = Activity::new(ActivityKind::Undo, actor, inner);
    let value = serde_json::to_value(&activity).unwrap_or_else(|_| json!({}));
    identified(value, actor, "undos")
}

/// Queues an activity for every inbox in `inboxes`.
///
/// Failures are logged rather than returned: the reader's action has already been stored,
/// and a queue that cannot be written is a server problem, not a reason to undo a post.
async fn enqueue(state: &AppState, account_id: &str, activity: Value, inboxes: Vec<String>) {
    if inboxes.is_empty() {
        return;
    }
    match nodus_server_store::delivery::enqueue(
        state.store().pool(),
        account_id,
        &activity,
        &inboxes,
    )
    .await
    {
        Ok(queued) => {
            tracing::debug!(inboxes = inboxes.len(), queued, "activity queued");
        }
        Err(error) => {
            tracing::warn!(%error, "could not queue an activity for delivery");
        }
    }
}

/// The followers of a local account who can be reached, and their inboxes.
async fn follower_inboxes(state: &AppState, account_id: &str) -> Vec<String> {
    nodus_server_store::delivery::followers_inboxes(state.store().pool(), account_id)
        .await
        .unwrap_or_default()
}

/// Announces a new post to the author's followers.
pub async fn deliver_create(
    state: &AppState,
    account_id: &str,
    row: &nodus_server_store::statuses::StatusRow,
) {
    // A direct or private post has no audience an ActivityPub peer would understand, and a
    // reply is delivered by the mention fan-out instead of the follower list.
    if !matches!(row.visibility.as_str(), "public" | "unlisted") {
        return;
    }
    let account = match nodus_server_store::accounts::by_id(state.store().pool(), account_id).await
    {
        Ok(Some(account)) => account,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!(%error, "could not read the author of a post");
            return;
        }
    };
    let activity = match crate::activitypub::status_activity(state, row, &account).await {
        Ok(activity) => activity,
        Err(error) => {
            tracing::warn!(error = %error.message(), "could not build a Create activity");
            return;
        }
    };
    let value = match serde_json::to_value(&activity) {
        Ok(value) => identified(
            value,
            &crate::activitypub::actor_url(state, &account),
            "activities",
        ),
        Err(error) => {
            tracing::warn!(%error, "could not serialise a Create activity");
            return;
        }
    };
    let inboxes = follower_inboxes(state, account_id).await;
    enqueue(state, account_id, value, inboxes).await;
}

/// Tells the followers that a post is gone.
pub async fn deliver_delete(
    state: &AppState,
    account_id: &str,
    row: &nodus_server_store::statuses::StatusRow,
) {
    if !matches!(row.visibility.as_str(), "public" | "unlisted") {
        return;
    }
    let Ok(Some(account)) =
        nodus_server_store::accounts::by_id(state.store().pool(), account_id).await
    else {
        return;
    };
    let actor = crate::activitypub::actor_url(state, &account);
    let object = crate::activitypub::status_url(state, row);
    let activity = Activity::new(
        ActivityKind::Delete,
        &actor,
        json!({
            "id": object,
            "type": "Tombstone",
        }),
    );
    let value = match serde_json::to_value(&activity) {
        Ok(value) => identified(value, &actor, "activities"),
        Err(error) => {
            tracing::warn!(%error, "could not serialise a Delete activity");
            return;
        }
    };
    let inboxes = follower_inboxes(state, account_id).await;
    enqueue(state, account_id, value, inboxes).await;
}

/// Tells an account that it was followed, or that the follow was withdrawn.
pub async fn deliver_follow(state: &AppState, account_id: &str, target_id: &str, following: bool) {
    let (Ok(Some(actor_row)), Ok(Some(target))) = (
        nodus_server_store::accounts::by_id(state.store().pool(), account_id).await,
        nodus_server_store::accounts::by_id(state.store().pool(), target_id).await,
    ) else {
        return;
    };
    let actor = crate::activitypub::actor_url(state, &actor_row);
    let object = crate::activitypub::actor_url(state, &target);
    let activity = if following {
        pointing(ActivityKind::Follow, "follows", &actor, &object)
    } else {
        undoing(
            &actor,
            pointing(ActivityKind::Follow, "follows", &actor, &object),
        )
    };
    if let Ok(Some(inbox)) =
        nodus_server_store::delivery::inbox_of(state.store().pool(), target_id).await
    {
        enqueue(state, account_id, activity, vec![inbox]).await;
    }
}

/// Answers a pending follow request.
pub async fn deliver_follow_response(
    state: &AppState,
    account_id: &str,
    requester_id: &str,
    accepted: bool,
    follow_id: Option<&str>,
) {
    let (Ok(Some(actor_row)), Ok(Some(requester))) = (
        nodus_server_store::accounts::by_id(state.store().pool(), account_id).await,
        nodus_server_store::accounts::by_id(state.store().pool(), requester_id).await,
    ) else {
        return;
    };
    let actor = crate::activitypub::actor_url(state, &actor_row);
    // The object of an Accept is the Follow that asked, not the follower: Mastodon matches
    // the answer to the request by that activity, and a bare actor URL resolves nothing.
    let follower = crate::activitypub::actor_url(state, &requester);
    let kind = if accepted {
        ActivityKind::Accept
    } else {
        ActivityKind::Reject
    };
    let value = follow_answer(kind, &actor, &follower, follow_id);
    if let Ok(Some(inbox)) =
        nodus_server_store::delivery::inbox_of(state.store().pool(), requester_id).await
    {
        enqueue(state, account_id, value, vec![inbox]).await;
    }
}

/// The Accept or Reject that answers a follow, carrying the request it answers.
fn follow_answer(
    kind: ActivityKind,
    actor: &str,
    follower: &str,
    follow_id: Option<&str>,
) -> Value {
    let object = follow_id.map_or_else(
        || json!({ "type": "Follow", "actor": follower, "object": actor }),
        |id| json!({ "id": id, "type": "Follow", "actor": follower, "object": actor }),
    );
    let activity = Activity::new(kind, actor, follower);
    let mut value = serde_json::to_value(&activity).unwrap_or_else(|_| json!({}));
    value["object"] = object;
    identified(value, actor, if kind == ActivityKind::Accept { "accepts" } else { "rejects" })
}

/// Tells the author of a post that it was favourited or boosted, or that it was not.
pub async fn deliver_reaction(
    state: &AppState,
    account_id: &str,
    status: &StatusRow,
    kind: ActivityKind,
    active: bool,
) {
    let (Ok(Some(actor_row)), Ok(Some(author))) = (
        nodus_server_store::accounts::by_id(state.store().pool(), account_id).await,
        nodus_server_store::accounts::by_id(state.store().pool(), &status.account_id).await,
    ) else {
        return;
    };
    // Only a remote author has an inbox to tell; a local one already has the row.
    if author.domain.is_none() {
        return;
    }
    let actor = crate::activitypub::actor_url(state, &actor_row);
    // The object of a Like or an Announce is the post, not its author: a remote server can
    // only attach a reaction it can resolve, and an actor URL resolves to nothing.
    let target = crate::activitypub::status_url(state, status);
    let label = if kind == ActivityKind::Like {
        "likes"
    } else {
        "announces"
    };
    let value = if active {
        pointing(kind, label, &actor, &target)
    } else {
        undoing(&actor, pointing(kind, label, &actor, &target))
    };
    if let Ok(Some(inbox)) =
        nodus_server_store::delivery::inbox_of(state.store().pool(), &author.id).await
    {
        enqueue(state, account_id, value, vec![inbox]).await;
    }
}

/// Sends one queued activity.
///
/// Returns `true` when there was work, so the worker can keep draining the queue without
/// waiting for the next tick.
pub async fn deliver_once(state: &AppState) -> ApiResult<bool> {
    let pool = state.store().pool();
    let due = nodus_server_store::delivery::due(pool, 1).await?;
    let Some(row) = due.into_iter().next() else {
        return Ok(false);
    };
    match post(state, &row).await {
        Ok(()) => {
            nodus_server_store::delivery::delivered(pool, &row.id).await?;
            tracing::info!(inbox = %row.inbox_url, "activity delivered");
        }
        Err(error) => {
            let attempts = row.attempts + 1;
            nodus_server_store::delivery::failed(pool, &row.id, attempts, &error).await?;
            tracing::warn!(inbox = %row.inbox_url, attempts, %error, "activity delivery failed");
        }
    }
    Ok(true)
}

/// Signs and posts an activity to the inbox it was queued for.
async fn post(
    state: &AppState,
    row: &nodus_server_store::delivery::DeliveryRow,
) -> Result<(), String> {
    let url = reqwest::Url::parse(&row.inbox_url).map_err(|error| error.to_string())?;
    let Some(host) = url.host_str().map(std::borrow::ToOwned::to_owned) else {
        return Err("the inbox has no host".to_owned());
    };
    let path = url.query().map_or_else(
        || url.path().to_owned(),
        |query| format!("{}?{query}", url.path()),
    );
    let body = serde_json::to_vec(&row.activity).map_err(|error| error.to_string())?;
    let (uri, pem) =
        nodus_server_store::delivery::signing_key(state.store().pool(), &row.account_id)
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "this account has no signing key".to_owned())?;
    let key_id = format!("{uri}#main-key");
    let signed =
        nodus_server_federation::sign("POST", &path, &host, Utc::now(), &body, &key_id, &pem)
            .map_err(|error| error.to_string())?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent(concat!("nodus/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| error.to_string())?;
    let mut request = client
        .post(url)
        .header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/activity+json"),
        )
        .header(
            ACCEPT,
            HeaderValue::from_static("application/activity+json"),
        );
    for (name, value) in signed.pairs() {
        // The header names are ours, and the values are base64 or an HTTP date, so a bad
        // value would mean a bug in signing rather than anything a peer could send us.
        let header = HeaderValue::from_str(value).map_err(|error| error.to_string())?;
        request = request.header(name, header);
    }
    let response = request
        .body(body)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let detail: String = response
        .text()
        .await
        .unwrap_or_default()
        .chars()
        .take(200)
        .collect();
    Err(format!("inbox answered {status}: {detail}"))
}

/// Drains the queue until there is nothing due, at most `BATCH` activities per round.
pub async fn drain(state: &AppState) -> usize {
    let mut sent = 0;
    for _ in 0..BATCH {
        match deliver_once(state).await {
            Ok(true) => sent += 1,
            Ok(false) => break,
            Err(error) => {
                tracing::warn!(error = %error.message(), "the delivery queue could not be read");
                break;
            }
        }
    }
    sent
}

/// The worker: looks for owed activities every `TICK`.
pub async fn run(state: AppState) {
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let sent = drain(&state).await;
        if sent > 0 {
            tracing::debug!(sent, "delivery round finished");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{follow_answer, pointing, undoing, ActivityKind};

    #[test]
    fn a_withdrawal_names_the_activity_it_withdrew() {
        let actor = "https://social.test/users/ada";
        let object = "https://mastodon.test/users/eve";
        let follow = pointing(ActivityKind::Follow, "follows", actor, object);
        let undo = undoing(actor, follow.clone());
        assert_eq!(undo["type"], "Undo");
        assert_eq!(undo["object"]["id"], follow["id"]);
        assert_eq!(follow["id"], format!("{actor}#follows/{object}"));
    }

    #[test]
    fn two_relationships_get_their_own_ids() {
        let actor = "https://social.test/users/ada";
        let eve = pointing(ActivityKind::Follow, "follows", actor, "https://a.test/users/eve");
        let bob = pointing(ActivityKind::Follow, "follows", actor, "https://b.test/users/bob");
        assert_ne!(eve["id"], bob["id"]);
    }

    #[test]
    fn an_accept_answers_the_follow_it_received() {
        let value = follow_answer(
            ActivityKind::Accept,
            "https://social.test/users/ada",
            "https://mastodon.test/users/eve",
            Some("https://mastodon.test/users/eve#follows/7"),
        );
        assert_eq!(value["type"], "Accept");
        assert_eq!(value["actor"], "https://social.test/users/ada");
        assert_eq!(value["object"]["type"], "Follow");
        assert_eq!(
            value["object"]["id"],
            "https://mastodon.test/users/eve#follows/7"
        );
        assert_eq!(value["object"]["actor"], "https://mastodon.test/users/eve");
        assert_eq!(value["object"]["object"], "https://social.test/users/ada");
    }

    #[test]
    fn an_accept_without_an_id_still_names_the_follow() {
        let value = follow_answer(
            ActivityKind::Accept,
            "https://social.test/users/ada",
            "https://mastodon.test/users/eve",
            None,
        );
        assert_eq!(value["object"]["type"], "Follow");
        assert!(value["object"].get("id").is_none());
    }

    #[test]
    fn a_reject_says_so() {
        let value = follow_answer(
            ActivityKind::Reject,
            "https://social.test/users/ada",
            "https://mastodon.test/users/eve",
            None,
        );
        assert_eq!(value["type"], "Reject");
    }
}
