//! The outbound federation queue: what we still owe other instances.
//!
//! Delivering an activity is two steps rather than one. The activity is first written down
//! — by the request that caused it, inside the same transaction where that is possible —
//! and only then sent by the worker. That ordering is the point: a peer that is down, slow
//! or hostile must not be able to make a post fail, and an activity that failed to send
//! must still be sendable an hour later.

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use sqlx::PgPool;
use ulid::Ulid;

/// How many times a delivery is retried before it is left for an operator to look at.
pub const MAX_ATTEMPTS: i32 = 8;

/// One queued activity, as the worker needs it.
#[derive(Debug, Clone)]
pub struct DeliveryRow {
    pub id: String,
    pub account_id: String,
    pub inbox_url: String,
    pub activity: Value,
    pub attempts: i32,
}

/// How long to wait after a failed attempt.
///
/// Doubling from thirty seconds and capped at an hour: a peer that is down for a minute is
/// retried promptly, and a peer that is down for a day is not hammered.
fn backoff(attempts: i32) -> Duration {
    let exponent = u32::try_from(attempts.clamp(0, 7)).unwrap_or(0);
    Duration::seconds(30 * 2_i64.pow(exponent)).min(Duration::hours(1))
}

/// Writes an activity down for every inbox it goes to.
///
/// Returns how many deliveries were actually queued, so a caller can tell "nobody follows
/// this account" (zero inboxes) from "the queue rejected it" (an error). Inboxes on a host
/// whose actor blocked this instance are dropped here rather than at send time, so the
/// worker never has to know about blocks.
pub async fn enqueue(
    pool: &PgPool,
    account_id: &str,
    activity: &Value,
    inboxes: &[String],
) -> Result<u64, sqlx::Error> {
    enqueue_with(pool, account_id, activity, inboxes, false).await
}

/// Writes an activity down even for an inbox whose actor is suspended.
///
/// The `Block` and `Undo(Block)` that apply or lift a suspension are the one thing that
/// must still reach the peer, so the suspension filter is skipped for them; a host that
/// blocked this instance is still not written to.
pub async fn enqueue_ignoring_suspension(
    pool: &PgPool,
    account_id: &str,
    activity: &Value,
    inboxes: &[String],
) -> Result<u64, sqlx::Error> {
    enqueue_with(pool, account_id, activity, inboxes, true).await
}

async fn enqueue_with(
    pool: &PgPool,
    account_id: &str,
    activity: &Value,
    inboxes: &[String],
    keep_suspended: bool,
) -> Result<u64, sqlx::Error> {
    let activity_id = activity
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if activity_id.is_empty() || inboxes.is_empty() {
        return Ok(0);
    }
    let blocked = crate::blocks::blocked_hosts(pool).await?;
    let mut inboxes = allowed_inboxes(inboxes, &blocked);
    if !keep_suspended {
        let suspended = crate::remote_moderation::suspended_inboxes(pool).await?;
        inboxes.retain(|inbox| !suspended.contains(inbox));
    }
    if inboxes.is_empty() {
        return Ok(0);
    }
    let ids: Vec<String> = inboxes.iter().map(|_| Ulid::new().to_string()).collect();
    let queued = sqlx::query(
        "INSERT INTO federation_delivery (id, account_id, activity_id, inbox_url, activity) \
         SELECT queued.id, $2, $3, queued.inbox, $4 \
           FROM UNNEST($1::text[], $5::text[]) AS queued (id, inbox) \
         ON CONFLICT (inbox_url, activity_id) DO NOTHING",
    )
    .bind(&ids)
    .bind(account_id)
    .bind(&activity_id)
    .bind(activity)
    .bind(inboxes)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(queued)
}

/// The deliveries that are due, oldest first.
pub async fn due(pool: &PgPool, limit: i64) -> Result<Vec<DeliveryRow>, sqlx::Error> {
    let rows: Vec<(String, String, String, Value, i32)> = sqlx::query_as(
        "SELECT id, account_id, inbox_url, activity, attempts FROM federation_delivery \
          WHERE delivered_at IS NULL AND next_attempt_at <= now() \
          ORDER BY next_attempt_at, created_at LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, account_id, inbox_url, activity, attempts)| DeliveryRow {
                id,
                account_id,
                inbox_url,
                activity,
                attempts,
            },
        )
        .collect())
}

/// Marks a delivery as done.
pub async fn delivered(pool: &PgPool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE federation_delivery SET delivered_at = now() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Records a failed attempt and schedules the next one.
///
/// A delivery that has used up its attempts is closed rather than kept forever: the row
/// stays, with its error, so an operator can see what was never sent.
pub async fn failed(
    pool: &PgPool,
    id: &str,
    attempts: i32,
    error: &str,
) -> Result<(), sqlx::Error> {
    let next = Utc::now() + backoff(attempts);
    let trimmed: String = error.chars().take(500).collect();
    sqlx::query(
        "UPDATE federation_delivery \
            SET attempts = $2, last_error = $3, \
                delivered_at = CASE WHEN $2 >= $4 THEN now() ELSE delivered_at END, \
                next_attempt_at = $5 \
          WHERE id = $1",
    )
    .bind(id)
    .bind(attempts)
    .bind(trimmed)
    .bind(MAX_ATTEMPTS)
    .bind(next)
    .execute(pool)
    .await?;
    Ok(())
}

/// Every inbox a post from `account_id` should reach: the accepted followers' inboxes,
/// with a shared inbox counted once.
pub async fn followers_inboxes(
    pool: &PgPool,
    account_id: &str,
) -> Result<Vec<String>, sqlx::Error> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT COALESCE(follower.shared_inbox_url, follower.inbox_url) AS inbox \
           FROM follow f \
           JOIN account follower ON follower.id = f.account_id \
          WHERE f.target_account_id = $1 \
            AND f.state = 'accepted' \
            AND follower.domain IS NOT NULL \
            AND COALESCE(follower.shared_inbox_url, follower.inbox_url) IS NOT NULL",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(inbox,)| inbox).collect())
}

/// The inbox one remote account reads: its shared inbox when it publishes one.
pub async fn inbox_of(pool: &PgPool, account_id: &str) -> Result<Option<String>, sqlx::Error> {
    let inbox: Option<Option<String>> = sqlx::query_scalar(
        "SELECT COALESCE(shared_inbox_url, inbox_url) FROM account WHERE id = $1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;
    Ok(inbox.flatten())
}

/// The key an account signs its activities with: its actor id and its private key.
///
/// The key id is derived from the stored actor id, so it names the same document peers can
/// fetch — a signature that points at a different URL is a signature they cannot check.
pub async fn signing_key(
    pool: &PgPool,
    account_id: &str,
) -> Result<Option<(String, String)>, sqlx::Error> {
    let row: Option<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT username, uri, private_key_pem FROM account \
          WHERE id = $1 AND private_key_pem IS NOT NULL",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(username, uri, pem)| (uri.unwrap_or(username), pem)))
}

/// Drops a queued delivery outright, for an activity that was withdrawn.
pub async fn withdraw(pool: &PgPool, activity_id: &str) -> Result<u64, sqlx::Error> {
    let removed = sqlx::query(
        "DELETE FROM federation_delivery WHERE activity_id = $1 AND delivered_at IS NULL",
    )
    .bind(activity_id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(removed)
}

/// The inboxes that do not belong to a host that blocked this instance.
fn allowed_inboxes(inboxes: &[String], blocked_hosts: &[String]) -> Vec<String> {
    inboxes
        .iter()
        .filter(|inbox| match crate::blocks::host_of(inbox) {
            Some(host) => !blocked_hosts.contains(&host),
            None => true,
        })
        .cloned()
        .collect()
}

/// The queue as an operator sees it: what is still owed, and when it is next tried.
#[derive(Debug, Clone)]
pub struct PendingDelivery {
    pub id: String,
    pub inbox_url: String,
    pub attempts: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub last_error: Option<String>,
}

/// One row as the query returns it, before it is given names.
type PendingRow = (String, String, i32, DateTime<Utc>, Option<String>);

/// The deliveries still owed, for the admin view.
pub async fn pending(pool: &PgPool, limit: i64) -> Result<Vec<PendingDelivery>, sqlx::Error> {
    let rows: Vec<PendingRow> = sqlx::query_as(
        "SELECT id, inbox_url, attempts, next_attempt_at, last_error \
           FROM federation_delivery WHERE delivered_at IS NULL \
          ORDER BY next_attempt_at, created_at LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, inbox_url, attempts, next_attempt_at, last_error)| PendingDelivery {
                id,
                inbox_url,
                attempts,
                next_attempt_at,
                last_error,
            },
        )
        .collect())
}

#[cfg(test)]
mod tests {
    #[test]
    fn inboxes_of_a_blocked_host_are_dropped_before_queueing() {
        let inboxes = vec![
            "https://open.test/inbox".to_owned(),
            "https://blocked.test/users/a/inbox".to_owned(),
            "https://blocked.test/inbox".to_owned(),
        ];
        let allowed = super::allowed_inboxes(&inboxes, &["blocked.test".to_owned()]);
        assert_eq!(allowed, vec!["https://open.test/inbox"]);
    }

    #[test]
    fn an_inbox_without_a_readable_host_is_left_for_the_worker() {
        let inboxes = vec!["not a url".to_owned()];
        assert_eq!(
            super::allowed_inboxes(&inboxes, &["blocked.test".to_owned()]),
            inboxes
        );
    }
}
