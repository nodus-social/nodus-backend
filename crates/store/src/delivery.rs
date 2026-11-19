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

/// First retry waits half a minute.
///
/// Short enough that a peer restarting does not cost us the activity, long enough that a
/// peer that is briefly overloaded is not hit again before it can recover.
pub const RETRY_BASE_SECS: i64 = 30;

/// The wait stops doubling after an hour.
///
/// A peer that has been down for a day is retried roughly hourly rather than every few
/// minutes: the queue keeps the obligation without becoming a flood the peer has to survive
/// before it can accept anything.
pub const RETRY_CAP_SECS: i64 = 3_600;

/// One queued activity, as the worker needs it.
#[derive(Debug, Clone)]
pub struct DeliveryRow {
    pub id: String,
    pub account_id: String,
    pub inbox_url: String,
    pub activity: Value,
    pub attempts: i32,
}

/// How long to wait after a failed attempt: thirty seconds, doubling, capped at an hour.
fn backoff(attempts: i32) -> Duration {
    let exponent = u32::try_from(attempts.clamp(0, 7)).unwrap_or(0);
    Duration::seconds(RETRY_BASE_SECS * 2_i64.pow(exponent)).min(Duration::seconds(RETRY_CAP_SECS))
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
    // A pause is not a block: `instance_block` is permanent and carries a severity, while
    // a pause expires and is never announced to the peer. Both stop new deliveries here.
    let paused = crate::pauses::active_domains(pool).await?;
    let mut inboxes = allowed_inboxes(inboxes, &blocked, &paused);
    if !keep_suspended {
        let suspended = crate::remote_moderation::suspended_inboxes(pool).await?;
        inboxes.retain(|inbox| !suspended.contains(inbox));
    }
    if inboxes.is_empty() {
        return Ok(0);
    }
    let ids: Vec<String> = inboxes.iter().map(|_| Ulid::new().to_string()).collect();
    // The host is written down here, not derived on every admin query: the filter is over
    // the same parser blocks uses, so "blocked by host" and "deliveries to host" agree.
    let hosts: Vec<String> = inboxes
        .iter()
        .map(|inbox| crate::blocks::host_of(inbox).unwrap_or_default())
        .collect();
    let kind = activity.get("type").and_then(Value::as_str);
    let queued = sqlx::query(
        "INSERT INTO federation_delivery \
             (id, account_id, activity_id, inbox_url, activity, host, activity_kind) \
         SELECT queued.id, $2, $3, queued.inbox, $4, queued.host, $6 \
           FROM UNNEST($1::text[], $5::text[], $7::text[]) AS queued (id, inbox, host) \
         ON CONFLICT (inbox_url, activity_id) DO NOTHING",
    )
    .bind(&ids)
    .bind(account_id)
    .bind(&activity_id)
    .bind(activity)
    .bind(inboxes)
    .bind(kind)
    .bind(&hosts)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(queued)
}

/// How long an actor `Update` stays open for more edits.
///
/// A profile form saves several fields at once, and a person who changes an avatar and then
/// a display name saves twice in a row. One minute folds that burst into the single activity
/// a peer needs, while staying short enough that an edit made later is not held behind a
/// version the followers have already seen.
pub const ACTOR_UPDATE_WINDOW_SECS: i64 = 60;

/// Queues an actor `Update`, reusing the one already owed for this actor inside the window.
///
/// The newest document replaces the queued object, so the followers receive the profile as
/// it is at the end of the burst rather than the first edit in it. A row already delivered is
/// never rewritten: the peer has that version, and a later edit is a new activity.
pub async fn enqueue_actor_update(
    pool: &PgPool,
    account_id: &str,
    activity: &Value,
    inboxes: &[String],
) -> Result<u64, sqlx::Error> {
    let mut activity = activity.clone();
    let Some(actor) = activity
        .get("actor")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return Ok(0);
    };
    let mut activity_id = activity
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if activity_id.is_empty() || inboxes.is_empty() {
        return Ok(0);
    }

    let blocked = crate::blocks::blocked_hosts(pool).await?;
    let paused = crate::pauses::active_domains(pool).await?;
    let mut inboxes = allowed_inboxes(inboxes, &blocked, &paused);
    // The queue's `blocked_hosts` is the set of peers that told us they block this instance.
    // A domain this instance blocked is a separate list and must stop an announcement too.
    let domain_blocked: Vec<String> = sqlx::query_scalar(
        "SELECT domain::text FROM instance_block WHERE severity IN ('suspend', 'silence')",
    )
    .fetch_all(pool)
    .await?;
    inboxes.retain(|inbox| {
        crate::blocks::host_of(inbox).is_none_or(|host| !domain_blocked.contains(&host))
    });
    let suspended = crate::remote_moderation::suspended_inboxes(pool).await?;
    inboxes.retain(|inbox| !suspended.contains(inbox));
    if inboxes.is_empty() {
        return Ok(0);
    }

    // One actor, one pending update: the id of the activity already in the queue is reused
    // so the `(inbox_url, activity_id)` conflict turns this save into an object replacement.
    let prefix = format!("{actor}#updates/");
    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT activity_id FROM federation_delivery \
          WHERE account_id = $1 AND delivered_at IS NULL \
            AND left(activity_id, length($2)) = $2 \
            AND created_at > now() - make_interval(secs => $3) \
          ORDER BY created_at DESC LIMIT 1",
    )
    .bind(account_id)
    .bind(&prefix)
    .bind(ACTOR_UPDATE_WINDOW_SECS as f64)
    .fetch_optional(pool)
    .await?;
    if let Some((id,)) = existing {
        activity_id = id.clone();
        if let Some(map) = activity.as_object_mut() {
            map.insert("id".to_owned(), Value::String(id));
        }
    }

    let ids: Vec<String> = inboxes.iter().map(|_| Ulid::new().to_string()).collect();
    let hosts: Vec<String> = inboxes
        .iter()
        .map(|inbox| crate::blocks::host_of(inbox).unwrap_or_default())
        .collect();
    let kind = activity.get("type").and_then(Value::as_str);
    let queued = sqlx::query(
        "INSERT INTO federation_delivery \
             (id, account_id, activity_id, inbox_url, activity, host, activity_kind) \
         SELECT queued.id, $2, $3, queued.inbox, $4, queued.host, $6 \
           FROM UNNEST($1::text[], $5::text[], $7::text[]) AS queued (id, inbox, host) \
         ON CONFLICT (inbox_url, activity_id) DO UPDATE \
           SET activity = EXCLUDED.activity \
         WHERE federation_delivery.delivered_at IS NULL",
    )
    .bind(&ids)
    .bind(account_id)
    .bind(&activity_id)
    .bind(&activity)
    .bind(&inboxes)
    .bind(kind)
    .bind(&hosts)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(queued)
}

/// The states a delivery row can be in.
pub const STATES: [&str; 4] = ["pending", "failed", "gave_up", "delivered"];

/// The deliveries that are due, oldest first.
///
/// A `gave_up` row is never due again: it is an operator's decision whether to retry it,
/// not the worker's. A `failed` row is still owed and still scheduled.
pub async fn due(pool: &PgPool, limit: i64) -> Result<Vec<DeliveryRow>, sqlx::Error> {
    let rows: Vec<(String, String, String, Value, i32)> = sqlx::query_as(
        "SELECT id, account_id, inbox_url, activity, attempts FROM federation_delivery f \
          WHERE state IN ('pending', 'failed') AND next_attempt_at <= now() \
            AND NOT EXISTS (SELECT 1 FROM domain_pause p \
                             WHERE p.domain = f.host \
                               AND (p.expires_at IS NULL OR p.expires_at > now())) \
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

/// Marks a delivery as done, recording the 2xx that accepted it.
pub async fn delivered(
    pool: &PgPool,
    id: &str,
    status_code: Option<i32>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE federation_delivery \
            SET state = 'delivered', delivered_at = now(), last_status_code = $2 \
          WHERE id = $1",
    )
    .bind(id)
    .bind(status_code)
    .execute(pool)
    .await?;
    Ok(())
}

/// Records a failed attempt and schedules the next one, or gives up.
///
/// `retryable` is the sender's answer to whether another attempt could plausibly work. A
/// peer that refused our signature with 401 will refuse it again, so that is closed at once
/// with the error kept; a 500 or a connection that never opened is retried with backoff
/// until [`MAX_ATTEMPTS`], then closed as `gave_up`. `delivered_at` stays NULL either way:
/// it is the mark of success, not of not-owing.
pub async fn failed(
    pool: &PgPool,
    id: &str,
    attempts: i32,
    status_code: Option<i32>,
    error: &str,
    retryable: bool,
) -> Result<(), sqlx::Error> {
    let next = Utc::now() + backoff(attempts);
    let trimmed: String = error.chars().take(500).collect();
    sqlx::query(
        "UPDATE federation_delivery \
            SET attempts = $2, last_error = $3, last_status_code = $4, \
                state = CASE WHEN $5 AND $2 < $6 THEN 'failed' ELSE 'gave_up' END, \
                next_attempt_at = $7 \
          WHERE id = $1",
    )
    .bind(id)
    .bind(attempts)
    .bind(trimmed)
    .bind(status_code)
    .bind(retryable)
    .bind(MAX_ATTEMPTS)
    .bind(next)
    .execute(pool)
    .await?;
    Ok(())
}

/// One delivery as an operator sees it.
#[derive(Debug, Clone)]
pub struct DeliveryRecord {
    pub id: String,
    pub inbox_url: String,
    pub host: String,
    pub activity_id: String,
    pub activity_kind: Option<String>,
    pub state: String,
    pub attempts: i32,
    pub last_status_code: Option<i32>,
    pub last_error: Option<String>,
    pub next_attempt_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
}

/// How much of the queue is in each state.
///
/// Always the whole queue, never narrowed by the list filters: a moderator filtering to one
/// host still needs to know that forty deliveries are stuck elsewhere.
#[derive(Debug, Clone, Default)]
pub struct DeliveryCounts {
    pub pending: i64,
    pub failed: i64,
    pub gave_up: i64,
    pub delivered: i64,
}

/// What the admin list can be narrowed to.
#[derive(Debug, Clone, Default)]
pub struct DeliveryFilter<'a> {
    pub state: Option<&'a str>,
    pub host: Option<&'a str>,
    pub limit: i64,
    pub offset: i64,
}

/// One page of the delivery log, newest first, with the queue's state counts.
pub async fn list(
    pool: &PgPool,
    filter: &DeliveryFilter<'_>,
) -> Result<(Vec<DeliveryRecord>, DeliveryCounts), sqlx::Error> {
    type Row = (
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        i32,
        Option<i32>,
        Option<String>,
        DateTime<Utc>,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, inbox_url, host, activity_id, activity_kind, state, attempts, \
                last_status_code, last_error, next_attempt_at, created_at, delivered_at \
           FROM federation_delivery \
          WHERE ($1::text IS NULL OR state = $1) \
            AND ($2::text IS NULL OR host = $2) \
          ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4",
    )
    .bind(filter.state)
    .bind(filter.host)
    .bind(filter.limit)
    .bind(filter.offset)
    .fetch_all(pool)
    .await?;
    let deliveries = rows
        .into_iter()
        .map(
            |(
                id,
                inbox_url,
                host,
                activity_id,
                activity_kind,
                state,
                attempts,
                last_status_code,
                last_error,
                next_attempt_at,
                created_at,
                delivered_at,
            )| DeliveryRecord {
                id,
                inbox_url,
                host,
                activity_id,
                activity_kind,
                state,
                attempts,
                last_status_code,
                last_error,
                next_attempt_at,
                created_at,
                delivered_at,
            },
        )
        .collect();
    let counts: Vec<(String, i64)> =
        sqlx::query_as("SELECT state, count(*) FROM federation_delivery GROUP BY state")
            .fetch_all(pool)
            .await?;
    let mut summary = DeliveryCounts::default();
    for (state, count) in counts {
        match state.as_str() {
            "pending" => summary.pending = count,
            "failed" => summary.failed = count,
            "gave_up" => summary.gave_up = count,
            "delivered" => summary.delivered = count,
            _ => {}
        }
    }
    Ok((deliveries, summary))
}

/// Re-queues one delivery now and resets its attempt budget.
///
/// Returns the id when the row existed. The last error is kept: it is the reason an operator
/// is retrying, and the next failure overwrites it.
pub async fn requeue(pool: &PgPool, id: &str) -> Result<Option<String>, sqlx::Error> {
    let requeued: Option<String> = sqlx::query_scalar(
        "UPDATE federation_delivery \
            SET state = 'pending', attempts = 0, next_attempt_at = now(), delivered_at = NULL \
          WHERE id = $1 RETURNING id",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(requeued)
}

/// Re-queues every delivery whose last attempt failed, optionally only one host.
///
/// Both `failed` and `gave_up` are included: the first is already scheduled for another
/// attempt, but "retry the failures now" means now, not at the backoff's convenience.
pub async fn requeue_failed(pool: &PgPool, host: Option<&str>) -> Result<u64, sqlx::Error> {
    let requeued = sqlx::query(
        "UPDATE federation_delivery \
            SET state = 'pending', attempts = 0, next_attempt_at = now(), delivered_at = NULL \
          WHERE state IN ('failed', 'gave_up') \
            AND ($1::text IS NULL OR host = $1)",
    )
    .bind(host)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(requeued)
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

/// Every inbox this account has already delivered an activity to.
///
/// A follower list only names the accounts that still follow us. A peer that received a
/// post and later unfollowed still caches the actor, so a `Delete` must reach the inboxes
/// the delivery ledger remembers, not only the current followers.
pub async fn delivered_inboxes(
    pool: &PgPool,
    account_id: &str,
) -> Result<Vec<String>, sqlx::Error> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT inbox_url FROM federation_delivery \
          WHERE account_id = $1 AND delivered_at IS NOT NULL",
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

/// The inboxes that do not belong to a host this instance blocked or paused.
///
/// The two lists stay separate at the call site because they mean different things: a
/// blocked host is final and is never told, a paused host is temporary and is never told.
fn allowed_inboxes(
    inboxes: &[String],
    blocked_hosts: &[String],
    paused_hosts: &[String],
) -> Vec<String> {
    inboxes
        .iter()
        .filter(|inbox| match crate::blocks::host_of(inbox) {
            Some(host) => !blocked_hosts.contains(&host) && !paused_hosts.contains(&host),
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
        let allowed = super::allowed_inboxes(
            &inboxes,
            &["blocked.test".to_owned()],
            &["paused.test".to_owned()],
        );
        assert_eq!(allowed, vec!["https://open.test/inbox"]);
    }

    #[test]
    fn inboxes_of_a_paused_host_are_dropped_before_queueing() {
        let inboxes = vec![
            "https://open.test/inbox".to_owned(),
            "https://paused.test/users/a/inbox".to_owned(),
        ];
        let allowed = super::allowed_inboxes(&inboxes, &[], &["paused.test".to_owned()]);
        assert_eq!(allowed, vec!["https://open.test/inbox"]);
    }

    #[test]
    fn an_inbox_without_a_readable_host_is_left_for_the_worker() {
        let inboxes = vec!["not a url".to_owned()];
        assert_eq!(
            super::allowed_inboxes(
                &inboxes,
                &["blocked.test".to_owned()],
                &["paused.test".to_owned()]
            ),
            inboxes
        );
    }
}
