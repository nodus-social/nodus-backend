//! Relay subscriptions: the instance's own `Follow` of a relay actor.
//!
//! These rows name no account — a relay is instance infrastructure, not a person — and are
//! read by the shared inbox and by the staff console. The state is a one-way walk from
//! `pending` to `accepted` or `rejected`, and the `Follow`'s id is kept because the `Undo`
//! that unsubscribes has to name the very activity the relay stored.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use ulid::Ulid;

/// Our `Follow` is queued, or has been queued at least once, and the relay has not answered.
pub const PENDING: &str = "pending";
/// The relay answered `Accept(Follow)`.
pub const ACCEPTED: &str = "accepted";
/// The relay answered `Reject(Follow)`.
pub const REJECTED: &str = "rejected";

/// Every state a row can be in, in the order a console reads them.
pub const STATES: [&str; 3] = [PENDING, ACCEPTED, REJECTED];

/// One subscription as stored.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RelayRow {
    pub id: String,
    /// The relay URL the `Follow` is addressed to and names as its object; the delivery
    /// target too, because a relay is reached at the same URL it is addressed by.
    pub actor_uri: String,
    pub state: String,
    pub follow_activity_id: Option<String>,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const COLUMNS: &str = "id, actor_uri, state, follow_activity_id, last_attempt_at, \
     created_at, updated_at";

/// What subscribing needs before the row exists.
#[derive(Debug, Clone)]
pub struct NewRelay<'a> {
    pub actor_uri: &'a str,
    pub follow_activity_id: &'a str,
}

/// Writes a subscription down as `pending`.
///
/// Returns `None` when the relay is already in the table. That conflict is the duplicate
/// the console refuses with a sentence, so it is a value here rather than an error.
pub async fn create(pool: &PgPool, relay: &NewRelay<'_>) -> Result<Option<RelayRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "INSERT INTO relay (id, actor_uri, state, follow_activity_id, last_attempt_at) \
         VALUES ($1, $2, $3, $4, now()) \
         ON CONFLICT (actor_uri) DO NOTHING \
         RETURNING {COLUMNS}"
    ))
    .bind(Ulid::new().to_string())
    .bind(relay.actor_uri)
    .bind(PENDING)
    .bind(relay.follow_activity_id)
    .fetch_optional(pool)
    .await
}

/// Every subscription, oldest first.
pub async fn list(pool: &PgPool) -> Result<Vec<RelayRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM relay ORDER BY created_at, id"
    ))
    .fetch_all(pool)
    .await
}

/// One subscription by id.
pub async fn by_id(pool: &PgPool, id: &str) -> Result<Option<RelayRow>, sqlx::Error> {
    sqlx::query_as(&format!("SELECT {COLUMNS} FROM relay WHERE id = $1"))
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// The subscription whose `Follow` an `Accept` or `Reject` names.
pub async fn by_follow_activity(
    pool: &PgPool,
    follow_activity_id: &str,
) -> Result<Option<RelayRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM relay WHERE follow_activity_id = $1"
    ))
    .bind(follow_activity_id)
    .fetch_optional(pool)
    .await
}

/// Moves a subscription to `state`, returning the updated row.
///
/// `None` means there is no such row — a relay answered a `Follow` that was already
/// unsubscribed, which is not an error at the inbox.
pub async fn set_state(
    pool: &PgPool,
    id: &str,
    state: &str,
) -> Result<Option<RelayRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "UPDATE relay SET state = $2, updated_at = now() WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(state)
    .fetch_optional(pool)
    .await
}

/// Removes a subscription and returns the row as it was, so the caller can still name the
/// `Follow` its `Undo` withdraws.
pub async fn delete(pool: &PgPool, id: &str) -> Result<Option<RelayRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "DELETE FROM relay WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
}
