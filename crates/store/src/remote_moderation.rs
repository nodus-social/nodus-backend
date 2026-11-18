//! One remote account moderated, rather than the whole instance it lives on.
//!
//! The row is the decision: `silence` keeps an actor's posts out of public timelines and
//! anonymous listings while a direct link still resolves, and `suspend` removes the actor
//! and its posts everywhere and refuses new inbound activities from it.
//!
//! Expiry is evaluated on every read (`expires_at IS NULL OR expires_at > now()`), never
//! by a sweeper: an expired row has to stop applying the moment it expires, and it stays
//! in the table as the record of what was done, by whom and why.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

pub const SILENCE: &str = "silence";
pub const SUSPEND: &str = "suspend";

const COLUMNS: &str = "actor_uri, action, reason, expires_at, created_at, created_by";

/// The predicate that says a row applies right now, for a given table alias.
fn active_at(alias: &str) -> String {
    format!("({alias}.expires_at IS NULL OR {alias}.expires_at > now())")
}

#[derive(Debug, Clone, FromRow)]
pub struct RemoteModerationRow {
    pub actor_uri: String,
    pub action: String,
    pub reason: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<String>,
}

impl RemoteModerationRow {
    /// Whether the action still applies at `now`.
    ///
    /// The database already filters on this; the admin list also shows expired rows, so
    /// the flag is computed once here instead of in every caller.
    #[must_use]
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_none_or(|expires_at| expires_at > now)
    }
}

/// A decision being written, applied or changed.
#[derive(Debug, Clone)]
pub struct NewRemoteModeration<'a> {
    pub actor_uri: &'a str,
    pub action: &'a str,
    pub reason: Option<&'a str>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_by: Option<&'a str>,
}

/// The stored columns plus the `xmax` flag that tells an insert from an update.
type UpsertedRow = (
    String,
    String,
    Option<String>,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
    Option<String>,
    bool,
);

/// Applies an action, replacing whatever was recorded for the actor.
///
/// Returns the stored row and whether it was newly created, so the endpoint can answer
/// `201` for a new decision and `200` for a change to an existing one.
pub async fn upsert(
    pool: &PgPool,
    new: &NewRemoteModeration<'_>,
) -> Result<(RemoteModerationRow, bool), sqlx::Error> {
    let sql = format!(
        "INSERT INTO remote_moderation (actor_uri, action, reason, expires_at, created_by) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (actor_uri) DO UPDATE SET action = $2, reason = $3, expires_at = $4, \
             created_by = $5, created_at = now() \
         RETURNING {COLUMNS}, (xmax = 0) AS inserted"
    );
    let (actor_uri, action, reason, expires_at, created_at, created_by, inserted): UpsertedRow =
        sqlx::query_as(&sql)
            .bind(new.actor_uri)
            .bind(new.action)
            .bind(new.reason)
            .bind(new.expires_at)
            .bind(new.created_by)
            .fetch_one(pool)
            .await?;
    Ok((
        RemoteModerationRow {
            actor_uri,
            action,
            reason,
            expires_at,
            created_at,
            created_by,
        },
        inserted,
    ))
}

/// Lifts the action. `false` means there was nothing to lift.
pub async fn lift(pool: &PgPool, actor_uri: &str) -> Result<bool, sqlx::Error> {
    let removed = sqlx::query("DELETE FROM remote_moderation WHERE actor_uri = $1")
        .bind(actor_uri)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(removed > 0)
}

/// The row as stored, expired or not.
pub async fn by_actor(
    pool: &PgPool,
    actor_uri: &str,
) -> Result<Option<RemoteModerationRow>, sqlx::Error> {
    let sql = format!("SELECT {COLUMNS} FROM remote_moderation WHERE actor_uri = $1");
    sqlx::query_as(&sql)
        .bind(actor_uri)
        .fetch_optional(pool)
        .await
}

/// The row only while it applies.
pub async fn active(
    pool: &PgPool,
    actor_uri: &str,
) -> Result<Option<RemoteModerationRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {COLUMNS} FROM remote_moderation m \
          WHERE m.actor_uri = $1 AND {}",
        active_at("m")
    );
    sqlx::query_as(&sql)
        .bind(actor_uri)
        .fetch_optional(pool)
        .await
}

/// The action in force for an actor, if any.
pub async fn active_action(pool: &PgPool, actor_uri: &str) -> Result<Option<String>, sqlx::Error> {
    let sql = format!(
        "SELECT m.action FROM remote_moderation m WHERE m.actor_uri = $1 AND {}",
        active_at("m")
    );
    sqlx::query_scalar(&sql)
        .bind(actor_uri)
        .fetch_optional(pool)
        .await
}

/// The action in force for a local account row, which the read paths have at hand.
pub async fn action_for_account(
    pool: &PgPool,
    account_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    let sql = format!(
        "SELECT m.action FROM remote_moderation m \
           JOIN account a ON a.uri = m.actor_uri \
          WHERE a.id = $1 AND {}",
        active_at("m")
    );
    sqlx::query_scalar(&sql)
        .bind(account_id)
        .fetch_optional(pool)
        .await
}

/// One row plus the names the console needs to render it.
#[derive(Debug, Clone)]
pub struct ListedRemoteModeration {
    pub row: RemoteModerationRow,
    /// The account's name when we know the actor, else the last segment of its URL.
    pub handle: String,
    pub domain: Option<String>,
    pub created_by_handle: Option<String>,
}

type ListedRow = (
    String,
    String,
    Option<String>,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Every recorded action, newest first, with the account and domain derived from the
/// actor URL. `domain`, when given, narrows the list to actors on that host.
pub async fn list(
    pool: &PgPool,
    domain: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<ListedRemoteModeration>, sqlx::Error> {
    let rows: Vec<ListedRow> = sqlx::query_as(
        "SELECT m.actor_uri, m.action, m.reason, m.expires_at, m.created_at, m.created_by, \
                a.username AS handle_name, \
                staff.username AS staff_name \
           FROM remote_moderation m \
           LEFT JOIN account a ON a.uri = m.actor_uri \
           LEFT JOIN account staff ON staff.id = m.created_by \
          ORDER BY m.created_at DESC, m.actor_uri",
    )
    .fetch_all(pool)
    .await?;

    let wanted = domain
        .map(|domain| domain.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|domain| !domain.is_empty());

    let listed: Vec<ListedRemoteModeration> = rows
        .into_iter()
        .map(
            |(
                actor_uri,
                action,
                reason,
                expires_at,
                created_at,
                created_by,
                handle_name,
                staff_name,
            )| {
                let host = crate::blocks::host_of(&actor_uri);
                let handle = handle_name.unwrap_or_else(|| {
                    actor_uri
                        .rsplit('/')
                        .next()
                        .unwrap_or(&actor_uri)
                        .to_owned()
                });
                ListedRemoteModeration {
                    row: RemoteModerationRow {
                        actor_uri,
                        action,
                        reason,
                        expires_at,
                        created_at,
                        created_by,
                    },
                    handle,
                    domain: host,
                    created_by_handle: staff_name,
                }
            },
        )
        .filter(|listed| {
            wanted
                .as_deref()
                .is_none_or(|wanted| listed.domain.as_deref() == Some(wanted))
        })
        .skip(usize::try_from(offset.max(0)).unwrap_or(0))
        .take(usize::try_from(limit.max(0)).unwrap_or(0))
        .collect();

    Ok(listed)
}

/// The inboxes that only suspended actors read.
///
/// A personal inbox belongs to one actor, so it is dropped whole. A shared inbox belongs
/// to every account on the host, so it is dropped only when every account known to use it
/// is suspended — otherwise one bad account would cut the server off.
pub async fn suspended_inboxes(pool: &PgPool) -> Result<Vec<String>, sqlx::Error> {
    let sql = format!(
        "SELECT DISTINCT COALESCE(a.shared_inbox_url, a.inbox_url) AS inbox \
           FROM account a \
          WHERE a.domain IS NOT NULL \
            AND COALESCE(a.shared_inbox_url, a.inbox_url) IS NOT NULL \
            AND EXISTS (SELECT 1 FROM remote_moderation m \
                         WHERE m.actor_uri = a.uri AND m.action = 'suspend' AND {}) \
            AND NOT EXISTS ( \
                SELECT 1 FROM account other \
                 WHERE other.domain IS NOT NULL \
                   AND COALESCE(other.shared_inbox_url, other.inbox_url) \
                       = COALESCE(a.shared_inbox_url, a.inbox_url) \
                   AND NOT EXISTS (SELECT 1 FROM remote_moderation m2 \
                                    WHERE m2.actor_uri = other.uri AND m2.action = 'suspend' \
                                      AND {}))",
        active_at("m"),
        active_at("m2")
    );
    sqlx::query_scalar(&sql).fetch_all(pool).await
}
