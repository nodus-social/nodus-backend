//! Social graph, interactions and notifications.
//!
//! These writes are deliberately small and transactional: a follow and its counters,
//! a favourite and its notification, a boost and its timeline copy must never be
//! observed as separate facts.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

use nodus_server_core::Id;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Relationship {
    pub following: bool,
    pub requested: bool,
    pub showing_reblogs: bool,
    pub notifying: bool,
    pub blocked: bool,
    pub blocked_by: bool,
    pub followed_by: bool,
    pub muting: bool,
    pub muting_notifications: bool,
}

/// `(follow state, reblogs, notify, blocked, muting, muting notifications, followed by, blocked by)`
type RelationshipRow = (
    Option<String>,
    Option<bool>,
    Option<bool>,
    bool,
    bool,
    bool,
    bool,
    bool,
);

/// One account's relationship to another.
///
/// Two of these fields point the other way — `followed_by` and `blocked_by` ask what the
/// target did to the reader, not what the reader did to the target — because a client draws
/// "Follows you" and "Blocks you" from the same answer as "Following" and "Blocking".
pub async fn relationship(
    pool: &PgPool,
    account_id: &str,
    target_id: &str,
) -> Result<Relationship, sqlx::Error> {
    let row: RelationshipRow = sqlx::query_as(
            "SELECT f.state, f.reblogs, f.notify, \
                    EXISTS (SELECT 1 FROM account_relation r WHERE r.account_id = $1 \
                            AND r.target_account_id = $2 AND r.kind = 'block'), \
                    EXISTS (SELECT 1 FROM account_relation r WHERE r.account_id = $1 \
                            AND r.target_account_id = $2 AND r.kind = 'mute'), \
                    COALESCE((SELECT r.notifications FROM account_relation r WHERE r.account_id = $1 \
                            AND r.target_account_id = $2 AND r.kind = 'mute'), false), \
                    EXISTS (SELECT 1 FROM follow back WHERE back.account_id = $2 \
                            AND back.target_account_id = $1 AND back.state = 'accepted'), \
                    EXISTS (SELECT 1 FROM account_relation r WHERE r.account_id = $2 \
                            AND r.target_account_id = $1 AND r.kind = 'block') \
             FROM (SELECT 1) seed \
             LEFT JOIN follow f ON f.account_id = $1 AND f.target_account_id = $2",
        )
        .bind(account_id)
        .bind(target_id)
        .fetch_one(pool)
        .await?;
    Ok(Relationship {
        following: row.0.as_deref() == Some("accepted"),
        requested: row.0.as_deref() == Some("pending"),
        showing_reblogs: row.1.unwrap_or(false),
        notifying: row.2.unwrap_or(false),
        blocked: row.3,
        muting: row.4,
        muting_notifications: row.5,
        followed_by: row.6,
        blocked_by: row.7,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowOutcome {
    Following,
    Requested,
}

fn ordered_pair<'a>(first: &'a str, second: &'a str) -> (&'a str, Option<&'a str>) {
    match first.cmp(second) {
        std::cmp::Ordering::Equal => (first, None),
        std::cmp::Ordering::Less => (first, Some(second)),
        std::cmp::Ordering::Greater => (second, Some(first)),
    }
}

/// Locks both accounts in deterministic `id` order to prevent counter drift and deadlocks.
async fn lock_account_pair(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    first: &str,
    second: &str,
) -> Result<(), sqlx::Error> {
    let (a, b) = ordered_pair(first, second);
    for id in std::iter::once(a).chain(b) {
        sqlx::query("SELECT id FROM account WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?;
    }
    Ok(())
}

/// Recomputes `followers_count` and `following_count` for both accounts inside `tx`.
async fn sync_follow_counts(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    first: &str,
    second: &str,
) -> Result<(), sqlx::Error> {
    let (a, b) = ordered_pair(first, second);
    for id in std::iter::once(a).chain(b) {
        sqlx::query(
            "UPDATE account SET \
                 followers_count = (SELECT count(*) FROM follow WHERE target_account_id = $1 AND state = 'accepted'), \
                 following_count = (SELECT count(*) FROM follow WHERE account_id = $1 AND state = 'accepted') \
             WHERE id = $1",
        )
        .bind(id)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Follows a target, or updates the reblog/notify switches when already following.
pub async fn follow(
    pool: &PgPool,
    account_id: &str,
    target_id: &str,
    reblogs: bool,
    notify: bool,
) -> Result<FollowOutcome, sqlx::Error> {
    if account_id == target_id {
        return Ok(FollowOutcome::Following);
    }
    let mut tx = pool.begin().await?;
    lock_account_pair(&mut tx, account_id, target_id).await?;
    let locked: Option<bool> = sqlx::query_scalar("SELECT locked FROM account WHERE id = $1")
        .bind(target_id)
        .fetch_optional(&mut *tx)
        .await?;
    let state = if locked.unwrap_or(false) {
        "pending"
    } else {
        "accepted"
    };
    let inserted: Option<(String,)> = sqlx::query_as(
        "INSERT INTO follow (id, account_id, target_account_id, state, reblogs, notify) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (account_id, target_account_id) DO UPDATE \
           SET state = CASE WHEN follow.state = 'accepted' THEN 'accepted' ELSE EXCLUDED.state END, \
               reblogs = EXCLUDED.reblogs, notify = EXCLUDED.notify \
         RETURNING state",
    )
    .bind(Id::new().to_string())
    .bind(account_id)
    .bind(target_id)
    .bind(state)
    .bind(reblogs)
    .bind(notify)
    .fetch_optional(&mut *tx)
    .await?;
    let resulting = inserted.map_or(state, |(value,)| {
        if value == "pending" {
            "pending"
        } else {
            "accepted"
        }
    });
    if resulting == "accepted" {
        sync_follow_counts(&mut tx, account_id, target_id).await?;
    }
    tx.commit().await?;
    Ok(if resulting == "pending" {
        FollowOutcome::Requested
    } else {
        FollowOutcome::Following
    })
}

/// Unfollows, and clears what that follow had already put on the reader's home timeline.
///
/// The posts were fanned into `timeline_entry` at creation, which makes the row outlive
/// the follow edge unless it is deleted here: the SQL page reads the row, not the follow,
/// so a stale entry would keep the target's posts on the reader's timeline after an
/// unfollow. Returns the ids removed, so the caller can take the same ids out of the
/// reader's cached timeline (`crates/api/src/home.rs` owns that copy).
///
/// One `DELETE` for every status of that author, in the same transaction as the follow
/// row: the two cannot be observed disagreeing. Entries written to *other* readers are
/// untouched — the purge is scoped to `account_id`'s timeline.
pub async fn unfollow(
    pool: &PgPool,
    account_id: &str,
    target_id: &str,
) -> Result<Vec<String>, sqlx::Error> {
    if account_id == target_id {
        return Ok(Vec::new());
    }
    let mut tx = pool.begin().await?;
    lock_account_pair(&mut tx, account_id, target_id).await?;
    let removed: Option<(String,)> = sqlx::query_as(
        "DELETE FROM follow WHERE account_id = $1 AND target_account_id = $2 RETURNING state",
    )
    .bind(account_id)
    .bind(target_id)
    .fetch_optional(&mut *tx)
    .await?;
    if removed.as_ref().is_some_and(|(state,)| state == "accepted") {
        sync_follow_counts(&mut tx, account_id, target_id).await?;
    }
    let purged: Vec<String> = sqlx::query_scalar(
        "DELETE FROM timeline_entry \
          WHERE account_id = $1 AND kind = 'home' \
            AND status_id IN (SELECT s.id FROM status s WHERE s.account_id = $2) \
         RETURNING status_id",
    )
    .bind(account_id)
    .bind(target_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(purged)
}

/// Accepts a pending follow request, if the target owns it.
pub async fn accept_follow(
    pool: &PgPool,
    target_id: &str,
    requester_id: &str,
) -> Result<bool, sqlx::Error> {
    if target_id == requester_id {
        return Ok(false);
    }
    let mut tx = pool.begin().await?;
    lock_account_pair(&mut tx, requester_id, target_id).await?;
    let changed = sqlx::query(
        "UPDATE follow SET state = 'accepted' \
         WHERE account_id = $1 AND target_account_id = $2 AND state = 'pending'",
    )
    .bind(requester_id)
    .bind(target_id)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    if changed {
        sync_follow_counts(&mut tx, requester_id, target_id).await?;
    }
    tx.commit().await?;
    Ok(changed)
}

pub async fn reject_follow(
    pool: &PgPool,
    target_id: &str,
    requester_id: &str,
) -> Result<bool, sqlx::Error> {
    let changed = sqlx::query(
        "DELETE FROM follow WHERE account_id = $1 AND target_account_id = $2 AND state = 'pending'",
    )
    .bind(requester_id)
    .bind(target_id)
    .execute(pool)
    .await?
    .rows_affected()
        == 1;
    Ok(changed)
}

#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct AccountListRow {
    pub id: String,
    pub username: String,
    pub domain: Option<String>,
    pub display_name: String,
    pub note: String,
    pub avatar_ref: Option<String>,
    pub header_ref: Option<String>,
    pub avatar_url: Option<String>,
    pub header_url: Option<String>,
    pub locked: bool,
    pub bot: bool,
    pub local: bool,
    pub uri: Option<String>,
    pub followers_count: i64,
    pub following_count: i64,
    pub statuses_count: i64,
    pub last_status_at: Option<DateTime<Utc>>,
    pub suspended_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// One account waiting for this reader to approve or refuse their follow.
#[derive(Debug, Clone, FromRow)]
pub struct FollowRequestRow {
    pub account_id: String,
    pub created_at: DateTime<Utc>,
}

/// Pending follows of a locked account, newest first.
///
/// Only `pending` rows: an accepted follow is in the followers list and a rejected one
/// has been deleted, so the state alone is the whole story.
pub async fn follow_requests(
    pool: &PgPool,
    target_id: &str,
    limit: i64,
) -> Result<Vec<FollowRequestRow>, sqlx::Error> {
    sqlx::query_as::<_, FollowRequestRow>(
        "SELECT account_id, created_at FROM follow \
          WHERE target_account_id = $1 AND state = 'pending' \
          ORDER BY created_at DESC LIMIT $2",
    )
    .bind(target_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Followers or following, newest relationship first.
pub async fn follow_page(
    pool: &PgPool,
    account_id: &str,
    followers: bool,
    max_id: Option<&str>,
    limit: i64,
) -> Result<Vec<AccountListRow>, sqlx::Error> {
    let sql = if followers {
        "SELECT a.id, a.username::text, a.domain::text, a.display_name, a.note, a.avatar_ref, \
                a.header_ref, a.avatar_url, a.header_url, a.locked, a.bot, a.local, a.uri, a.followers_count, \
                a.following_count, a.statuses_count, a.last_status_at, a.suspended_at, a.created_at \
           FROM follow f JOIN account a ON a.id = f.account_id \
          WHERE f.target_account_id = $1 AND f.state = 'accepted' \
            AND ($2::text IS NULL OR f.id < $2) \
          ORDER BY f.id DESC LIMIT $3"
    } else {
        "SELECT a.id, a.username::text, a.domain::text, a.display_name, a.note, a.avatar_ref, \
                a.header_ref, a.avatar_url, a.header_url, a.locked, a.bot, a.local, a.uri, a.followers_count, \
                a.following_count, a.statuses_count, a.last_status_at, a.suspended_at, a.created_at \
           FROM follow f JOIN account a ON a.id = f.target_account_id \
          WHERE f.account_id = $1 AND f.state = 'accepted' \
            AND ($2::text IS NULL OR f.id < $2) \
          ORDER BY f.id DESC LIMIT $3"
    };
    sqlx::query_as::<_, AccountListRow>(sql)
        .bind(account_id)
        .bind(max_id)
        .bind(limit)
        .fetch_all(pool)
        .await
}

/// Adds a notification unless the actor is the recipient.
///
/// A `poll` notification is one line per poll: a second voter bumps the existing row's
/// actor and tally instead of adding another line, which is what the partial unique index
/// `notification_poll_group_idx` enforces. Every other kind stays one row per event.
pub async fn notify(
    pool: &PgPool,
    account_id: &str,
    kind: &str,
    from_account_id: &str,
    status_id: Option<&str>,
) -> Result<(), sqlx::Error> {
    notify_with_note(pool, account_id, kind, from_account_id, status_id, None).await
}

/// The same event with a sentence the reader is told, for kinds whose payload is text
/// rather than a status: a decided appeal carries its outcome and the moderator's note.
pub async fn notify_with_note(
    pool: &PgPool,
    account_id: &str,
    kind: &str,
    from_account_id: &str,
    status_id: Option<&str>,
    note: Option<&str>,
) -> Result<(), sqlx::Error> {
    if account_id == from_account_id {
        return Ok(());
    }
    // The id comes back from both shapes so the live stream can name the row it tells the
    // recipient about. Publishing is fire-and-forget: a browser that stopped reading must
    // not make a favourite wait.
    let id: String = if kind == "poll" && status_id.is_some() {
        sqlx::query_scalar(
            "INSERT INTO notification (id, account_id, kind, from_account_id, status_id, note) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (account_id, status_id) WHERE kind = 'poll' \
             DO UPDATE SET from_account_id = EXCLUDED.from_account_id, \
                           group_count = notification.group_count + 1, \
                           created_at = now(), \
                           seen_at = NULL \
             RETURNING id",
        )
        .bind(Id::new().to_string())
        .bind(account_id)
        .bind(kind)
        .bind(from_account_id)
        .bind(status_id)
        .bind(note)
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_scalar(
            "INSERT INTO notification (id, account_id, kind, from_account_id, status_id, note) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             RETURNING id",
        )
        .bind(Id::new().to_string())
        .bind(account_id)
        .bind(kind)
        .bind(from_account_id)
        .bind(status_id)
        .bind(note)
        .fetch_one(pool)
        .await?
    };
    crate::live::notification(account_id, &id);
    Ok(())
}

#[derive(Debug, Clone, FromRow)]
pub struct NotificationRow {
    pub id: String,
    pub kind: String,
    pub account_id: String,
    pub from_account_id: String,
    pub status_id: Option<String>,
    /// The sentence a kind without a status carries; `appeal` and `moderation` are the
    /// users today.
    pub note: Option<String>,
    /// For `moderation`: the decision, spelled as the audit log spells it (`silence`,
    /// `unsuspend`, `warn`). `None` on every other kind.
    pub moderation_action: Option<String>,
    /// For `moderation`: the moderator's reason — the same text the audit row carries.
    pub moderation_reason: Option<String>,
    /// For `moderation`: the rule that decided, when a rule rather than a person did.
    pub moderation_rule: Option<String>,
    /// For `moderation`: when the restriction ends, when it has an end.
    pub moderation_expires_at: Option<DateTime<Utc>>,
    /// How many events this line stands for; only `poll` aggregates, so it is 1 elsewhere.
    pub group_count: i32,
    pub seen_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

pub async fn notifications(
    pool: &PgPool,
    account_id: &str,
    max_id: Option<&str>,
    limit: i64,
    kinds: &[String],
) -> Result<Vec<NotificationRow>, sqlx::Error> {
    sqlx::query_as::<_, NotificationRow>(
        "SELECT id, kind, account_id, from_account_id, status_id, note, group_count, \
                seen_at, created_at, moderation_action, moderation_reason, moderation_rule, \
                moderation_expires_at \
           FROM notification \
          WHERE account_id = $1 \
            AND ($2::text IS NULL OR id < $2) \
            AND (cardinality($3::text[]) = 0 OR kind = ANY($3)) \
            AND NOT EXISTS (SELECT 1 FROM account_relation r \
                            WHERE r.account_id = $1 AND r.target_account_id = from_account_id \
                              AND (r.kind = 'block' OR (r.kind = 'mute' AND r.notifications))) \
            AND NOT EXISTS (SELECT 1 FROM account a \
                              JOIN account_domain_block d ON d.host = a.domain \
                            WHERE a.id = from_account_id AND d.account_id = $1) \
          ORDER BY id DESC LIMIT $4",
    )
    .bind(account_id)
    .bind(max_id)
    .bind(kinds)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// One notification, for the live stream that names the row it just created.
///
/// Unlike [`notifications`] this does not re-check blocks and mutes: the row exists only
/// because the write path made it, and a recipient whose filters changed mid-flight will
/// see it drop on the next read rather than miss the event that was already sent.
pub async fn notification_by_id(
    pool: &PgPool,
    account_id: &str,
    id: &str,
) -> Result<Option<NotificationRow>, sqlx::Error> {
    sqlx::query_as::<_, NotificationRow>(
        "SELECT id, kind, account_id, from_account_id, status_id, note, group_count, \
                seen_at, created_at, moderation_action, moderation_reason, moderation_rule, \
                moderation_expires_at \
           FROM notification WHERE account_id = $1 AND id = $2",
    )
    .bind(account_id)
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn dismiss_notification(
    pool: &PgPool,
    account_id: &str,
    id: &str,
) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query("DELETE FROM notification WHERE id = $1 AND account_id = $2")
            .bind(id)
            .bind(account_id)
            .execute(pool)
            .await?
            .rows_affected()
            == 1,
    )
}

pub async fn clear_notifications(pool: &PgPool, account_id: &str) -> Result<u64, sqlx::Error> {
    Ok(
        sqlx::query("DELETE FROM notification WHERE account_id = $1")
            .bind(account_id)
            .execute(pool)
            .await?
            .rows_affected(),
    )
}

pub async fn mark_seen(pool: &PgPool, account_id: &str, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE notification SET seen_at = now() WHERE id = $1 AND account_id = $2")
        .bind(id)
        .bind(account_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Favourites one status, returning the new count.
pub async fn favourite(
    pool: &PgPool,
    account_id: &str,
    status_id: &str,
) -> Result<i64, sqlx::Error> {
    let inserted = sqlx::query(
        "INSERT INTO favourite (account_id, status_id) VALUES ($1, $2) \
         ON CONFLICT DO NOTHING",
    )
    .bind(account_id)
    .bind(status_id)
    .execute(pool)
    .await?
    .rows_affected();
    if inserted == 1 {
        sqlx::query(
            "UPDATE status SET favourites_count = \
                 (SELECT count(*) FROM favourite WHERE status_id = $1) WHERE id = $1",
        )
        .bind(status_id)
        .execute(pool)
        .await?;
        let author: Option<String> =
            sqlx::query_scalar("SELECT account_id FROM status WHERE id = $1")
                .bind(status_id)
                .fetch_optional(pool)
                .await?;
        if let Some(author) = author {
            notify(pool, &author, "favourite", account_id, Some(status_id)).await?;
        }
    }
    count(pool, status_id, "favourite").await
}

pub async fn unfavourite(
    pool: &PgPool,
    account_id: &str,
    status_id: &str,
) -> Result<i64, sqlx::Error> {
    if sqlx::query("DELETE FROM favourite WHERE account_id = $1 AND status_id = $2")
        .bind(account_id)
        .bind(status_id)
        .execute(pool)
        .await?
        .rows_affected()
        == 1
    {
        sqlx::query(
            "UPDATE status SET favourites_count = \
                 (SELECT count(*) FROM favourite WHERE status_id = $1) WHERE id = $1",
        )
        .bind(status_id)
        .execute(pool)
        .await?;
    }
    count(pool, status_id, "favourite").await
}

pub async fn bookmark(pool: &PgPool, account_id: &str, status_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO bookmark (account_id, status_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(account_id)
    .bind(status_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn unbookmark(
    pool: &PgPool,
    account_id: &str,
    status_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM bookmark WHERE account_id = $1 AND status_id = $2")
        .bind(account_id)
        .bind(status_id)
        .execute(pool)
        .await?;
    Ok(())
}

async fn count(pool: &PgPool, status_id: &str, table: &str) -> Result<i64, sqlx::Error> {
    let column = if table == "favourite" {
        "favourites_count"
    } else {
        "reblogs_count"
    };
    let sql = format!("SELECT {column} FROM status WHERE id = $1");
    sqlx::query_scalar(&sql)
        .bind(status_id)
        .fetch_optional(pool)
        .await
        .map(Option::unwrap_or_default)
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ViewerFlags {
    pub favourited: bool,
    pub reblogged: bool,
    pub bookmarked: bool,
}

/// Viewer state for many statuses in one query, keyed by status id.
pub async fn viewer_flags(
    pool: &PgPool,
    account_id: &str,
    status_ids: &[String],
) -> Result<std::collections::HashMap<String, ViewerFlags>, sqlx::Error> {
    #[derive(FromRow)]
    struct Row {
        id: String,
        favourited: bool,
        reblogged: bool,
        bookmarked: bool,
    }
    let rows = sqlx::query_as::<_, Row>(
        "SELECT s.id, \
                EXISTS (SELECT 1 FROM favourite f WHERE f.status_id = s.id AND f.account_id = $1) AS favourited, \
                EXISTS (SELECT 1 FROM status r WHERE r.reblog_of_id = s.id AND r.account_id = $1 AND r.deleted_at IS NULL) AS reblogged, \
                EXISTS (SELECT 1 FROM bookmark b WHERE b.status_id = s.id AND b.account_id = $1) AS bookmarked \
           FROM status s WHERE s.id = ANY($2)",
    )
    .bind(account_id)
    .bind(status_ids)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            (
                row.id,
                ViewerFlags {
                    favourited: row.favourited,
                    reblogged: row.reblogged,
                    bookmarked: row.bookmarked,
                },
            )
        })
        .collect())
}

/// Blocks a target, removing follows in both directions and all notifications.
pub async fn block(pool: &PgPool, account_id: &str, target_id: &str) -> Result<(), sqlx::Error> {
    if account_id == target_id {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    lock_account_pair(&mut tx, account_id, target_id).await?;
    sqlx::query(
        "INSERT INTO account_relation (account_id, target_account_id, kind) \
         VALUES ($1, $2, 'block') ON CONFLICT DO NOTHING",
    )
    .bind(account_id)
    .bind(target_id)
    .execute(&mut *tx)
    .await?;
    let mut removed_accepted = false;
    for (from, to) in [(account_id, target_id), (target_id, account_id)] {
        let removed: Option<(String,)> = sqlx::query_as(
            "DELETE FROM follow WHERE account_id = $1 AND target_account_id = $2 RETURNING state",
        )
        .bind(from)
        .bind(to)
        .fetch_optional(&mut *tx)
        .await?;
        if removed.as_ref().is_some_and(|(state,)| state == "accepted") {
            removed_accepted = true;
        }
    }
    if removed_accepted {
        sync_follow_counts(&mut tx, account_id, target_id).await?;
    }
    sqlx::query(
        "DELETE FROM notification WHERE (account_id = $1 AND from_account_id = $2) \
         OR (account_id = $2 AND from_account_id = $1)",
    )
    .bind(account_id)
    .bind(target_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    crate::live::filters_changed(account_id);
    Ok(())
}

pub async fn unblock(pool: &PgPool, account_id: &str, target_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM account_relation WHERE account_id = $1 AND target_account_id = $2 AND kind = 'block'")
        .bind(account_id)
        .bind(target_id)
        .execute(pool)
        .await?;
    crate::live::filters_changed(account_id);
    Ok(())
}

pub async fn mute(
    pool: &PgPool,
    account_id: &str,
    target_id: &str,
    notifications: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO account_relation (account_id, target_account_id, kind, notifications) \
         VALUES ($1, $2, 'mute', $3) \
         ON CONFLICT (account_id, target_account_id, kind) DO UPDATE \
           SET notifications = EXCLUDED.notifications",
    )
    .bind(account_id)
    .bind(target_id)
    .bind(notifications)
    .execute(pool)
    .await?;
    crate::live::filters_changed(account_id);
    Ok(())
}

pub async fn unmute(pool: &PgPool, account_id: &str, target_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM account_relation WHERE account_id = $1 AND target_account_id = $2 AND kind = 'mute'")
        .bind(account_id)
        .bind(target_id)
        .execute(pool)
        .await?;
    crate::live::filters_changed(account_id);
    Ok(())
}

pub async fn relations(
    pool: &PgPool,
    account_id: &str,
    kind: &str,
) -> Result<Vec<crate::accounts::AccountRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {} FROM account a JOIN account_relation r ON r.target_account_id = a.id \
         WHERE r.account_id = $1 AND r.kind = $2 ORDER BY r.created_at DESC",
        crate::accounts::ACCOUNT_COLUMNS_ALIASED
    );
    sqlx::query_as::<_, crate::accounts::AccountRow>(&sql)
        .bind(account_id)
        .bind(kind)
        .fetch_all(pool)
        .await
}
