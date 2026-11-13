//! Social graph, interactions and notifications.
//!
//! These writes are deliberately small and transactional: a follow and its counters,
//! a favourite and its notification, a boost and its timeline copy must never be
//! observed as separate facts.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

use nodus_server_core::Id;

#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct Relationship {
    pub following: bool,
    pub requested: bool,
    pub showing_reblogs: bool,
    pub notifying: bool,
}

/// One account's relationship to another.
pub async fn relationship(
    pool: &PgPool,
    account_id: &str,
    target_id: &str,
) -> Result<Relationship, sqlx::Error> {
    let row: Option<(String, bool, bool)> = sqlx::query_as(
        "SELECT state, reblogs, notify FROM follow \
         WHERE account_id = $1 AND target_account_id = $2",
    )
    .bind(account_id)
    .bind(target_id)
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        Some((state, reblogs, notify)) => Relationship {
            following: state == "accepted",
            requested: state == "pending",
            showing_reblogs: reblogs,
            notifying: notify,
        },
        None => Relationship::default(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowOutcome {
    Following,
    Requested,
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
    let locked: Option<bool> = sqlx::query_scalar("SELECT locked FROM account WHERE id = $1")
        .bind(target_id)
        .fetch_optional(pool)
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
    .fetch_optional(pool)
    .await?;
    let resulting = inserted.map_or(state, |(value,)| {
        if value == "pending" {
            "pending"
        } else {
            "accepted"
        }
    });
    if resulting == "accepted" {
        sqlx::query(
            "UPDATE account SET followers_count = \
                 (SELECT count(*) FROM follow WHERE target_account_id = $1 AND state = 'accepted') \
             WHERE id = $1",
        )
        .bind(target_id)
        .execute(pool)
        .await?;
        sqlx::query(
            "UPDATE account SET following_count = \
                 (SELECT count(*) FROM follow WHERE account_id = $1 AND state = 'accepted') \
             WHERE id = $1",
        )
        .bind(account_id)
        .execute(pool)
        .await?;
    }
    Ok(if resulting == "pending" {
        FollowOutcome::Requested
    } else {
        FollowOutcome::Following
    })
}

pub async fn unfollow(pool: &PgPool, account_id: &str, target_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM follow WHERE account_id = $1 AND target_account_id = $2")
        .bind(account_id)
        .bind(target_id)
        .execute(pool)
        .await?;
    sqlx::query(
        "UPDATE account SET followers_count = \
             (SELECT count(*) FROM follow WHERE target_account_id = $1 AND state = 'accepted') \
         WHERE id = $1",
    )
    .bind(target_id)
    .execute(pool)
    .await?;
    sqlx::query(
        "UPDATE account SET following_count = \
             (SELECT count(*) FROM follow WHERE account_id = $1 AND state = 'accepted') \
         WHERE id = $1",
    )
    .bind(account_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Accepts a pending follow request, if the target owns it.
pub async fn accept_follow(
    pool: &PgPool,
    target_id: &str,
    requester_id: &str,
) -> Result<bool, sqlx::Error> {
    let changed = sqlx::query(
        "UPDATE follow SET state = 'accepted' \
         WHERE account_id = $1 AND target_account_id = $2 AND state = 'pending'",
    )
    .bind(requester_id)
    .bind(target_id)
    .execute(pool)
    .await?
    .rows_affected()
        == 1;
    if changed {
        sqlx::query(
            "UPDATE account SET followers_count = \
                 (SELECT count(*) FROM follow WHERE target_account_id = $1 AND state = 'accepted') \
             WHERE id = $1",
        )
        .bind(target_id)
        .execute(pool)
        .await?;
        sqlx::query(
            "UPDATE account SET following_count = \
                 (SELECT count(*) FROM follow WHERE account_id = $1 AND state = 'accepted') \
             WHERE id = $1",
        )
        .bind(requester_id)
        .execute(pool)
        .await?;
    }
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
                a.header_ref, a.locked, a.bot, a.local, a.uri, a.followers_count, \
                a.following_count, a.statuses_count, a.last_status_at, a.suspended_at, a.created_at \
           FROM follow f JOIN account a ON a.id = f.account_id \
          WHERE f.target_account_id = $1 AND f.state = 'accepted' \
            AND ($2::text IS NULL OR f.id < $2) \
          ORDER BY f.id DESC LIMIT $3"
    } else {
        "SELECT a.id, a.username::text, a.domain::text, a.display_name, a.note, a.avatar_ref, \
                a.header_ref, a.locked, a.bot, a.local, a.uri, a.followers_count, \
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
pub async fn notify(
    pool: &PgPool,
    account_id: &str,
    kind: &str,
    from_account_id: &str,
    status_id: Option<&str>,
) -> Result<(), sqlx::Error> {
    if account_id == from_account_id {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO notification (id, account_id, kind, from_account_id, status_id) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Id::new().to_string())
    .bind(account_id)
    .bind(kind)
    .bind(from_account_id)
    .bind(status_id)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, FromRow)]
pub struct NotificationRow {
    pub id: String,
    pub kind: String,
    pub account_id: String,
    pub from_account_id: String,
    pub status_id: Option<String>,
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
        "SELECT id, kind, account_id, from_account_id, status_id, seen_at, created_at \
           FROM notification \
          WHERE account_id = $1 \
            AND ($2::text IS NULL OR id < $2) \
            AND (cardinality($3::text[]) = 0 OR kind = ANY($3)) \
          ORDER BY id DESC LIMIT $4",
    )
    .bind(account_id)
    .bind(max_id)
    .bind(kinds)
    .bind(limit)
    .fetch_all(pool)
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
