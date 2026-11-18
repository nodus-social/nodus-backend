//! Polls: one per status, with one row of votes per account per chosen option.
//!
//! The poll is an attachment of the status, not a status of its own. A vote is a row, so
//! counting is `GROUP BY option_index`, and the primary key `(poll_id, account_id,
//! option_index)` makes a retried vote idempotent rather than a second vote.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use sqlx::types::Json;
use sqlx::{FromRow, PgPool};

/// One poll, with the local/remote flag of the status it belongs to.
#[derive(Debug, Clone, FromRow)]
pub struct PollRow {
    pub id: String,
    pub status_id: String,
    pub options: Json<Vec<String>>,
    pub multiple: bool,
    pub hide_totals: bool,
    pub expires_at: Option<DateTime<Utc>>,
    /// False when the owning status was federated in; its poll is read-only here.
    pub local: bool,
}

#[derive(Debug, Clone)]
pub struct NewPoll<'a> {
    pub id: &'a str,
    pub status_id: &'a str,
    pub options: &'a [String],
    pub multiple: bool,
    pub hide_totals: bool,
    pub expires_at: Option<DateTime<Utc>>,
}

const COLUMNS: &str = "p.id, p.status_id, p.options, p.multiple, p.hide_totals, \
     p.expires_at, s.local";

/// Inserts the poll attached to an existing status.
pub async fn create(pool: &PgPool, new: &NewPoll<'_>) -> Result<PollRow, sqlx::Error> {
    sqlx::query(
        "INSERT INTO poll (id, status_id, options, multiple, hide_totals, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(new.id)
    .bind(new.status_id)
    .bind(Json(new.options.to_vec()))
    .bind(new.multiple)
    .bind(new.hide_totals)
    .bind(new.expires_at)
    .execute(pool)
    .await?;
    by_id(pool, new.id).await?.ok_or(sqlx::Error::RowNotFound)
}

/// A poll by its own id; deleted statuses take their polls with them.
pub async fn by_id(pool: &PgPool, id: &str) -> Result<Option<PollRow>, sqlx::Error> {
    sqlx::query_as::<_, PollRow>(&format!(
        "SELECT {COLUMNS} FROM poll p JOIN status s ON s.id = p.status_id \
         WHERE p.id = $1 AND s.deleted_at IS NULL"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// The poll attached to a status, if it has one.
pub async fn by_status(pool: &PgPool, status_id: &str) -> Result<Option<PollRow>, sqlx::Error> {
    sqlx::query_as::<_, PollRow>(&format!(
        "SELECT {COLUMNS} FROM poll p JOIN status s ON s.id = p.status_id \
         WHERE p.status_id = $1 AND s.deleted_at IS NULL"
    ))
    .bind(status_id)
    .fetch_optional(pool)
    .await
}

/// Every poll attached to a page of statuses, keyed by status id.
pub async fn by_status_ids(
    pool: &PgPool,
    status_ids: &[String],
) -> Result<HashMap<String, PollRow>, sqlx::Error> {
    if status_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = sqlx::query_as::<_, PollRow>(&format!(
        "SELECT {COLUMNS} FROM poll p JOIN status s ON s.id = p.status_id \
         WHERE p.status_id = ANY($1) AND s.deleted_at IS NULL"
    ))
    .bind(status_ids)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| (row.status_id.clone(), row))
        .collect())
}

#[derive(Debug, Clone, Copy, FromRow)]
pub struct OptionCount {
    pub option_index: i32,
    pub votes: i64,
}

/// Votes per option, for the options that have at least one.
pub async fn option_counts(pool: &PgPool, poll_id: &str) -> Result<Vec<OptionCount>, sqlx::Error> {
    sqlx::query_as::<_, OptionCount>(
        "SELECT option_index, count(*) AS votes FROM poll_vote \
         WHERE poll_id = $1 GROUP BY option_index ORDER BY option_index",
    )
    .bind(poll_id)
    .fetch_all(pool)
    .await
}

/// How many distinct accounts voted, whatever they chose.
pub async fn voters_count(pool: &PgPool, poll_id: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(DISTINCT account_id) FROM poll_vote WHERE poll_id = $1")
        .bind(poll_id)
        .fetch_one(pool)
        .await
}

/// The options this account chose, ascending.
pub async fn own_votes(
    pool: &PgPool,
    poll_id: &str,
    account_id: &str,
) -> Result<Vec<i32>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT option_index FROM poll_vote WHERE poll_id = $1 AND account_id = $2 \
         ORDER BY option_index",
    )
    .bind(poll_id)
    .bind(account_id)
    .fetch_all(pool)
    .await
}

pub async fn has_voted(
    pool: &PgPool,
    poll_id: &str,
    account_id: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM poll_vote WHERE poll_id = $1 AND account_id = $2)",
    )
    .bind(poll_id)
    .bind(account_id)
    .fetch_one(pool)
    .await
}

/// Records a vote, once.
///
/// A poll row is locked first so two requests from one account cannot both pass the
/// "has this account voted" check; the unique key is the second line of defence. An
/// account that already voted keeps its original choice and this returns `false` — a
/// client that retries a vote gets the same poll back instead of a duplicate.
pub async fn vote(
    pool: &PgPool,
    poll_id: &str,
    account_id: &str,
    choices: &[i32],
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT id FROM poll WHERE id = $1 FOR UPDATE")
        .bind(poll_id)
        .fetch_one(&mut *tx)
        .await?;
    let already: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM poll_vote WHERE poll_id = $1 AND account_id = $2)",
    )
    .bind(poll_id)
    .bind(account_id)
    .fetch_one(&mut *tx)
    .await?;
    if already {
        tx.commit().await?;
        return Ok(false);
    }
    for index in choices {
        sqlx::query(
            "INSERT INTO poll_vote (poll_id, account_id, option_index) VALUES ($1, $2, $3) \
             ON CONFLICT DO NOTHING",
        )
        .bind(poll_id)
        .bind(account_id)
        .bind(index)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(true)
}
