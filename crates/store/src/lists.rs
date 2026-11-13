//! Client-owned lists of followed accounts.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

use nodus_server_core::Id;

#[derive(Debug, Clone, FromRow)]
pub struct ListRow {
    pub id: String,
    pub account_id: String,
    pub title: String,
    pub replies_policy: String,
    pub exclusive: bool,
    pub created_at: DateTime<Utc>,
}

pub async fn lists(
    pool: &PgPool,
    account_id: &str,
    limit: i64,
) -> Result<Vec<ListRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, account_id, title, replies_policy, exclusive, created_at \
         FROM list WHERE account_id = $1 ORDER BY created_at DESC LIMIT $2",
    )
    .bind(account_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn list(
    pool: &PgPool,
    account_id: &str,
    id: &str,
) -> Result<Option<ListRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, account_id, title, replies_policy, exclusive, created_at \
         FROM list WHERE id = $1 AND account_id = $2",
    )
    .bind(id)
    .bind(account_id)
    .fetch_optional(pool)
    .await
}

pub async fn create(
    pool: &PgPool,
    account_id: &str,
    title: &str,
    replies_policy: &str,
    exclusive: bool,
) -> Result<ListRow, sqlx::Error> {
    sqlx::query_as(
        "INSERT INTO list (id, account_id, title, replies_policy, exclusive) \
         VALUES ($1, $2, $3, $4, $5) \
         RETURNING id, account_id, title, replies_policy, exclusive, created_at",
    )
    .bind(Id::new().to_string())
    .bind(account_id)
    .bind(title)
    .bind(replies_policy)
    .bind(exclusive)
    .fetch_one(pool)
    .await
}

pub async fn update(
    pool: &PgPool,
    account_id: &str,
    id: &str,
    title: &str,
    replies_policy: &str,
    exclusive: bool,
) -> Result<Option<ListRow>, sqlx::Error> {
    sqlx::query_as(
        "UPDATE list SET title = $3, replies_policy = $4, exclusive = $5 \
         WHERE id = $1 AND account_id = $2 \
         RETURNING id, account_id, title, replies_policy, exclusive, created_at",
    )
    .bind(id)
    .bind(account_id)
    .bind(title)
    .bind(replies_policy)
    .bind(exclusive)
    .fetch_optional(pool)
    .await
}

pub async fn delete(pool: &PgPool, account_id: &str, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM list WHERE id = $1 AND account_id = $2")
        .bind(id)
        .bind(account_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn account_ids(
    pool: &PgPool,
    list_id: &str,
    limit: i64,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT account_id FROM list_account WHERE list_id = $1 \
         ORDER BY created_at DESC LIMIT $2",
    )
    .bind(list_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn add_account(
    pool: &PgPool,
    list_id: &str,
    account_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO list_account (list_id, account_id) VALUES ($1, $2) \
         ON CONFLICT (list_id, account_id) DO NOTHING",
    )
    .bind(list_id)
    .bind(account_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn remove_account(
    pool: &PgPool,
    list_id: &str,
    account_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM list_account WHERE list_id = $1 AND account_id = $2")
        .bind(list_id)
        .bind(account_id)
        .execute(pool)
        .await?;
    Ok(())
}
