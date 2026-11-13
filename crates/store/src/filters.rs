//! Client-owned keyword filters.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

use nodus_server_core::Id;

#[derive(Debug, Clone, FromRow)]
pub struct FilterRow {
    pub id: String,
    pub account_id: String,
    pub title: String,
    pub context: Vec<String>,
    pub action: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct KeywordRow {
    pub id: String,
    pub filter_id: String,
    pub keyword: String,
    pub whole_word: bool,
}

pub async fn filters(
    pool: &PgPool,
    account_id: &str,
    limit: i64,
) -> Result<Vec<FilterRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, account_id, title, context, action, expires_at, created_at \
         FROM filter WHERE account_id = $1 ORDER BY created_at DESC LIMIT $2",
    )
    .bind(account_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn filter(
    pool: &PgPool,
    account_id: &str,
    id: &str,
) -> Result<Option<FilterRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, account_id, title, context, action, expires_at, created_at \
         FROM filter WHERE id = $1 AND account_id = $2",
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
    context: &[String],
    action: &str,
    expires_at: Option<DateTime<Utc>>,
) -> Result<FilterRow, sqlx::Error> {
    sqlx::query_as(
        "INSERT INTO filter (id, account_id, title, context, action, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         RETURNING id, account_id, title, context, action, expires_at, created_at",
    )
    .bind(Id::new().to_string())
    .bind(account_id)
    .bind(title)
    .bind(context)
    .bind(action)
    .bind(expires_at)
    .fetch_one(pool)
    .await
}

pub async fn update(
    pool: &PgPool,
    account_id: &str,
    id: &str,
    title: &str,
    context: &[String],
    action: &str,
    expires_at: Option<DateTime<Utc>>,
) -> Result<Option<FilterRow>, sqlx::Error> {
    sqlx::query_as(
        "UPDATE filter SET title = $3, context = $4, action = $5, expires_at = $6 \
         WHERE id = $1 AND account_id = $2 \
         RETURNING id, account_id, title, context, action, expires_at, created_at",
    )
    .bind(id)
    .bind(account_id)
    .bind(title)
    .bind(context)
    .bind(action)
    .bind(expires_at)
    .fetch_optional(pool)
    .await
}

pub async fn delete(pool: &PgPool, account_id: &str, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM filter WHERE id = $1 AND account_id = $2")
        .bind(id)
        .bind(account_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn keywords(pool: &PgPool, filter_id: &str) -> Result<Vec<KeywordRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, filter_id, keyword, whole_word FROM filter_keyword \
         WHERE filter_id = $1 ORDER BY keyword",
    )
    .bind(filter_id)
    .fetch_all(pool)
    .await
}

pub async fn add_keyword(
    pool: &PgPool,
    filter_id: &str,
    keyword: &str,
    whole_word: bool,
) -> Result<KeywordRow, sqlx::Error> {
    sqlx::query_as(
        "INSERT INTO filter_keyword (id, filter_id, keyword, whole_word) VALUES ($1, $2, $3, $4) \
         RETURNING id, filter_id, keyword, whole_word",
    )
    .bind(Id::new().to_string())
    .bind(filter_id)
    .bind(keyword)
    .bind(whole_word)
    .fetch_one(pool)
    .await
}

pub async fn delete_keyword(
    pool: &PgPool,
    account_id: &str,
    filter_id: &str,
    keyword_id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM filter_keyword k USING filter f \
         WHERE k.id = $3 AND k.filter_id = $2 AND f.id = k.filter_id AND f.account_id = $1",
    )
    .bind(account_id)
    .bind(filter_id)
    .bind(keyword_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
