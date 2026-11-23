//! Browser sessions a reader can see and sign out.
//!
//! The login page writes these rows; the settings API lists and removes them. The token
//! digest stays on the row so a request can name its own session without trusting a flag
//! the client sent.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

#[derive(Debug, Clone, FromRow)]
pub struct SessionRow {
    pub id: String,
    /// The digest of the cookie that made this session. Never serialised.
    pub token_hash: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub user_agent: String,
    pub ip: Option<String>,
}

/// Sessions that can still be presented, newest first.
pub async fn list(pool: &PgPool, account_id: &str) -> Result<Vec<SessionRow>, sqlx::Error> {
    sqlx::query_as::<_, SessionRow>(
        "SELECT id, token_hash, created_at, last_used_at, user_agent, ip \
         FROM auth_session WHERE account_id = $1 AND expires_at > now() \
         ORDER BY created_at DESC",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await
}

/// Removes one session of this account. `false` means no such row for this account.
pub async fn revoke(pool: &PgPool, account_id: &str, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM auth_session WHERE id = $1 AND account_id = $2")
        .bind(id)
        .bind(account_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Removes every session except `keep`, the caller's own.
pub async fn revoke_others(
    pool: &PgPool,
    account_id: &str,
    keep: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM auth_session WHERE account_id = $1 AND id <> $2")
        .bind(account_id)
        .bind(keep)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Removes every session of the account, including the caller's.
pub async fn revoke_all(pool: &PgPool, account_id: &str) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM auth_session WHERE account_id = $1")
        .bind(account_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}
