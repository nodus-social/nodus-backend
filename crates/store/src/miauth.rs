//! `MiAuth` session persistence and OAuth token issuance.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

use nodus_server_core::Id;

const MIAUTH_APP_ID: &str = "misskey-miauth";

/// Current state of a `MiAuth` session.
#[derive(Debug, Clone, FromRow)]
pub struct MiauthSession {
    pub token: Option<String>,
    pub account_id: Option<String>,
    pub expires_at: DateTime<Utc>,
}

/// Outcome of approving a `MiAuth` session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproveStatus {
    Approved,
    NotFound,
    AdminRequired,
}

/// Outcome of polling/consuming a `MiAuth` session.
#[derive(Debug, Clone)]
pub enum SessionCheck {
    Ready(MiauthSession),
    Pending,
    Unknown,
}

/// Creates a new pending `MiAuth` session. Returns `false` if the session id already exists.
pub async fn create_session(
    pool: &PgPool,
    session_id: &str,
    app_name: &str,
    callback: Option<&str>,
    scopes: &[String],
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO miauth_session (id, app_name, callback, scopes) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(session_id)
    .bind(app_name)
    .bind(callback)
    .bind(scopes)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Approves an unexpired, unapproved `MiAuth` session and issues its bearer token atomically.
pub async fn approve_session(
    pool: &PgPool,
    session_id: &str,
    account_id: &str,
    is_admin: bool,
    token: &str,
    token_hash: &str,
) -> Result<ApproveStatus, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let row: Option<(Vec<String>,)> = sqlx::query_as(
        "SELECT scopes FROM miauth_session \
         WHERE id = $1 AND expires_at > now() AND token IS NULL \
         FOR UPDATE",
    )
    .bind(session_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((scopes,)) = row else {
        return Ok(ApproveStatus::NotFound);
    };

    if !is_admin
        && scopes
            .iter()
            .any(|scope| scope == "admin" || scope.starts_with("admin:"))
    {
        return Ok(ApproveStatus::AdminRequired);
    }

    sqlx::query(
        "INSERT INTO oauth_app (id, client_id, client_secret_hash, name, redirect_uris, scopes) \
         VALUES ($1, $1, 'unused', 'MiAuth', '{}', $2) ON CONFLICT (id) DO NOTHING",
    )
    .bind(MIAUTH_APP_ID)
    .bind(&scopes)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO oauth_token (id, app_id, account_id, token_hash, scopes) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Id::new().to_string())
    .bind(MIAUTH_APP_ID)
    .bind(account_id)
    .bind(token_hash)
    .bind(&scopes)
    .execute(&mut *tx)
    .await?;

    sqlx::query("UPDATE miauth_session SET account_id = $2, token = $3 WHERE id = $1")
        .bind(session_id)
        .bind(account_id)
        .bind(token)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(ApproveStatus::Approved)
}

/// Atomically consumes an approved `MiAuth` session so its token can only be retrieved once.
pub async fn consume_session(pool: &PgPool, session_id: &str) -> Result<SessionCheck, sqlx::Error> {
    let row = sqlx::query_as::<_, MiauthSession>(
        "DELETE FROM miauth_session \
         WHERE id = $1 AND token IS NOT NULL \
         RETURNING token, account_id, expires_at",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?;
    if let Some(session) = row {
        return Ok(SessionCheck::Ready(session));
    }
    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM miauth_session WHERE id = $1 AND expires_at > now())",
    )
    .bind(session_id)
    .fetch_one(pool)
    .await?;
    if pending {
        Ok(SessionCheck::Pending)
    } else {
        Ok(SessionCheck::Unknown)
    }
}
