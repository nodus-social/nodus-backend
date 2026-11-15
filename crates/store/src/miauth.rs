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

/// Creates or refreshes a pending `MiAuth` session.
pub async fn upsert_session(
    pool: &PgPool,
    session_id: &str,
    app_name: &str,
    callback: Option<&str>,
    scopes: &[String],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO miauth_session (id, app_name, callback, scopes) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (id) DO UPDATE SET app_name = EXCLUDED.app_name, \
             callback = EXCLUDED.callback, scopes = EXCLUDED.scopes",
    )
    .bind(session_id)
    .bind(app_name)
    .bind(callback)
    .bind(scopes)
    .execute(pool)
    .await?;
    Ok(())
}

/// Approves an unexpired `MiAuth` session and issues its bearer token atomically.
///
/// Returns `Ok(false)` when the session does not exist or has already expired.
pub async fn approve_session(
    pool: &PgPool,
    session_id: &str,
    account_id: &str,
    token: &str,
    token_hash: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let row: Option<(Vec<String>,)> =
        sqlx::query_as("SELECT scopes FROM miauth_session WHERE id = $1 AND expires_at > now()")
            .bind(session_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((scopes,)) = row else {
        return Ok(false);
    };

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
    Ok(true)
}

/// Reads the approval status of a `MiAuth` session.
pub async fn session_status(
    pool: &PgPool,
    session_id: &str,
) -> Result<Option<MiauthSession>, sqlx::Error> {
    sqlx::query_as::<_, MiauthSession>(
        "SELECT token, account_id, expires_at FROM miauth_session WHERE id = $1",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await
}
