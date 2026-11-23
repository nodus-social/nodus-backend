//! OAuth application registration.
//!
//! The raw secret is returned exactly once. Only its digest is stored, so a database
//! leak does not hand an attacker every client credential.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

#[derive(Debug, Clone, FromRow)]
pub struct OAuthAppRow {
    pub id: String,
    pub client_id: String,
    pub name: String,
    pub website: Option<String>,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[allow(clippy::too_many_arguments)]
pub async fn register(
    pool: &PgPool,
    id: &str,
    client_id: &str,
    client_secret_hash: &str,
    name: &str,
    website: Option<&str>,
    redirect_uris: &[String],
    scopes: &[String],
) -> Result<OAuthAppRow, sqlx::Error> {
    sqlx::query_as::<_, OAuthAppRow>(
        "INSERT INTO oauth_app \
             (id, client_id, client_secret_hash, name, website, redirect_uris, scopes) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING id, client_id, name, website, redirect_uris, scopes, created_at",
    )
    .bind(id)
    .bind(client_id)
    .bind(client_secret_hash)
    .bind(name)
    .bind(website)
    .bind(redirect_uris)
    .bind(scopes)
    .fetch_one(pool)
    .await
}

/// The digest stored for a registered client.
pub async fn secret_hash(pool: &PgPool, client_id: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT client_secret_hash FROM oauth_app WHERE client_id = $1")
        .bind(client_id)
        .fetch_optional(pool)
        .await
}

/// One live app token, joined to the application that was granted it.
#[derive(Debug, Clone, FromRow)]
pub struct AuthorizationRow {
    pub id: String,
    /// The digest of the bearer token. Never serialised.
    pub token_hash: String,
    pub app_name: String,
    pub app_website: Option<String>,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// App tokens of this account that have not been revoked, newest first.
pub async fn list_authorizations(
    pool: &PgPool,
    account_id: &str,
) -> Result<Vec<AuthorizationRow>, sqlx::Error> {
    sqlx::query_as::<_, AuthorizationRow>(
        "SELECT t.id, t.token_hash, a.name AS app_name, a.website AS app_website, \
                t.scopes, t.created_at, t.last_used_at \
         FROM oauth_token t JOIN oauth_app a ON a.id = t.app_id \
         WHERE t.account_id = $1 AND t.revoked_at IS NULL \
         ORDER BY t.created_at DESC",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await
}

/// Revokes one app token of this account. `false` means no live row for this account.
pub async fn revoke_authorization(
    pool: &PgPool,
    account_id: &str,
    id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE oauth_token SET revoked_at = now() \
         WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(account_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
