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
