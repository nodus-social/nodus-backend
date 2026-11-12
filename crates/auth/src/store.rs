//! Auth storage boundary.
//!
//! The service only needs a handful of queries. They are expressed as a trait so the
//! Postgres implementation can be replaced by the future database service without
//! changing the handlers.

use std::future::Future;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, Clone)]
pub struct Credential {
    pub account_id: String,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub password_hash: String,
}

#[derive(Debug, Clone)]
pub struct ClientApp {
    pub id: String,
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SessionAccount {
    pub account_id: String,
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Clone)]
pub struct AuthorizationCode {
    pub id: String,
    pub app_id: String,
    pub account_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: String,
}

pub trait AuthStore: Clone + Send + Sync + 'static {
    fn credential_by_email(
        &self,
        email: &str,
    ) -> impl Future<Output = Result<Option<Credential>, Error>> + Send;

    fn client_app(
        &self,
        client_id: &str,
    ) -> impl Future<Output = Result<Option<ClientApp>, Error>> + Send;

    fn create_session(
        &self,
        token_hash: &str,
        account_id: &str,
        expires_at: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    fn session_account(
        &self,
        token_hash: &str,
    ) -> impl Future<Output = Result<Option<SessionAccount>, Error>> + Send;

    fn delete_session(&self, token_hash: &str) -> impl Future<Output = Result<(), Error>> + Send;

    #[allow(clippy::too_many_arguments)]
    fn create_code(
        &self,
        code_hash: &str,
        app_id: &str,
        account_id: &str,
        redirect_uri: &str,
        scopes: &[String],
        code_challenge: &str,
        expires_at: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    fn consume_code(
        &self,
        code_hash: &str,
    ) -> impl Future<Output = Result<Option<AuthorizationCode>, Error>> + Send;

    fn issue_token(
        &self,
        token_hash: &str,
        app_id: &str,
        account_id: &str,
        scopes: &[String],
    ) -> impl Future<Output = Result<(), Error>> + Send;

    fn revoke_token(&self, token_hash: &str) -> impl Future<Output = Result<(), Error>> + Send;
}

#[derive(Clone)]
pub struct PgAuthStore {
    pool: PgPool,
}

impl PgAuthStore {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Attaches a password credential to an existing local account.
    pub async fn create_credential(
        &self,
        account_id: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO account_credential (account_id, email, password_hash) VALUES ($1, $2, $3)",
        )
        .bind(account_id)
        .bind(email)
        .bind(password_hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Whether an email already has a login.
    pub async fn has_credential(&self, email: &str) -> Result<bool, Error> {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM account_credential WHERE email = $1)")
                .bind(email)
                .fetch_one(&self.pool)
                .await?;
        Ok(exists)
    }
}

impl AuthStore for PgAuthStore {
    async fn credential_by_email(&self, email: &str) -> Result<Option<Credential>, Error> {
        let row = sqlx::query_as::<_, (String, String, String, String, String)>(
            "SELECT c.account_id, a.username::text, a.display_name, c.email::text, c.password_hash \
             FROM account_credential c JOIN account a ON a.id = c.account_id \
             WHERE c.email = $1 AND a.suspended_at IS NULL",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(
            |(account_id, username, display_name, email, password_hash)| Credential {
                account_id,
                username,
                display_name,
                email,
                password_hash,
            },
        ))
    }

    async fn client_app(&self, client_id: &str) -> Result<Option<ClientApp>, Error> {
        let row = sqlx::query_as::<_, (String, String, String, Vec<String>, Vec<String>)>(
            "SELECT id, client_id, name, redirect_uris, scopes FROM oauth_app WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(
            row.map(|(id, client_id, name, redirect_uris, scopes)| ClientApp {
                id,
                client_id,
                name,
                redirect_uris,
                scopes,
            }),
        )
    }

    async fn create_session(
        &self,
        token_hash: &str,
        account_id: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO auth_session (id, account_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(new_id())
        .bind(account_id)
        .bind(token_hash)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn session_account(&self, token_hash: &str) -> Result<Option<SessionAccount>, Error> {
        let row = sqlx::query_as::<_, (String, String, String)>(
            "SELECT a.id, a.username::text, a.display_name \
             FROM auth_session s JOIN account a ON a.id = s.account_id \
             WHERE s.token_hash = $1 AND s.expires_at > now() AND a.suspended_at IS NULL",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(
            row.map(|(account_id, username, display_name)| SessionAccount {
                account_id,
                username,
                display_name,
            }),
        )
    }

    async fn delete_session(&self, token_hash: &str) -> Result<(), Error> {
        sqlx::query("DELETE FROM auth_session WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn create_code(
        &self,
        code_hash: &str,
        app_id: &str,
        account_id: &str,
        redirect_uri: &str,
        scopes: &[String],
        code_challenge: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO oauth_code (id, app_id, account_id, code_hash, redirect_uri, scopes, code_challenge, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(new_id())
        .bind(app_id)
        .bind(account_id)
        .bind(code_hash)
        .bind(redirect_uri)
        .bind(scopes)
        .bind(code_challenge)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn consume_code(&self, code_hash: &str) -> Result<Option<AuthorizationCode>, Error> {
        let row = sqlx::query_as::<_, (String, String, String, String, Vec<String>, String)>(
            "UPDATE oauth_code SET consumed_at = now() \
             WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > now() \
             RETURNING id, app_id, account_id, redirect_uri, scopes, code_challenge",
        )
        .bind(code_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(
            |(id, app_id, account_id, redirect_uri, scopes, code_challenge)| AuthorizationCode {
                id,
                app_id,
                account_id,
                redirect_uri,
                scopes,
                code_challenge,
            },
        ))
    }

    async fn issue_token(
        &self,
        token_hash: &str,
        app_id: &str,
        account_id: &str,
        scopes: &[String],
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO oauth_token (id, app_id, account_id, token_hash, scopes) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(new_id())
        .bind(app_id)
        .bind(account_id)
        .bind(token_hash)
        .bind(scopes)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn revoke_token(&self, token_hash: &str) -> Result<(), Error> {
        sqlx::query("UPDATE oauth_token SET revoked_at = now() WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn new_id() -> String {
    ulid::Ulid::new().to_string().to_lowercase()
}
