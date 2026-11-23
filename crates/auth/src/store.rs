//! Auth storage boundary.
//!
//! The service only needs a handful of queries. They are expressed as a trait so the
//! Postgres implementation can be replaced by the future database service without
//! changing the handlers.

use std::future::Future;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use thiserror::Error;

use crate::outbox::{self, Confirmation};

#[derive(Debug, Error)]
pub enum Error {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// Why a self-service registration was refused.
///
/// The name clashes are separated from storage errors because the form re-renders with a
/// message about the field that caused it, and "that username is taken" is a different
/// repair than "the database is down".
#[derive(Debug, Error)]
pub enum RegisterError {
    #[error("that username is already taken")]
    UsernameTaken,
    #[error("that email address already has a login")]
    EmailTaken,
    #[error(transparent)]
    Database(#[from] Error),
}

impl From<sqlx::Error> for RegisterError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(Error::Database(error))
    }
}

/// What a live IP block says about the network a request came from.
///
/// Declared here rather than in the store crate because this service's only view of the
/// blocks is this three-way answer; it never lists or edits them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpBlockVerdict {
    /// No request from the network may reach the instance.
    NoAccess,
    /// Registration is refused; an existing login is unaffected.
    SignUpBlock,
    /// Registration is accepted into the approval queue.
    RequiresApproval,
}

impl IpBlockVerdict {
    fn from_severity(severity: &str) -> Option<Self> {
        Some(match severity {
            "no_access" => Self::NoAccess,
            "sign_up_block" => Self::SignUpBlock,
            "sign_up_requires_approval" => Self::RequiresApproval,
            _ => return None,
        })
    }
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
    pub client_secret_hash: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SessionAccount {
    pub account_id: String,
    pub username: String,
    pub display_name: String,
    pub admin: bool,
}

#[derive(Debug, Clone)]
pub struct AuthorizationCode {
    pub id: String,
    pub app_id: String,
    pub account_id: String,
    pub account_admin: bool,
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
        user_agent: &str,
        ip: Option<&str>,
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

    /// The strongest live block covering `prefix`, or `None` when the network is clear.
    ///
    /// `prefix` is the truncated address the session table would record. The block table
    /// stores CIDRs, so the database does the containment test and the expiry filter in one
    /// read: a lapsed block cannot be served from a cached decision.
    fn ip_block_verdict(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Option<IpBlockVerdict>, Error>> + Send;

    /// Creates a local account together with its password login.
    ///
    /// `confirmation` is queued in the same transaction as the account: the caller has
    /// already decided a real sender exists, and a confirmation that survives a rolled
    /// back registration would point at an account nobody has.
    #[allow(clippy::too_many_arguments)]
    fn register_local(
        &self,
        username: &str,
        email: &str,
        password_hash: &str,
        approved: bool,
        confirmation: Option<Confirmation>,
    ) -> impl Future<Output = Result<SessionAccount, RegisterError>> + Send;

    /// Marks an address confirmed and returns the username, or `None` when the token is
    /// unknown, expired or already used.
    fn confirm_email(
        &self,
        token_hash: &str,
    ) -> impl Future<Output = Result<Option<String>, Error>> + Send;
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
        Self::create_credential_with(&self.pool, account_id, email, password_hash).await
    }

    /// Attaches a password credential to an existing local account using the given executor.
    ///
    /// No confirmation message goes out from this path, so the address is recorded as
    /// confirmed at creation. The registration path is the one that can leave it NULL.
    pub async fn create_credential_with<'e>(
        executor: impl sqlx::PgExecutor<'e>,
        account_id: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO account_credential (account_id, email, password_hash, confirmed_at) \
             VALUES ($1, $2, $3, now())",
        )
        .bind(account_id)
        .bind(email)
        .bind(password_hash)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Whether an email already has a login.
    pub async fn has_credential(&self, email: &str) -> Result<bool, Error> {
        Self::has_credential_with(&self.pool, email).await
    }

    /// Whether an email already has a login, queried on the given executor.
    pub async fn has_credential_with<'e>(
        executor: impl sqlx::PgExecutor<'e>,
        email: &str,
    ) -> Result<bool, Error> {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM account_credential WHERE email = $1)")
                .bind(email)
                .fetch_one(executor)
                .await?;
        Ok(exists)
    }

    /// Whether an account already has a password login.
    pub async fn has_credential_for_account(&self, account_id: &str) -> Result<bool, Error> {
        Self::has_credential_for_account_with(&self.pool, account_id).await
    }

    /// Whether an account already has a password login, queried on the given executor.
    pub async fn has_credential_for_account_with<'e>(
        executor: impl sqlx::PgExecutor<'e>,
        account_id: &str,
    ) -> Result<bool, Error> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM account_credential WHERE account_id = $1)",
        )
        .bind(account_id)
        .fetch_one(executor)
        .await?;
        Ok(exists)
    }

    /// Deletes expired browser sessions and returns the number of rows removed.
    pub async fn delete_expired_sessions(&self) -> Result<u64, Error> {
        let result = sqlx::query("DELETE FROM auth_session WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Creates a local account with a password login in one transaction.
    ///
    /// The uniqueness checks run inside the transaction so a refused name leaves no
    /// orphaned account behind, and the two unique indexes stay the real guard against two
    /// people claiming one name at the same moment.
    ///
    /// Without a `confirmation` there is no message to answer, so the address is recorded
    /// as confirmed at creation. A NULL `confirmed_at` therefore always means "a link was
    /// sent and has not been followed", which is exactly what enforcement reads.
    pub async fn register_local_with(
        pool: &PgPool,
        username: &str,
        email: &str,
        password_hash: &str,
        approved: bool,
        confirmation: Option<Confirmation>,
    ) -> Result<SessionAccount, RegisterError> {
        let mut tx = pool.begin().await?;

        let username_taken: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM account WHERE username = $1 AND domain IS NULL)",
        )
        .bind(username)
        .fetch_one(&mut *tx)
        .await?;
        if username_taken {
            return Err(RegisterError::UsernameTaken);
        }

        let email_taken: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM account_credential WHERE email = $1)")
                .bind(email)
                .fetch_one(&mut *tx)
                .await?;
        if email_taken {
            return Err(RegisterError::EmailTaken);
        }

        let id = ulid::Ulid::new().to_string();
        sqlx::query(
            "INSERT INTO account (id, username, display_name, local, approved) \
             VALUES ($1, $2, $2, true, $3)",
        )
        .bind(&id)
        .bind(username)
        .bind(approved)
        .execute(&mut *tx)
        .await
        .map_err(name_clash)?;
        let confirmed_at = confirmation.is_none().then(Utc::now);
        sqlx::query(
            "INSERT INTO account_credential (account_id, email, password_hash, confirmed_at) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(&id)
        .bind(email)
        .bind(password_hash)
        .bind(confirmed_at)
        .execute(&mut *tx)
        .await
        .map_err(name_clash)?;

        if let Some(confirmation) = confirmation {
            sqlx::query(
                "INSERT INTO email_confirmation (token_hash, account_id, expires_at) \
                 VALUES ($1, $2, $3)",
            )
            .bind(&confirmation.token_hash)
            .bind(&id)
            .bind(confirmation.expires_at)
            .execute(&mut *tx)
            .await?;
            outbox::enqueue(&mut *tx, &confirmation.message).await?;
        }

        tx.commit().await?;

        Ok(SessionAccount {
            account_id: id,
            username: username.to_owned(),
            display_name: username.to_owned(),
            admin: false,
        })
    }

    /// Deletes expired `OAuth` authorization codes and returns the number of rows removed.
    pub async fn delete_expired_codes(&self) -> Result<u64, Error> {
        let result = sqlx::query("DELETE FROM oauth_code WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

/// Maps a unique-index violation onto the field that collided.
fn name_clash(error: sqlx::Error) -> RegisterError {
    if let sqlx::Error::Database(database) = &error {
        if database.code().as_deref() == Some("23505") {
            return match database.constraint() {
                Some("account_credential_email_key") => RegisterError::EmailTaken,
                _ => RegisterError::UsernameTaken,
            };
        }
    }
    RegisterError::Database(Error::Database(error))
}

impl AuthStore for PgAuthStore {
    async fn credential_by_email(&self, email: &str) -> Result<Option<Credential>, Error> {
        let row = sqlx::query_as::<_, (String, String, String, String, String)>(
            "SELECT c.account_id, a.username::text, a.display_name, c.email::text, c.password_hash \
             FROM account_credential c JOIN account a ON a.id = c.account_id \
             WHERE c.email = $1 AND a.suspended_at IS NULL AND a.deleted_at IS NULL",
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

    async fn register_local(
        &self,
        username: &str,
        email: &str,
        password_hash: &str,
        approved: bool,
        confirmation: Option<Confirmation>,
    ) -> Result<SessionAccount, RegisterError> {
        Self::register_local_with(&self.pool, username, email, password_hash, approved, confirmation)
            .await
    }

    async fn ip_block_verdict(
        &self,
        prefix: &str,
    ) -> Result<Option<IpBlockVerdict>, Error> {
        let severity: Option<String> = sqlx::query_scalar(
            "SELECT severity FROM ip_block \
             WHERE (expires_at IS NULL OR expires_at > now()) AND $1::inet <<= ip::inet \
             ORDER BY CASE severity WHEN 'no_access' THEN 0 WHEN 'sign_up_block' THEN 1 ELSE 2 END \
             LIMIT 1",
        )
        .bind(prefix)
        .fetch_optional(&self.pool)
        .await?;
        Ok(severity.as_deref().and_then(IpBlockVerdict::from_severity))
    }

    async fn confirm_email(&self, token: &str) -> Result<Option<String>, Error> {
        let mut tx = self.pool.begin().await?;
        let account_id: Option<String> = sqlx::query_scalar(
            "UPDATE email_confirmation SET used_at = now() \
             WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() \
             RETURNING account_id",
        )
        .bind(token)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(account_id) = account_id else {
            return Ok(None);
        };
        sqlx::query(
            "UPDATE account_credential SET confirmed_at = COALESCE(confirmed_at, now()) \
             WHERE account_id = $1",
        )
        .bind(&account_id)
        .execute(&mut *tx)
        .await?;
        let username: String =
            sqlx::query_scalar("SELECT username::text FROM account WHERE id = $1")
                .bind(&account_id)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(Some(username))
    }

    async fn client_app(&self, client_id: &str) -> Result<Option<ClientApp>, Error> {
        let row = sqlx::query_as::<_, (String, String, String, String, Vec<String>, Vec<String>)>(
            "SELECT id, client_id, client_secret_hash, name, redirect_uris, scopes FROM oauth_app WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(
            |(id, client_id, client_secret_hash, name, redirect_uris, scopes)| ClientApp {
                id,
                client_id,
                client_secret_hash,
                name,
                redirect_uris,
                scopes,
            },
        ))
    }

    async fn create_session(
        &self,
        token_hash: &str,
        account_id: &str,
        expires_at: DateTime<Utc>,
        user_agent: &str,
        ip: Option<&str>,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO auth_session \
                 (id, account_id, token_hash, expires_at, user_agent, ip, last_used_at) \
             VALUES ($1, $2, $3, $4, $5, $6, now())",
        )
        .bind(new_id())
        .bind(account_id)
        .bind(token_hash)
        .bind(expires_at)
        .bind(user_agent)
        .bind(ip)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn session_account(&self, token_hash: &str) -> Result<Option<SessionAccount>, Error> {
        // A session is used on every page load, but "last used" only has to be true to a
        // minute. The conditional UPDATE matches nothing until the stored value is stale,
        // so two requests in the same minute cost one write, not two.
        let _ = sqlx::query(
            "UPDATE auth_session SET last_used_at = now() \
             WHERE token_hash = $1 \
               AND (last_used_at IS NULL OR last_used_at < now() - interval '60 seconds')",
        )
        .bind(token_hash)
        .execute(&self.pool)
        .await;

        let row = sqlx::query_as::<_, (String, String, String, bool)>(
            "SELECT a.id, a.username::text, a.display_name, a.admin \
             FROM auth_session s JOIN account a ON a.id = s.account_id \
             WHERE s.token_hash = $1 AND s.expires_at > now() AND a.suspended_at IS NULL \
               AND a.deleted_at IS NULL AND a.approved",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(
            |(account_id, username, display_name, admin)| SessionAccount {
                account_id,
                username,
                display_name,
                admin,
            },
        ))
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
        let row = sqlx::query_as::<_, (String, String, String, bool, String, Vec<String>, String)>(
            "UPDATE oauth_code c SET consumed_at = now() \
             FROM account a \
             WHERE c.code_hash = $1 AND c.consumed_at IS NULL AND c.expires_at > now() \
               AND a.id = c.account_id AND a.suspended_at IS NULL AND a.deleted_at IS NULL \
               AND a.approved \
             RETURNING c.id, c.app_id, c.account_id, a.admin, c.redirect_uri, c.scopes, c.code_challenge",
        )
        .bind(code_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(
            |(id, app_id, account_id, account_admin, redirect_uri, scopes, code_challenge)| {
                AuthorizationCode {
                    id,
                    app_id,
                    account_id,
                    account_admin,
                    redirect_uri,
                    scopes,
                    code_challenge,
                }
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
