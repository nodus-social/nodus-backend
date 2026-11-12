//! Accounts and token verification.
//!
//! Token verification is here rather than in a middleware crate because the same
//! query answers two questions that must not disagree: *who is this* and *what may
//! they do*. A suspended account's token is rejected in the same predicate that
//! resolves its scopes.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgPool};

use nodus_server_core::Id;

/// A row of `account`, with `citext` cast to `text`.
///
/// The cast is not cosmetic: sqlx has no codec for `citext`, and a `String` column
/// read through a `citext` OID fails at runtime rather than at compile time.
#[derive(Debug, Clone, FromRow)]
pub struct AccountRow {
    pub id: String,
    pub username: String,
    pub domain: Option<String>,
    pub display_name: String,
    pub note: String,
    pub avatar_ref: Option<String>,
    pub header_ref: Option<String>,
    pub fields: Value,
    pub locked: bool,
    pub bot: bool,
    pub local: bool,
    pub uri: Option<String>,
    pub followers_count: i64,
    pub following_count: i64,
    pub statuses_count: i64,
    pub last_status_at: Option<DateTime<Utc>>,
    pub suspended_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

const ACCOUNT_COLUMNS: &str = "id, username::text AS username, domain::text AS domain, \
     display_name, note, avatar_ref, header_ref, fields, locked, bot, local, uri, \
     followers_count, following_count, statuses_count, last_status_at, suspended_at, created_at";

/// A token verified against an account.
#[derive(Debug, Clone, FromRow)]
pub struct Authenticated {
    #[sqlx(flatten)]
    pub account: AccountRow,
    pub scopes: Vec<String>,
}

impl Authenticated {
    /// Mastodon's scopes are hierarchical: `write` implies `write:statuses`. A token
    /// without the exact scope but with its family is accepted, which is what clients
    /// that request only `write` expect.
    #[must_use]
    pub fn allows(&self, scope: &str) -> bool {
        self.scopes.iter().any(|granted| {
            granted == scope
                || granted == "read write follow push"
                || (scope.starts_with(granted.as_str())
                    && scope.get(granted.len()..).is_some_and(|rest| rest.starts_with(':')))
        })
    }
}

/// Resolves a bearer token by its SHA-256 digest.
pub async fn verify_token(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<Authenticated>, sqlx::Error> {
    let sql = format!(
        "SELECT {ACCOUNT_COLUMNS}, t.scopes FROM oauth_token t \
         JOIN account a ON a.id = t.account_id \
         WHERE t.token_hash = $1 AND t.revoked_at IS NULL AND a.suspended_at IS NULL"
    );
    let row = sqlx::query_as::<_, Authenticated>(&sql)
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;
    if row.is_some() {
        // Best-effort: a failed stamp must not fail the request it authenticates.
        let _ = sqlx::query("UPDATE oauth_token SET last_used_at = now() WHERE token_hash = $1")
            .bind(token_hash)
            .execute(pool)
            .await;
    }
    Ok(row)
}

/// One account by id, local or remote.
pub async fn by_id(pool: &PgPool, id: &str) -> Result<Option<AccountRow>, sqlx::Error> {
    let sql = format!("SELECT {ACCOUNT_COLUMNS} FROM account WHERE id = $1");
    sqlx::query_as::<_, AccountRow>(&sql).bind(id).fetch_optional(pool).await
}

/// A local account by username (`@alice`, without the domain).
pub async fn local_by_username(
    pool: &PgPool,
    username: &str,
) -> Result<Option<AccountRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {ACCOUNT_COLUMNS} FROM account WHERE domain IS NULL AND username = $1"
    );
    sqlx::query_as::<_, AccountRow>(&sql)
        .bind(username)
        .fetch_optional(pool)
        .await
}

/// What creating a local account needs. The id is minted here, not in the caller.
#[derive(Debug, Clone)]
pub struct NewAccount<'a> {
    pub username: &'a str,
    pub display_name: &'a str,
    pub note: &'a str,
    pub bot: bool,
    pub locked: bool,
}

/// Creates a local account.
pub async fn insert(pool: &PgPool, new: &NewAccount<'_>) -> Result<AccountRow, sqlx::Error> {
    let id = Id::new().to_string();
    let sql = format!(
        "INSERT INTO account (id, username, display_name, note, bot, locked, local) \
         VALUES ($1, $2, $3, $4, $5, $6, true) RETURNING {ACCOUNT_COLUMNS}"
    );
    sqlx::query_as::<_, AccountRow>(&sql)
        .bind(&id)
        .bind(new.username)
        .bind(new.display_name)
        .bind(new.note)
        .bind(new.bot)
        .bind(new.locked)
        .fetch_one(pool)
        .await
}
