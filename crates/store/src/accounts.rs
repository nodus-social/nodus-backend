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
#[allow(clippy::struct_excessive_bools)]
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
    pub inbox_url: Option<String>,
    pub shared_inbox_url: Option<String>,
    pub public_key_pem: Option<String>,
    pub private_key_pem: Option<String>,
    pub discoverable: bool,
    pub indexable: bool,
    pub admin: bool,
    pub lossless_images_default: bool,
    pub lossless_videos_default: bool,
    pub lossless_images_allowed: bool,
    pub lossless_videos_allowed: bool,
    pub followers_count: i64,
    pub following_count: i64,
    pub statuses_count: i64,
    pub last_status_at: Option<DateTime<Utc>>,
    pub suspended_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

const ACCOUNT_COLUMNS_ALIASED: &str = "a.id, a.username::text AS username, a.domain::text AS domain, \
     a.display_name, a.note, a.avatar_ref, a.header_ref, a.fields, a.locked, a.bot, a.local, a.uri, \
     a.inbox_url, a.shared_inbox_url, a.public_key_pem, a.private_key_pem, a.discoverable, a.indexable, a.admin, \
     a.lossless_images_default, a.lossless_videos_default, a.lossless_images_allowed, \
     a.lossless_videos_allowed, a.followers_count, a.following_count, a.statuses_count, a.last_status_at, a.suspended_at, a.created_at";

const ACCOUNT_COLUMNS: &str = "id, username::text AS username, domain::text AS domain, \
     display_name, note, avatar_ref, header_ref, fields, locked, bot, local, uri, \
     inbox_url, shared_inbox_url, public_key_pem, private_key_pem, discoverable, indexable, admin, \
     lossless_images_default, lossless_videos_default, lossless_images_allowed, \
     lossless_videos_allowed, followers_count, following_count, statuses_count, last_status_at, suspended_at, created_at";

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
                    && scope
                        .get(granted.len()..)
                        .is_some_and(|rest| rest.starts_with(':')))
        })
    }
}

/// Resolves a bearer token by its SHA-256 digest.
pub async fn verify_token(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<Authenticated>, sqlx::Error> {
    let sql = format!(
        "SELECT {ACCOUNT_COLUMNS_ALIASED}, t.scopes FROM oauth_token t \
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
    sqlx::query_as::<_, AccountRow>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// A local account by username (`@alice`, without the domain).
pub async fn local_by_username(
    pool: &PgPool,
    username: &str,
) -> Result<Option<AccountRow>, sqlx::Error> {
    let sql =
        format!("SELECT {ACCOUNT_COLUMNS} FROM account WHERE domain IS NULL AND username = $1");
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

/// Writes the actor identity a local account needs to be resolvable by a peer.
///
/// The URI is written once. Changing it after a remote server has cached the actor
/// would break every existing follow, so a later call leaves an existing URI alone.
pub async fn set_actor_identity(
    pool: &PgPool,
    id: &str,
    uri: &str,
    public_key_pem: &str,
    private_key_pem: &str,
    inbox_url: &str,
    shared_inbox_url: Option<&str>,
) -> Result<AccountRow, sqlx::Error> {
    let sql = format!(
        "UPDATE account SET uri = COALESCE(uri, $2), public_key_pem = $3, \
             private_key_pem = $4, inbox_url = COALESCE(inbox_url, $5), \
             shared_inbox_url = COALESCE(shared_inbox_url, $6), updated_at = now() \
         WHERE id = $1 RETURNING {ACCOUNT_COLUMNS}"
    );
    sqlx::query_as::<_, AccountRow>(&sql)
        .bind(id)
        .bind(uri)
        .bind(public_key_pem)
        .bind(private_key_pem)
        .bind(inbox_url)
        .bind(shared_inbox_url)
        .fetch_one(pool)
        .await
}

/// Updates the two discovery switches Mastodon's account settings expose: whether the
/// profile may be recommended, and whether search engines may index it.
pub async fn update_discovery(
    pool: &PgPool,
    id: &str,
    discoverable: bool,
    indexable: bool,
) -> Result<AccountRow, sqlx::Error> {
    let sql = format!(
        "UPDATE account SET discoverable = $2, indexable = $3, updated_at = now() \
         WHERE id = $1 RETURNING {ACCOUNT_COLUMNS}"
    );
    sqlx::query_as::<_, AccountRow>(&sql)
        .bind(id)
        .bind(discoverable)
        .bind(indexable)
        .fetch_one(pool)
        .await
}

/// Update the account's default lossless preference per media kind.
pub async fn set_media_preferences(
    pool: &PgPool,
    id: &str,
    lossless_images: bool,
    lossless_videos: bool,
) -> Result<Option<AccountRow>, sqlx::Error> {
    let sql = format!(
        "UPDATE account SET lossless_images_default = $2, lossless_videos_default = $3 \
         WHERE id = $1 RETURNING {ACCOUNT_COLUMNS}"
    );
    sqlx::query_as::<_, AccountRow>(&sql)
        .bind(id)
        .bind(lossless_images)
        .bind(lossless_videos)
        .fetch_optional(pool)
        .await
}

/// Grant or revoke administrator access.
pub async fn set_admin(pool: &PgPool, id: &str, admin: bool) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("UPDATE account SET admin = $2 WHERE id = $1")
        .bind(id)
        .bind(admin)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() == 1)
}

/// Limit or grant lossless uploads per media kind.
pub async fn set_lossless_permissions(
    pool: &PgPool,
    id: &str,
    images: bool,
    videos: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE account SET lossless_images_allowed = $2, lossless_videos_allowed = $3 \
         WHERE id = $1",
    )
    .bind(id)
    .bind(images)
    .bind(videos)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}
