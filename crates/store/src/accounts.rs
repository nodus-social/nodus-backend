//! Accounts and token verification.
//!
//! Token verification is here rather than in a middleware crate because the same
//! query answers two questions that must not disagree: *who is this* and *what may
//! they do*. A suspended account's token is rejected in the same predicate that
//! resolves its scopes.

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sqlx::{FromRow, PgPool};

use nodus_server_core::client_metadata::{validate_key, ClientMetadataError};
use nodus_server_core::limits::{
    CLIENT_METADATA_MAX_BYTES, CLIENT_METADATA_MAX_KEYS, PAGE_MAX_ACCOUNTS,
};
use nodus_server_core::{Id, PageOrder, PageParams, PageSize};

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
    pub client_metadata: Value,
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
    pub approved: bool,
    pub lossless_images_default: bool,
    pub lossless_videos_default: bool,
    pub lossless_images_allowed: bool,
    pub lossless_videos_allowed: bool,
    pub followers_count: i64,
    pub following_count: i64,
    pub statuses_count: i64,
    pub last_status_at: Option<DateTime<Utc>>,
    pub suspended_at: Option<DateTime<Utc>>,
    pub silenced_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

pub(crate) const ACCOUNT_COLUMNS_ALIASED: &str = "a.id, a.username::text AS username, a.domain::text AS domain, \
     a.display_name, a.note, a.avatar_ref, a.header_ref, a.fields, a.client_metadata, a.locked, a.bot, a.local, a.uri, \
     a.inbox_url, a.shared_inbox_url, a.public_key_pem, a.private_key_pem, a.discoverable, a.indexable, a.admin, a.approved, \
     a.lossless_images_default, a.lossless_videos_default, a.lossless_images_allowed, \
     a.lossless_videos_allowed, a.followers_count, a.following_count, a.statuses_count, a.last_status_at, a.suspended_at, a.silenced_at, a.created_at";

pub(crate) const ACCOUNT_COLUMNS: &str = "id, username::text AS username, domain::text AS domain, \
     display_name, note, avatar_ref, header_ref, fields, client_metadata, locked, bot, local, uri, \
     inbox_url, shared_inbox_url, public_key_pem, private_key_pem, discoverable, indexable, admin, approved, \
     lossless_images_default, lossless_videos_default, lossless_images_allowed, \
     lossless_videos_allowed, followers_count, following_count, statuses_count, last_status_at, suspended_at, silenced_at, created_at";

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
         WHERE t.token_hash = $1 AND t.revoked_at IS NULL AND a.suspended_at IS NULL \
           AND a.approved"
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

/// One account by its canonical `ActivityPub` actor URL.
pub async fn by_uri(pool: &PgPool, uri: &str) -> Result<Option<AccountRow>, sqlx::Error> {
    let sql = format!("SELECT {ACCOUNT_COLUMNS} FROM account WHERE uri = $1");
    sqlx::query_as::<_, AccountRow>(&sql)
        .bind(uri)
        .fetch_optional(pool)
        .await
}

/// A remote actor learned from an inbound activity.
#[derive(Debug, Clone)]
pub struct RemoteAccount<'a> {
    pub uri: &'a str,
    pub username: &'a str,
    pub domain: &'a str,
    pub display_name: &'a str,
    pub note: &'a str,
    pub avatar: Option<&'a str>,
    pub inbox_url: Option<&'a str>,
    pub shared_inbox_url: Option<&'a str>,
    pub public_key_pem: Option<&'a str>,
    pub locked: bool,
    pub bot: bool,
}

/// Inserts or refreshes a remote actor by its canonical URI.
pub async fn upsert_remote(
    pool: &PgPool,
    remote: &RemoteAccount<'_>,
) -> Result<AccountRow, sqlx::Error> {
    let sql = format!(
        "INSERT INTO account (id, username, domain, display_name, note, avatar_ref, local, uri, \
             inbox_url, shared_inbox_url, public_key_pem, locked, bot) \
         VALUES ($1, $2, $3, $4, $5, $6, false, $7, $8, $9, $10, $11, $12) \
         ON CONFLICT (uri) DO UPDATE SET display_name = EXCLUDED.display_name, note = EXCLUDED.note, \
             avatar_ref = COALESCE(EXCLUDED.avatar_ref, account.avatar_ref), \
             inbox_url = COALESCE(EXCLUDED.inbox_url, account.inbox_url), \
             shared_inbox_url = COALESCE(EXCLUDED.shared_inbox_url, account.shared_inbox_url), \
             public_key_pem = COALESCE(EXCLUDED.public_key_pem, account.public_key_pem), \
             locked = EXCLUDED.locked, bot = EXCLUDED.bot, updated_at = now() \
         RETURNING {ACCOUNT_COLUMNS}"
    );
    sqlx::query_as::<_, AccountRow>(&sql)
        .bind(Id::new().to_string())
        .bind(remote.username)
        .bind(remote.domain)
        .bind(remote.display_name)
        .bind(remote.note)
        .bind(remote.avatar)
        .bind(remote.uri)
        .bind(remote.inbox_url)
        .bind(remote.shared_inbox_url)
        .bind(remote.public_key_pem)
        .bind(remote.locked)
        .bind(remote.bot)
        .fetch_one(pool)
        .await
}

/// A local account by username (`@alice`, without the domain).
pub async fn local_by_username<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    username: &str,
) -> Result<Option<AccountRow>, sqlx::Error> {
    let sql =
        format!("SELECT {ACCOUNT_COLUMNS} FROM account WHERE domain IS NULL AND username = $1");
    sqlx::query_as::<_, AccountRow>(&sql)
        .bind(username)
        .fetch_optional(executor)
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
pub async fn insert<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    new: &NewAccount<'_>,
) -> Result<AccountRow, sqlx::Error> {
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
        .fetch_one(executor)
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
pub async fn set_admin<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    id: &str,
    admin: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("UPDATE account SET admin = $2 WHERE id = $1")
        .bind(id)
        .bind(admin)
        .execute(executor)
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

/// A page of accounts from a follow list, with the `follow.id` cursor for the next page.
#[derive(Debug, Clone)]
pub struct FollowPage {
    pub items: Vec<AccountRow>,
    pub next_max_id: Option<String>,
}

#[derive(Debug, FromRow)]
struct FollowAccountRow {
    follow_id: String,
    #[sqlx(flatten)]
    account: AccountRow,
}

/// Followers or following, ordered by the follow edge id (`f.id`). Full account rows so
/// the API can reuse `AccountDto` without a second query per row.
pub async fn follow_page(
    pool: &PgPool,
    account_id: &str,
    followers: bool,
    params: PageParams,
) -> Result<FollowPage, sqlx::Error> {
    let size = PageSize::clamp(params.limit, PAGE_MAX_ACCOUNTS);
    let max_id = params.max_id.map(|id| id.to_string());
    let lower_id = params.lower_bound().map(|id| id.to_string());
    let order = match params.order() {
        PageOrder::NewestFirst => "DESC",
        PageOrder::OldestFirst => "ASC",
    };
    let (join_col, filter_col) = if followers {
        ("f.account_id", "f.target_account_id")
    } else {
        ("f.target_account_id", "f.account_id")
    };
    let sql = format!(
        "SELECT f.id AS follow_id, {ACCOUNT_COLUMNS_ALIASED} \
           FROM follow f JOIN account a ON a.id = {join_col} \
          WHERE {filter_col} = $1 AND f.state = 'accepted' \
            AND ($2::text IS NULL OR f.id < $2) \
            AND ($3::text IS NULL OR f.id > $3) \
          ORDER BY f.id {order} LIMIT $4"
    );
    let mut rows = sqlx::query_as::<_, FollowAccountRow>(&sql)
        .bind(account_id)
        .bind(max_id)
        .bind(lower_id)
        .bind(size.as_i64() + 1)
        .fetch_all(pool)
        .await?;
    let limit = usize::try_from(size.get()).unwrap_or(usize::from(u16::MAX));
    let next_max_id = if rows.len() > limit {
        rows.truncate(limit);
        rows.last().map(|row| row.follow_id.clone())
    } else {
        None
    };
    Ok(FollowPage {
        items: rows.into_iter().map(|row| row.account).collect(),
        next_max_id,
    })
}

/// Resolves `user` or `user@domain` to a local account.
pub async fn lookup(pool: &PgPool, acct: &str) -> Result<Option<AccountRow>, sqlx::Error> {
    let mut parts = acct.trim_start_matches('@').split('@');
    let username = parts.next().unwrap_or_default();
    let domain = parts.next();
    let sql = format!(
        "SELECT {ACCOUNT_COLUMNS} FROM account \
          WHERE username = $1 AND (($2::text IS NULL AND domain IS NULL) OR domain = $2)"
    );
    sqlx::query_as::<_, AccountRow>(&sql)
        .bind(username)
        .bind(domain)
        .fetch_optional(pool)
        .await
}

/// Local account search by username, display name and bio.
pub async fn search_local(
    pool: &PgPool,
    query: &str,
    limit: i64,
) -> Result<Vec<AccountRow>, sqlx::Error> {
    let pattern = format!("%{}%", query.trim());
    let sql = format!(
        "SELECT {ACCOUNT_COLUMNS} FROM account \
          WHERE domain IS NULL AND suspended_at IS NULL \
            AND (username ILIKE $1 OR display_name ILIKE $1 OR note ILIKE $1) \
          ORDER BY (username ILIKE $2) DESC, followers_count DESC, username ASC LIMIT $3"
    );
    sqlx::query_as::<_, AccountRow>(&sql)
        .bind(&pattern)
        .bind(format!("{}%", query.trim()))
        .bind(limit)
        .fetch_all(pool)
        .await
}

/// Errors from updating or clearing per-account client metadata.
#[derive(Debug, thiserror::Error)]
pub enum ClientMetadataStoreError {
    #[error("account not found")]
    AccountNotFound,
    #[error(transparent)]
    Validation(#[from] ClientMetadataError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

fn validate_metadata_map(map: &Map<String, Value>) -> Result<Value, ClientMetadataStoreError> {
    if map.len() > CLIENT_METADATA_MAX_KEYS {
        return Err(ClientMetadataError::TooManyKeys.into());
    }
    let json_value = Value::Object(map.clone());
    let serialized = serde_json::to_vec(&json_value).map_err(|error| {
        sqlx::Error::Protocol(format!("failed to serialize client metadata: {error}"))
    })?;
    if serialized.len() > CLIENT_METADATA_MAX_BYTES {
        return Err(ClientMetadataError::PayloadTooLarge.into());
    }
    Ok(json_value)
}

/// Reads all client metadata entries for an account.
pub async fn client_metadata_all(
    pool: &PgPool,
    account_id: &str,
) -> Result<Option<Map<String, Value>>, sqlx::Error> {
    let raw: Option<Value> =
        sqlx::query_scalar("SELECT client_metadata FROM account WHERE id = $1")
            .bind(account_id)
            .fetch_optional(pool)
            .await?;
    Ok(raw.map(|value| match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }))
}

/// Reads a requested subset of client metadata keys for an account.
pub async fn client_metadata_get_keys(
    pool: &PgPool,
    account_id: &str,
    keys: &[String],
) -> Result<Option<Map<String, Value>>, sqlx::Error> {
    let Some(all) = client_metadata_all(pool, account_id).await? else {
        return Ok(None);
    };
    let mut filtered = Map::new();
    for key in keys {
        if let Some(value) = all.get(key).filter(|value| !value.is_null()) {
            filtered.insert(key.clone(), value.clone());
        }
    }
    Ok(Some(filtered))
}

/// Reads a single client metadata key for an account.
pub async fn client_metadata_get_key(
    pool: &PgPool,
    account_id: &str,
    key: &str,
) -> Result<Option<Value>, sqlx::Error> {
    let value: Option<Option<Value>> =
        sqlx::query_scalar("SELECT client_metadata -> $2 FROM account WHERE id = $1")
            .bind(account_id)
            .bind(key)
            .fetch_optional(pool)
            .await?;
    Ok(value.flatten().filter(|val| !val.is_null()))
}

/// Atomically merges client metadata entries for an account (`null` values remove keys).
pub async fn client_metadata_patch(
    pool: &PgPool,
    account_id: &str,
    entries: &Map<String, Value>,
) -> Result<Map<String, Value>, ClientMetadataStoreError> {
    for key in entries.keys() {
        validate_key(key)?;
    }
    let mut tx = pool.begin().await?;
    let current: Option<Value> =
        sqlx::query_scalar("SELECT client_metadata FROM account WHERE id = $1 FOR UPDATE")
            .bind(account_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(current) = current else {
        return Err(ClientMetadataStoreError::AccountNotFound);
    };
    let mut map = match current {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    for (key, value) in entries {
        if value.is_null() {
            map.remove(key);
        } else {
            map.insert(key.clone(), value.clone());
        }
    }
    let json_value = validate_metadata_map(&map)?;
    sqlx::query("UPDATE account SET client_metadata = $2, updated_at = now() WHERE id = $1")
        .bind(account_id)
        .bind(json_value)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(map)
}

/// Replaces all client metadata entries for an account (top-level `null` values are omitted).
pub async fn client_metadata_replace(
    pool: &PgPool,
    account_id: &str,
    entries: &Map<String, Value>,
) -> Result<Map<String, Value>, ClientMetadataStoreError> {
    let mut map = Map::new();
    for (key, value) in entries {
        validate_key(key)?;
        if !value.is_null() {
            map.insert(key.clone(), value.clone());
        }
    }
    let json_value = validate_metadata_map(&map)?;
    let updated =
        sqlx::query("UPDATE account SET client_metadata = $2, updated_at = now() WHERE id = $1")
            .bind(account_id)
            .bind(json_value)
            .execute(pool)
            .await?;
    if updated.rows_affected() == 0 {
        return Err(ClientMetadataStoreError::AccountNotFound);
    }
    Ok(map)
}

/// Sets or updates a single client metadata key for an account.
pub async fn client_metadata_set_key(
    pool: &PgPool,
    account_id: &str,
    key: &str,
    value: Value,
) -> Result<Map<String, Value>, ClientMetadataStoreError> {
    let mut entries = Map::new();
    entries.insert(key.to_owned(), value);
    client_metadata_patch(pool, account_id, &entries).await
}

/// Removes the specified client metadata keys for an account.
pub async fn client_metadata_delete_keys(
    pool: &PgPool,
    account_id: &str,
    keys: &[String],
) -> Result<Map<String, Value>, ClientMetadataStoreError> {
    let mut entries = Map::new();
    for key in keys {
        entries.insert(key.clone(), Value::Null);
    }
    client_metadata_patch(pool, account_id, &entries).await
}

/// Clears all client metadata entries for an account.
pub async fn client_metadata_clear(
    pool: &PgPool,
    account_id: &str,
) -> Result<(), ClientMetadataStoreError> {
    let updated = sqlx::query(
        "UPDATE account SET client_metadata = '{}'::jsonb, updated_at = now() WHERE id = $1",
    )
    .bind(account_id)
    .execute(pool)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ClientMetadataStoreError::AccountNotFound);
    }
    Ok(())
}
