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
    pub avatar_url: Option<String>,
    pub header_url: Option<String>,
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
    /// `none`, `moderator` or `admin`. The role decides which doors open; the token's
    /// scopes say what may be done once one does. `admin` above is kept as its mirror.
    pub staff_role: String,
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
    pub moved_to: Option<String>,
    pub also_known_as: Vec<String>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub purge_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

pub(crate) const ACCOUNT_COLUMNS_ALIASED: &str = "a.id, a.username::text AS username, a.domain::text AS domain, \
     a.display_name, a.note, a.avatar_ref, a.header_ref, a.avatar_url, a.header_url, a.fields, a.client_metadata, a.locked, a.bot, a.local, a.uri, \
     a.inbox_url, a.shared_inbox_url, a.public_key_pem, a.private_key_pem, a.discoverable, a.indexable, a.admin, a.staff_role, a.approved, \
     a.lossless_images_default, a.lossless_videos_default, a.lossless_images_allowed, \
     a.lossless_videos_allowed, a.followers_count, a.following_count, a.statuses_count, a.last_status_at, a.suspended_at, a.silenced_at, a.moved_to, a.also_known_as, \
     a.deleted_at, a.purge_at, a.created_at";

pub(crate) const ACCOUNT_COLUMNS: &str = "id, username::text AS username, domain::text AS domain, \
     display_name, note, avatar_ref, header_ref, avatar_url, header_url, fields, client_metadata, locked, bot, local, uri, \
     inbox_url, shared_inbox_url, public_key_pem, private_key_pem, discoverable, indexable, admin, staff_role, approved, \
     lossless_images_default, lossless_videos_default, lossless_images_allowed, \
     lossless_videos_allowed, followers_count, following_count, statuses_count, last_status_at, suspended_at, silenced_at, moved_to, also_known_as, deleted_at, purge_at, created_at";

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

/// Resolves a bearer token by its SHA-256 digest, refusing a restricted account.
pub async fn verify_token(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<Authenticated>, sqlx::Error> {
    let sql = format!(
        "SELECT {ACCOUNT_COLUMNS_ALIASED}, t.scopes FROM oauth_token t \
         JOIN account a ON a.id = t.account_id \
         WHERE t.token_hash = $1 AND t.revoked_at IS NULL AND a.suspended_at IS NULL \
           AND a.deleted_at IS NULL AND a.approved"
    );
    resolve_token(pool, &sql, token_hash).await
}

/// The same resolution with the state predicates dropped.
///
/// Only the appeal endpoints use this: a suspended or refused person still owns the
/// token and must be able to read and answer their own appeal, while every other route
/// keeps refusing the token through [`verify_token`]. Silence never blocked the token in
/// the first place, so this only widens it for suspension and refusal.
pub async fn verify_token_any_state(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<Authenticated>, sqlx::Error> {
    let sql = format!(
        "SELECT {ACCOUNT_COLUMNS_ALIASED}, t.scopes FROM oauth_token t \
         JOIN account a ON a.id = t.account_id \
         WHERE t.token_hash = $1 AND t.revoked_at IS NULL"
    );
    resolve_token(pool, &sql, token_hash).await
}

async fn resolve_token(
    pool: &PgPool,
    sql: &str,
    token_hash: &str,
) -> Result<Option<Authenticated>, sqlx::Error> {
    let row = sqlx::query_as::<_, Authenticated>(sql)
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

/// Removes an account and everything it owns.
///
/// Every table that points at `account` either cascades or nulls out, so the single
/// delete is the whole purge; the transaction exists so a foreign key added later that
/// does neither fails the purge instead of leaving half an account behind.
pub async fn purge(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let removed = sqlx::query("DELETE FROM account WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        == 1;
    tx.commit().await?;
    Ok(removed)
}

/// Marks a local account deleted and cuts its access immediately.
///
/// The row survives: it is the tombstone that keeps a stale activity from creating a new
/// account under the same URI, and the profile fields are erased later by
/// [`purge_due`]. Tokens and sessions die now, because a deleted account must not act while
/// it waits for the purge.
pub async fn request_deletion(
    pool: &PgPool,
    id: &str,
    purge_at: DateTime<Utc>,
) -> Result<Option<AccountRow>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let sql = format!(
        "UPDATE account SET deleted_at = COALESCE(deleted_at, now()), \
             purge_at = CASE WHEN deleted_at IS NULL THEN $2 ELSE purge_at END, \
             updated_at = now() \
          WHERE id = $1 AND local RETURNING {ACCOUNT_COLUMNS}"
    );
    let row = sqlx::query_as::<_, AccountRow>(&sql)
        .bind(id)
        .bind(purge_at)
        .fetch_optional(&mut *tx)
        .await?;
    if row.is_some() {
        sqlx::query(
            "UPDATE oauth_token SET revoked_at = COALESCE(revoked_at, now()) WHERE account_id = $1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM auth_session WHERE account_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM oauth_code WHERE account_id = $1 AND consumed_at IS NULL")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(row)
}

/// Reverses a deletion inside the grace window.
///
/// Only the tombstone is cleared. Tokens stay revoked and sessions stay gone: undoing a
/// deletion with the token that performed it would make the deletion reversible by theft.
pub async fn undelete(pool: &PgPool, id: &str) -> Result<Option<AccountRow>, sqlx::Error> {
    let sql = format!(
        "UPDATE account SET deleted_at = NULL, purge_at = NULL, updated_at = now() \
          WHERE id = $1 AND local AND deleted_at IS NOT NULL RETURNING {ACCOUNT_COLUMNS}"
    );
    sqlx::query_as::<_, AccountRow>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// Erases the profile, media references, credentials and tokens of due tombstones.
///
/// Returns the number of accounts erased, so the prune worker can log a non-zero pass and
/// stay quiet otherwise. Running it twice is safe: the second pass has nothing left to
/// select.
pub async fn purge_due(pool: &PgPool, limit: i64) -> Result<u64, sqlx::Error> {
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT a.id FROM account a \
          WHERE a.deleted_at IS NOT NULL AND a.purge_at IS NOT NULL AND a.purge_at <= now() \
            AND (a.display_name <> '' OR a.note <> '' OR a.avatar_ref IS NOT NULL \
                 OR a.header_ref IS NOT NULL OR a.avatar_url IS NOT NULL \
                 OR a.header_url IS NOT NULL OR a.fields <> '[]'::jsonb \
                 OR a.client_metadata <> '{}'::jsonb OR a.inbox_url IS NOT NULL \
                 OR a.shared_inbox_url IS NOT NULL OR a.public_key_pem IS NOT NULL \
                 OR a.private_key_pem IS NOT NULL OR a.moved_to IS NOT NULL \
                 OR a.also_known_as <> '{}' OR a.discoverable OR a.indexable \
                 OR EXISTS (SELECT 1 FROM account_credential c WHERE c.account_id = a.id) \
                 OR EXISTS (SELECT 1 FROM auth_session s WHERE s.account_id = a.id) \
                 OR EXISTS (SELECT 1 FROM oauth_token t WHERE t.account_id = a.id) \
                 OR EXISTS (SELECT 1 FROM oauth_code c WHERE c.account_id = a.id) \
                 OR EXISTS (SELECT 1 FROM media_attachment m WHERE m.account_id = a.id)) \
          ORDER BY a.purge_at LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let mut erased = 0_u64;
    for id in ids {
        let mut tx = pool.begin().await?;
        let row = sqlx::query(
            "UPDATE account SET display_name = '', note = '', avatar_ref = NULL, \
                 header_ref = NULL, avatar_url = NULL, header_url = NULL, \
                 fields = '[]'::jsonb, client_metadata = '{}'::jsonb, \
                 discoverable = false, indexable = false, moved_to = NULL, \
                 also_known_as = '{}', inbox_url = NULL, shared_inbox_url = NULL, \
                 public_key_pem = NULL, private_key_pem = NULL, updated_at = now() \
              WHERE id = $1 AND deleted_at IS NOT NULL",
        )
        .bind(&id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM account_credential WHERE account_id = $1")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM auth_session WHERE account_id = $1")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM oauth_code WHERE account_id = $1")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM oauth_token WHERE account_id = $1")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM media_attachment WHERE account_id = $1")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        if row.rows_affected() == 1 {
            erased += 1;
        }
    }
    Ok(erased)
}

/// Whether an account has requested deletion. Used by read paths that only have an id.
pub async fn is_deleted(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM account WHERE id = $1 AND deleted_at IS NOT NULL)",
    )
    .bind(id)
    .fetch_one(pool)
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
    /// A picture URL on the account's own instance; `avatar_ref` names a file we host.
    pub avatar_url: Option<&'a str>,
    pub header_url: Option<&'a str>,
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
        "INSERT INTO account (id, username, domain, display_name, note, avatar_url, header_url, \
             local, uri, inbox_url, shared_inbox_url, public_key_pem, locked, bot) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, false, $8, $9, $10, $11, $12, $13) \
         ON CONFLICT (uri) DO UPDATE SET display_name = EXCLUDED.display_name, note = EXCLUDED.note, \
             avatar_url = COALESCE(EXCLUDED.avatar_url, account.avatar_url), \
             header_url = COALESCE(EXCLUDED.header_url, account.header_url), \
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
        .bind(remote.avatar_url)
        .bind(remote.header_url)
        .bind(remote.uri)
        .bind(remote.inbox_url)
        .bind(remote.shared_inbox_url)
        .bind(remote.public_key_pem)
        .bind(remote.locked)
        .bind(remote.bot)
        .fetch_one(pool)
        .await
}

/// A remote actor's changed profile fields; `None` leaves a field as it was.
#[derive(Debug, Clone, Default)]
pub struct RemoteProfile<'a> {
    pub display_name: Option<&'a str>,
    pub note: Option<&'a str>,
    pub avatar_url: Option<&'a str>,
    pub header_url: Option<&'a str>,
}

/// The aliases a remote actor published in its document, replacing what we had.
pub async fn set_also_known_as(
    pool: &PgPool,
    uri: &str,
    aliases: &[String],
) -> Result<Option<AccountRow>, sqlx::Error> {
    let sql = format!(
        "UPDATE account SET also_known_as = $2 WHERE uri = $1 AND NOT local RETURNING {ACCOUNT_COLUMNS}"
    );
    sqlx::query_as::<_, AccountRow>(&sql)
        .bind(uri)
        .bind(aliases.to_vec())
        .fetch_optional(pool)
        .await
}

/// Records where a remote account moved, or clears it when `moved_to` is `None`.
pub async fn set_moved_to(
    pool: &PgPool,
    id: &str,
    moved_to: Option<&str>,
) -> Result<Option<AccountRow>, sqlx::Error> {
    let sql = format!(
        "UPDATE account SET moved_to = $2, updated_at = now() \
          WHERE id = $1 AND NOT local RETURNING {ACCOUNT_COLUMNS}"
    );
    sqlx::query_as::<_, AccountRow>(&sql)
        .bind(id)
        .bind(moved_to)
        .fetch_optional(pool)
        .await
}

/// Refreshes the profile of a remote actor we already know.
///
/// Returns `None` when the URI names no remote account, so a peer cannot reach a local
/// profile through an `Update`.
pub async fn update_remote_profile(
    pool: &PgPool,
    uri: &str,
    profile: &RemoteProfile<'_>,
) -> Result<Option<AccountRow>, sqlx::Error> {
    let sql = format!(
        "UPDATE account SET display_name = COALESCE($2, display_name), \
             note = COALESCE($3, note), avatar_url = COALESCE($4, avatar_url), \
             header_url = COALESCE($5, header_url), updated_at = now() \
          WHERE uri = $1 AND NOT local RETURNING {ACCOUNT_COLUMNS}"
    );
    sqlx::query_as::<_, AccountRow>(&sql)
        .bind(uri)
        .bind(profile.display_name)
        .bind(profile.note)
        .bind(profile.avatar_url)
        .bind(profile.header_url)
        .fetch_optional(pool)
        .await
}

/// A local account by username (`@alice`, without the domain).
pub async fn local_by_username<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    username: &str,
) -> Result<Option<AccountRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {ACCOUNT_COLUMNS} FROM account \
          WHERE domain IS NULL AND username = $1 AND deleted_at IS NULL"
    );
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
///
/// The boolean is no longer the grant: it mirrors the role, so granting means
/// administrator and revoking means no staff role at all.
pub async fn set_admin<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    id: &str,
    admin: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE account SET admin = $2, \
             staff_role = CASE WHEN $2 THEN 'admin' ELSE 'none' END \
         WHERE id = $1",
    )
    .bind(id)
    .bind(admin)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Sets the staff role and keeps the `admin` mirror in step.
pub async fn set_staff_role<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    id: &str,
    role: &str,
) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query("UPDATE account SET admin = $2 <> 'none', staff_role = $2 WHERE id = $1")
            .bind(id)
            .bind(role)
            .execute(executor)
            .await?;
    Ok(result.rows_affected() == 1)
}

/// How many accounts hold a role, used to refuse the last administrator's demotion.
pub async fn count_role(pool: &PgPool, role: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*)::bigint FROM account WHERE staff_role = $1")
        .bind(role)
        .fetch_one(pool)
        .await
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
          WHERE username = $1 AND (($2::text IS NULL AND domain IS NULL) OR domain = $2) \
            AND deleted_at IS NULL"
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

/// The parts of a profile its owner may change.
///
/// Every field is optional: a client sends the ones the reader touched, and `None` means
/// "leave it alone" rather than "clear it", which is what a partial update means.
#[derive(Debug, Default, Clone)]
pub struct ProfileUpdate<'a> {
    pub display_name: Option<&'a str>,
    pub note: Option<&'a str>,
    pub locked: Option<bool>,
    pub bot: Option<bool>,
    pub discoverable: Option<bool>,
    pub indexable: Option<bool>,
    /// A reference under `/media/`, such as `{id}/preview`, or `None` to keep the current
    /// picture.
    pub avatar_ref: Option<&'a str>,
    pub header_ref: Option<&'a str>,
}

/// Writes the parts of a profile that were sent.
pub async fn update_profile(
    pool: &PgPool,
    id: &str,
    update: &ProfileUpdate<'_>,
) -> Result<AccountRow, sqlx::Error> {
    let sql = format!(
        "UPDATE account SET \
            display_name = COALESCE($2, display_name), \
            note = COALESCE($3, note), \
            locked = COALESCE($4, locked), \
            bot = COALESCE($5, bot), \
            discoverable = COALESCE($6, discoverable), \
            indexable = COALESCE($7, indexable), \
            avatar_ref = COALESCE($8, avatar_ref), \
            header_ref = COALESCE($9, header_ref), \
            updated_at = now() \
          WHERE id = $1 RETURNING {ACCOUNT_COLUMNS}"
    );
    sqlx::query_as::<_, AccountRow>(&sql)
        .bind(id)
        .bind(update.display_name)
        .bind(update.note)
        .bind(update.locked)
        .bind(update.bot)
        .bind(update.discoverable)
        .bind(update.indexable)
        .bind(update.avatar_ref)
        .bind(update.header_ref)
        .fetch_one(pool)
        .await
}

/// Accounts the instance suggests, for the directory screen.
///
/// `order = "active"` puts the accounts that actually post first, which is what a reader
/// opening a directory wants; the default is by sign-up date, so a fresh profile with
/// nothing in it does not lead the list.
pub async fn directory(
    pool: &PgPool,
    local_only: bool,
    active_first: bool,
    offset: i64,
    limit: i64,
) -> Result<Vec<AccountRow>, sqlx::Error> {
    let order = if active_first {
        "last_status_at DESC NULLS LAST, followers_count DESC, username ASC"
    } else {
        "created_at DESC, username ASC"
    };
    let sql = format!(
        "SELECT {ACCOUNT_COLUMNS} FROM account \
          WHERE suspended_at IS NULL AND deleted_at IS NULL AND discoverable \
            AND ($1 = false OR domain IS NULL) \
          ORDER BY {order} OFFSET $2 LIMIT $3"
    );
    sqlx::query_as::<_, AccountRow>(&sql)
        .bind(local_only)
        .bind(offset)
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
/// The key we sign outgoing federation reads with.
///
/// `None` means no local account carries a private key yet, in which case callers send
/// unsigned requests and instances in authorised-fetch mode refuse them.
pub async fn local_signer(
    pool: &PgPool,
) -> Result<Option<(String, Option<String>, String)>, sqlx::Error> {
    sqlx::query_as::<_, (String, Option<String>, String)>(
        "SELECT username, uri, private_key_pem FROM account \
          WHERE domain IS NULL AND private_key_pem IS NOT NULL \
            AND suspended_at IS NULL AND deleted_at IS NULL \
          ORDER BY admin DESC, created_at ASC LIMIT 1",
    )
    .fetch_optional(pool)
    .await
}

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

/// Accounts worth following, for `GET /api/v2/suggestions`.
///
/// This is deliberately a simple query rather than a call into the recommender: a
/// suggestion endpoint that 404s is worse than one that ranks recently active local
/// accounts by follower count, and it stays correct when the recommender is down. The
/// viewer is never suggested, and neither is anyone either side has blocked or muted,
/// anyone already followed, or an account that moderation has suspended, silenced,
/// deleted or left unapproved.
pub async fn suggestions(
    pool: &PgPool,
    viewer_id: &str,
    limit: i64,
) -> Result<Vec<AccountRow>, sqlx::Error> {
    let sql = format!(
        "SELECT {columns} FROM account a \
          WHERE a.id <> $1 AND a.local AND a.approved AND a.discoverable \
            AND a.suspended_at IS NULL AND a.silenced_at IS NULL AND a.deleted_at IS NULL \
            AND NOT EXISTS ( \
                SELECT 1 FROM follow f \
                 WHERE f.account_id = $1 AND f.target_account_id = a.id) \
            AND NOT EXISTS ( \
                SELECT 1 FROM account_relation r \
                 WHERE r.kind IN ('block', 'mute') \
                   AND ((r.account_id = $1 AND r.target_account_id = a.id) \
                     OR (r.account_id = a.id AND r.target_account_id = $1))) \
          ORDER BY a.last_status_at DESC NULLS LAST, a.followers_count DESC, a.username ASC \
          LIMIT $2",
        columns = ACCOUNT_COLUMNS_ALIASED,
    );
    sqlx::query_as(&sql)
        .bind(viewer_id)
        .bind(limit)
        .fetch_all(pool)
        .await
}
