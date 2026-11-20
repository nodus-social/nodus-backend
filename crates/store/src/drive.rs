//! The cloud drive: folders, files, and the attachment that points at one.
//!
//! The drive is not the social graph. A file is a row here and the bytes are the blob
//! store's problem; a post that shows the file gets a `media_attachment` whose digest is
//! the same SHA-256, so the media layer serves it out of the store it already reads —
//! [`attach_object`] is the whole zero-copy path and it never touches a byte.
//!
//! Two rules hold every statement below:
//!
//! - `account_id` is the first predicate. The composite key `(account_id, id)` is the
//!   primary key of both tables, so two accounts may hold the same uuid and neither can
//!   read the other's row. That is also what lets the tables shard by account without a
//!   query rewrite.
//! - ids are `UUIDv7` minted here, not by a sequence. A shard cannot hand out a global
//!   counter, and a timestamp-ordered id keeps inserts appending to the index.

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

/// A row of `drive_folder`.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct DriveFolder {
    pub account_id: String,
    pub id: Uuid,
    /// `None` for a folder at the root of the drive.
    pub parent_id: Option<Uuid>,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A row of `drive_object`.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct DriveObject {
    pub account_id: String,
    pub id: Uuid,
    /// `None` for a file at the root of the drive.
    pub folder_id: Option<Uuid>,
    pub filename: String,
    pub mime_type: String,
    pub byte_size: i64,
    /// Lowercase hex SHA-256 of the bytes; the blob store's address for them.
    pub sha256: String,
    /// `private`, `unlisted_link` or `public_federated`. See [`Visibility`].
    pub visibility: String,
    /// `pending`, `ready` or `failed`. See [`ProcessingState`].
    pub processing_state: String,
    pub created_at: DateTime<Utc>,
}

/// Who may fetch an object.
///
/// A typed value rather than a free string, because the set is closed in the schema
/// (`CHECK (visibility IN (...))`) and a typo should not become a database error at the
/// edge of a request handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Private,
    UnlistedLink,
    PublicFederated,
}

impl Visibility {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::UnlistedLink => "unlisted_link",
            Self::PublicFederated => "public_federated",
        }
    }

    /// Parses the wire/storage spelling. `None` for anything the schema would refuse.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "private" => Some(Self::Private),
            "unlisted_link" => Some(Self::UnlistedLink),
            "public_federated" => Some(Self::PublicFederated),
            _ => None,
        }
    }
}

/// Whether an object's bytes are usable yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessingState {
    Pending,
    Ready,
    Failed,
}

impl ProcessingState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Failed => "failed",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "ready" => Some(Self::Ready),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Why a folder move was refused before anything was written.
#[derive(Debug, thiserror::Error)]
pub enum MoveError {
    /// The target parent is the folder itself or one of its descendants. Storing this
    /// would detach the subtree from the root into a cycle nothing can enumerate.
    #[error("a folder cannot be moved into itself or its own descendant")]
    Cycle,
    /// The folder, or the parent it names, does not exist in this account.
    #[error("folder not found")]
    NotFound,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

const FOLDER_COLUMNS: &str = "account_id, id, parent_id, name, created_at, updated_at";

const OBJECT_COLUMNS: &str = "account_id, id, folder_id, filename, mime_type, byte_size, \
     sha256, visibility, processing_state, created_at";

/// Creates a folder under `parent`, or at the root when `parent` is `None`.
///
/// The composite foreign key is the check that matters: a parent in another account is
/// not a parent, and the insert fails rather than filing a folder under a stranger.
pub async fn create_folder(
    pool: &PgPool,
    account: &str,
    parent: Option<Uuid>,
    name: &str,
) -> Result<DriveFolder, sqlx::Error> {
    let mut connection = pool.acquire().await?;
    create_folder_tx(&mut connection, account, parent, name).await
}

/// [`create_folder`] on a connection the caller already holds.
///
/// The writer runs this inside its batch's transaction, so the statement must not begin
/// one of its own; the pool wrapper above is the single-statement case.
pub(crate) async fn create_folder_tx(
    connection: &mut PgConnection,
    account: &str,
    parent: Option<Uuid>,
    name: &str,
) -> Result<DriveFolder, sqlx::Error> {
    let sql = format!(
        "INSERT INTO drive_folder (account_id, id, parent_id, name) \
         VALUES ($1, $2, $3, $4) RETURNING {FOLDER_COLUMNS}"
    );
    sqlx::query_as::<_, DriveFolder>(&sql)
        .bind(account)
        .bind(Uuid::now_v7())
        .bind(parent)
        .bind(name)
        .fetch_one(&mut *connection)
        .await
}

/// Every folder in the account, by name.
///
/// A drive's folder count is small enough that the tree is fetched whole and assembled by
/// the caller: one query beats one round trip per level.
pub async fn folders(pool: &PgPool, account: &str) -> Result<Vec<DriveFolder>, sqlx::Error> {
    let sql = format!(
        "SELECT {FOLDER_COLUMNS} FROM drive_folder \
         WHERE account_id = $1 ORDER BY lower(name) ASC, id ASC"
    );
    sqlx::query_as::<_, DriveFolder>(&sql)
        .bind(account)
        .fetch_all(pool)
        .await
}

/// Renames a folder. `false` when the account has no such folder.
pub async fn rename_folder(
    pool: &PgPool,
    account: &str,
    id: Uuid,
    name: &str,
) -> Result<bool, sqlx::Error> {
    let mut connection = pool.acquire().await?;
    rename_folder_tx(&mut connection, account, id, name).await
}

pub(crate) async fn rename_folder_tx(
    connection: &mut PgConnection,
    account: &str,
    id: Uuid,
    name: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE drive_folder SET name = $3, updated_at = now() \
         WHERE account_id = $1 AND id = $2",
    )
    .bind(account)
    .bind(id)
    .bind(name)
    .execute(&mut *connection)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Re-parents a folder, refusing a cycle.
///
/// The descendant test is a recursive walk of the folder's own subtree in one statement;
/// the row is then written in the same transaction, so a concurrent move cannot slip a
/// cycle in between the check and the update.
pub async fn move_folder(
    pool: &PgPool,
    account: &str,
    id: Uuid,
    parent: Option<Uuid>,
) -> Result<(), MoveError> {
    let mut tx = pool.begin().await?;
    move_folder_tx(&mut tx, account, id, parent).await?;
    tx.commit().await?;
    Ok(())
}

/// The check-and-update, on a connection the caller already holds.
///
/// The caller owns the transaction: the writer's batch is one transaction for many
/// statements, and a move must not open a second one inside it.
pub(crate) async fn move_folder_tx(
    connection: &mut PgConnection,
    account: &str,
    id: Uuid,
    parent: Option<Uuid>,
) -> Result<(), MoveError> {
    if let Some(parent) = parent {
        let cycle: bool = sqlx::query_scalar(
            "WITH RECURSIVE subtree AS ( \
                 SELECT id FROM drive_folder WHERE account_id = $1 AND id = $2 \
                 UNION ALL \
                 SELECT child.id FROM drive_folder child \
                   JOIN subtree ON child.parent_id = subtree.id \
                  WHERE child.account_id = $1 \
             ) \
             SELECT EXISTS (SELECT 1 FROM subtree WHERE id = $3)",
        )
        .bind(account)
        .bind(id)
        .bind(parent)
        .fetch_one(&mut *connection)
        .await?;
        if cycle {
            return Err(MoveError::Cycle);
        }
    }
    let result = sqlx::query(
        "UPDATE drive_folder SET parent_id = $3, updated_at = now() \
         WHERE account_id = $1 AND id = $2",
    )
    .bind(account)
    .bind(id)
    .bind(parent)
    .execute(&mut *connection)
    .await;
    match result {
        Ok(done) if done.rows_affected() == 1 => {}
        // A missing parent trips the composite foreign key, not a row count: both mean
        // "there is nothing in this account to move to".
        Ok(_) => return Err(MoveError::NotFound),
        Err(error) if is_foreign_key_violation(&error) => return Err(MoveError::NotFound),
        Err(error) => return Err(MoveError::Db(error)),
    }
    Ok(())
}

/// Deletes a folder and its subtree, returning the digests that went with it.
///
/// The rows cascade in the schema, but the digests cannot be read after the delete, so
/// they are collected first: they are the caller's candidates for freeing bytes, once
/// `object_by_sha` says no other object in the account still names them.
pub async fn delete_folder(
    pool: &PgPool,
    account: &str,
    id: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let digests = delete_folder_tx(&mut tx, account, id).await?;
    tx.commit().await?;
    Ok(digests)
}

/// Deletes the subtree on a connection the caller already holds, digests included.
pub(crate) async fn delete_folder_tx(
    connection: &mut PgConnection,
    account: &str,
    id: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    let digests: Vec<String> = sqlx::query_scalar(
        "WITH RECURSIVE subtree AS ( \
             SELECT id FROM drive_folder WHERE account_id = $1 AND id = $2 \
             UNION ALL \
             SELECT child.id FROM drive_folder child \
               JOIN subtree ON child.parent_id = subtree.id \
              WHERE child.account_id = $1 \
         ) \
         DELETE FROM drive_object \
          WHERE account_id = $1 AND folder_id IN (SELECT id FROM subtree) \
         RETURNING sha256",
    )
    .bind(account)
    .bind(id)
    .fetch_all(&mut *connection)
    .await?;
    sqlx::query("DELETE FROM drive_folder WHERE account_id = $1 AND id = $2")
        .bind(account)
        .bind(id)
        .execute(&mut *connection)
        .await?;
    let mut digests = digests;
    digests.sort_unstable();
    digests.dedup();
    Ok(digests)
}

/// Records a file the caller has already written to the blob store under `sha256`.
///
/// The bytes are not an argument, by design: the row is what the drive owns, and the
/// digest either names bytes the store already has or names nothing.
pub async fn create_object(
    pool: &PgPool,
    account: &str,
    folder: Option<Uuid>,
    filename: &str,
    mime_type: &str,
    sha256: &str,
    byte_size: i64,
) -> Result<DriveObject, sqlx::Error> {
    let mut connection = pool.acquire().await?;
    create_object_tx(
        &mut connection,
        account,
        folder,
        filename,
        mime_type,
        sha256,
        byte_size,
    )
    .await
}

#[allow(clippy::too_many_arguments, reason = "one row, one column each")]
pub(crate) async fn create_object_tx(
    connection: &mut PgConnection,
    account: &str,
    folder: Option<Uuid>,
    filename: &str,
    mime_type: &str,
    sha256: &str,
    byte_size: i64,
) -> Result<DriveObject, sqlx::Error> {
    let sql = format!(
        "INSERT INTO drive_object \
         (account_id, id, folder_id, filename, mime_type, sha256, byte_size) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {OBJECT_COLUMNS}"
    );
    sqlx::query_as::<_, DriveObject>(&sql)
        .bind(account)
        .bind(Uuid::now_v7())
        .bind(folder)
        .bind(filename)
        .bind(mime_type)
        .bind(sha256)
        .bind(byte_size)
        .fetch_one(&mut *connection)
        .await
}

/// One page of a folder's files, newest first. `None` is the root of the drive.
pub async fn objects(
    pool: &PgPool,
    account: &str,
    folder: Option<Uuid>,
    limit: i64,
    offset: i64,
) -> Result<Vec<DriveObject>, sqlx::Error> {
    let sql = format!(
        "SELECT {OBJECT_COLUMNS} FROM drive_object \
         WHERE account_id = $1 AND folder_id IS NOT DISTINCT FROM $2 \
         ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4"
    );
    sqlx::query_as::<_, DriveObject>(&sql)
        .bind(account)
        .bind(folder)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
}

/// One file by id.
pub async fn object(
    pool: &PgPool,
    account: &str,
    id: Uuid,
) -> Result<Option<DriveObject>, sqlx::Error> {
    let sql =
        format!("SELECT {OBJECT_COLUMNS} FROM drive_object WHERE account_id = $1 AND id = $2");
    sqlx::query_as::<_, DriveObject>(&sql)
        .bind(account)
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// Renames a file. `false` when the account has no such file.
pub async fn rename_object(
    pool: &PgPool,
    account: &str,
    id: Uuid,
    filename: &str,
) -> Result<bool, sqlx::Error> {
    let mut connection = pool.acquire().await?;
    rename_object_tx(&mut connection, account, id, filename).await
}

pub(crate) async fn rename_object_tx(
    connection: &mut PgConnection,
    account: &str,
    id: Uuid,
    filename: &str,
) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query("UPDATE drive_object SET filename = $3 WHERE account_id = $1 AND id = $2")
            .bind(account)
            .bind(id)
            .bind(filename)
            .execute(&mut *connection)
            .await?;
    Ok(result.rows_affected() == 1)
}

/// Files a file into `folder`, or at the root when `folder` is `None`.
///
/// A folder in another account cannot be a target: the composite foreign key refuses it.
pub async fn move_object(
    pool: &PgPool,
    account: &str,
    id: Uuid,
    folder: Option<Uuid>,
) -> Result<bool, sqlx::Error> {
    let mut connection = pool.acquire().await?;
    move_object_tx(&mut connection, account, id, folder).await
}

pub(crate) async fn move_object_tx(
    connection: &mut PgConnection,
    account: &str,
    id: Uuid,
    folder: Option<Uuid>,
) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query("UPDATE drive_object SET folder_id = $3 WHERE account_id = $1 AND id = $2")
            .bind(account)
            .bind(id)
            .bind(folder)
            .execute(&mut *connection)
            .await?;
    Ok(result.rows_affected() == 1)
}

/// Sets who may fetch a file.
pub async fn set_visibility(
    pool: &PgPool,
    account: &str,
    id: Uuid,
    visibility: Visibility,
) -> Result<bool, sqlx::Error> {
    let mut connection = pool.acquire().await?;
    set_visibility_tx(&mut connection, account, id, visibility).await
}

pub(crate) async fn set_visibility_tx(
    connection: &mut PgConnection,
    account: &str,
    id: Uuid,
    visibility: Visibility,
) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query("UPDATE drive_object SET visibility = $3 WHERE account_id = $1 AND id = $2")
            .bind(account)
            .bind(id)
            .bind(visibility.as_str())
            .execute(&mut *connection)
            .await?;
    Ok(result.rows_affected() == 1)
}

/// Records how far an upload got.
pub async fn set_state(
    pool: &PgPool,
    account: &str,
    id: Uuid,
    state: ProcessingState,
) -> Result<bool, sqlx::Error> {
    let mut connection = pool.acquire().await?;
    set_state_tx(&mut connection, account, id, state).await
}

pub(crate) async fn set_state_tx(
    connection: &mut PgConnection,
    account: &str,
    id: Uuid,
    state: ProcessingState,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE drive_object SET processing_state = $3 WHERE account_id = $1 AND id = $2",
    )
    .bind(account)
    .bind(id)
    .bind(state.as_str())
    .execute(&mut *connection)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Deletes a file, returning its digest so the caller can consider freeing the bytes.
///
/// The denormalised `media_attachment.stored_object_id` is untouched by design: no
/// foreign key means the delete cannot fail because a post still shows the picture, and
/// cannot pull the picture out of a post either.
pub async fn delete_object(
    pool: &PgPool,
    account: &str,
    id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    let mut connection = pool.acquire().await?;
    delete_object_tx(&mut connection, account, id).await
}

pub(crate) async fn delete_object_tx(
    connection: &mut PgConnection,
    account: &str,
    id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "DELETE FROM drive_object WHERE account_id = $1 AND id = $2 RETURNING sha256",
    )
    .bind(account)
    .bind(id)
    .fetch_optional(&mut *connection)
    .await
}

/// Bytes this account's drive holds, as its own rows measure them.
///
/// Every file counts, including duplicates of the same digest: a quota is about what the
/// account has put in its drive, not about how the store happens to deduplicate it.
pub async fn used_bytes(pool: &PgPool, account: &str) -> Result<i64, sqlx::Error> {
    let sql = "SELECT COALESCE(SUM(byte_size), 0)::bigint FROM drive_object WHERE account_id = $1";
    sqlx::query_scalar(sql).bind(account).fetch_one(pool).await
}

/// Bytes the blob store actually holds for this account: each digest counted once.
///
/// [`used_bytes`] counts every row, which answers "what has the account put in its
/// drive". This answers "what does the store hold", which is the number a quota and the
/// drive's own summary need: an upload of bytes the account already has writes nothing,
/// so it must not consume quota. A digest held by two rows contributes its size once.
pub async fn stored_bytes(pool: &PgPool, account: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COALESCE(SUM(byte_size), 0)::bigint FROM ( \
             SELECT DISTINCT ON (sha256) sha256, byte_size FROM drive_object \
              WHERE account_id = $1 ORDER BY sha256, byte_size DESC \
         ) stored",
    )
    .bind(account)
    .fetch_one(pool)
    .await
}

/// How many files the account's drive holds, duplicates included.
pub async fn object_count(pool: &PgPool, account: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*)::bigint FROM drive_object WHERE account_id = $1")
        .bind(account)
        .fetch_one(pool)
        .await
}

/// One folder by id, `None` when this account has no such folder.
pub async fn folder(
    pool: &PgPool,
    account: &str,
    id: Uuid,
) -> Result<Option<DriveFolder>, sqlx::Error> {
    let sql =
        format!("SELECT {FOLDER_COLUMNS} FROM drive_folder WHERE account_id = $1 AND id = $2");
    sqlx::query_as::<_, DriveFolder>(&sql)
        .bind(account)
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// The account's oldest file with these exact bytes — the dedupe candidate for an upload.
pub async fn object_by_sha(
    pool: &PgPool,
    account: &str,
    sha256: &str,
) -> Result<Option<DriveObject>, sqlx::Error> {
    let sql = format!(
        "SELECT {OBJECT_COLUMNS} FROM drive_object \
         WHERE account_id = $1 AND sha256 = $2 ORDER BY created_at ASC, id ASC LIMIT 1"
    );
    sqlx::query_as::<_, DriveObject>(&sql)
        .bind(account)
        .bind(sha256)
        .fetch_optional(pool)
        .await
}

/// Mints the `media_attachment` that shows a drive file in a post, returning its id.
///
/// This is the zero-copy path: the attachment carries the object's digest, so the media
/// layer finds the bytes in the store under the name the drive already gave them. Nothing
/// is copied, re-hashed or re-uploaded, and `stored_object_id` keeps the provenance even
/// though no constraint enforces it.
///
/// `None` means the object is not in this account — nothing was written.
pub async fn attach_object(
    pool: &PgPool,
    account: &str,
    object_id: Uuid,
    status_id: Option<&str>,
    alt_text: &str,
    focus: Option<&str>,
    blurhash: Option<&str>,
) -> Result<Option<String>, sqlx::Error> {
    let mut connection = pool.acquire().await?;
    attach_object_tx(
        &mut connection,
        account,
        object_id,
        status_id,
        alt_text,
        focus,
        blurhash,
    )
    .await
}

#[allow(clippy::too_many_arguments, reason = "one row, one column each")]
pub(crate) async fn attach_object_tx(
    connection: &mut PgConnection,
    account: &str,
    object_id: Uuid,
    status_id: Option<&str>,
    alt_text: &str,
    focus: Option<&str>,
    blurhash: Option<&str>,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO media_attachment \
         (id, account_id, status_id, digest, content_type, size, blurhash, description, \
          processing_state, processing_progress, meta, stored_object_id, created_at) \
         SELECT $1, object.account_id, $2, object.sha256, object.mime_type, object.byte_size, \
                $6, $5, object.processing_state, \
                CASE WHEN object.processing_state = 'ready' THEN 100 ELSE 0 END, \
                CASE WHEN $7::text IS NULL THEN '{}'::jsonb \
                     ELSE jsonb_build_object('focus', $7::text) END, \
                object.id, now() \
           FROM drive_object object \
          WHERE object.account_id = $3 AND object.id = $4 \
         RETURNING id",
    )
    .bind(nodus_server_core::Id::new().to_string())
    .bind(status_id)
    .bind(account)
    .bind(object_id)
    .bind(alt_text)
    .bind(blurhash)
    .bind(focus)
    .fetch_optional(&mut *connection)
    .await
}

/// True for SQLSTATE 23503, the composite foreign key saying "not in this account".
fn is_foreign_key_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code == "23503")
}
