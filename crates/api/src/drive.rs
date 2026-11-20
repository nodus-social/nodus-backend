//! The cloud drive: folders, files, and the bytes behind them.
//!
//! Every route here answers for the caller's own drive and nothing else. The store keys
//! both tables by `(account_id, id)`, so a row that belongs to another account simply
//! does not exist for this request — which is why a `PATCH` or `DELETE` against someone
//! else's id is a `404` and never a `403`: answering "forbidden" would confirm the id.
//!
//! An upload is content-addressed. The digest is the blob store's address, so a second
//! upload of bytes the account already holds writes nothing and adds a row that points at
//! the same digest. That is also why the drive's used-bytes figure counts each digest
//! once: duplicate rows are free, both to the quota and to the disk.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};

use axum::extract::{DefaultBodyLimit, Multipart, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use nodus_server_core::limits::PAGE_MAX;
use nodus_server_core::PageSize;
use nodus_server_media::cluster;
use nodus_server_store::drive::{
    self, DriveFolder, DriveObject, MoveError, ProcessingState, Visibility,
};
use nodus_storage::{BlobError, BlobStore, ByteRange, Capability, LocalDiskBlobStore, RangeError};

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::media::{storage_dir, ClusterUpload};
use crate::state::AppState;

/// The default quota: one gibibyte per account.
const DEFAULT_QUOTA_BYTES: i64 = 1024 * 1024 * 1024;

/// What one upload may weigh, whatever the quota is.
///
/// The bytes are held in memory in this phase (the same shape `POST /api/v1/media`
/// uses), so this is the ceiling on one request body, not on the drive.
const MAX_UPLOAD: usize = 1024 * 1024 * 1024;

/// How long a share link lives when the caller does not say.
///
/// A week is long enough to paste into a chat and short enough that a leaked link stops
/// working on its own; [`MAX_SHARE_SECONDS`] is the ceiling this instance will mint, so a
/// caller cannot hand out something effectively permanent.
const DEFAULT_SHARE_SECONDS: u64 = 7 * 24 * 60 * 60;

/// The longest a share link may live: thirty days.
const MAX_SHARE_SECONDS: u64 = 30 * 24 * 60 * 60;

/// The only rendition a share link grants. `Capability` compares the variant, so a
/// preview token cannot be spelled into an original one.
const SHARE_VARIANT: &str = "original";

/// A folder as the client reads it.
#[derive(Debug, Serialize)]
pub struct FolderDto {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Folders filed directly under this one. The tree is assembled in one pass, so a
    /// client never has to walk it level by level.
    pub children: Vec<FolderDto>,
}

impl FolderDto {
    fn flat(row: &DriveFolder) -> Self {
        Self {
            id: row.id.to_string(),
            parent_id: row.parent_id.map(|id| id.to_string()),
            name: row.name.clone(),
            created_at: row.created_at,
            updated_at: row.updated_at,
            children: Vec::new(),
        }
    }
}

/// A file as the client reads it.
#[derive(Debug, Serialize)]
pub struct ObjectDto {
    pub id: String,
    pub folder_id: Option<String>,
    pub filename: String,
    pub mime_type: String,
    pub byte_size: i64,
    /// Lowercase hex SHA-256: the same digest a `media_attachment` carries.
    pub sha256: String,
    pub visibility: String,
    pub processing_state: String,
    pub created_at: DateTime<Utc>,
}

impl From<&DriveObject> for ObjectDto {
    fn from(row: &DriveObject) -> Self {
        Self {
            id: row.id.to_string(),
            folder_id: row.folder_id.map(|id| id.to_string()),
            filename: row.filename.clone(),
            mime_type: row.mime_type.clone(),
            byte_size: row.byte_size,
            sha256: row.sha256.clone(),
            visibility: row.visibility.clone(),
            processing_state: row.processing_state.clone(),
            created_at: row.created_at,
        }
    }
}

/// `GET /api/v1/drive` — what the drive holds.
///
/// `used_bytes` is the deduplicated figure, the one the quota is measured against: two
/// rows naming one digest occupy it once. `objects` and `folders` are row counts.
#[derive(Debug, Serialize)]
pub struct DriveSummary {
    pub used_bytes: i64,
    pub objects: i64,
    pub folders: i64,
}

/// The folder tree, roots first.
#[derive(Debug, Serialize)]
pub struct FolderTree {
    pub folders: Vec<FolderDto>,
}

#[derive(Debug, Deserialize)]
pub struct NewFolder {
    #[serde(default)]
    pub parent_id: Option<String>,
    pub name: String,
}

/// `parent_id: null` means the root, and a missing field means "leave it alone".
///
/// `Option<Option<T>>` alone cannot tell those apart — serde collapses both into `None`
/// — so the inner value is wrapped as soon as the field is present, however null it is.
#[derive(Debug, Deserialize)]
pub struct FolderChanges {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "present_option")]
    pub parent_id: Option<Option<String>>,
}

#[derive(Debug, Deserialize)]
pub struct ObjectChanges {
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(default, deserialize_with = "present_option")]
    pub folder_id: Option<Option<String>>,
    #[serde(default)]
    pub visibility: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FileQuery {
    pub folder_id: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<i64>,
}

/// Marks a field as present even when its value is `null`.
fn present_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// `GET /api/v1/drive`
pub async fn show(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<DriveSummary>> {
    auth.require_scope("read:drive")?;
    let pool = state.store().pool();
    let account = &auth.0.account.id;
    Ok(Json(DriveSummary {
        used_bytes: drive::stored_bytes(pool, account).await?,
        objects: drive::object_count(pool, account).await?,
        folders: i64::try_from(drive::folders(pool, account).await?.len()).unwrap_or(i64::MAX),
    }))
}

/// `GET /api/v1/drive/folders` — the whole tree, assembled from one query.
pub async fn folders(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<FolderTree>> {
    auth.require_scope("read:drive")?;
    let rows = drive::folders(state.store().pool(), &auth.0.account.id).await?;
    Ok(Json(FolderTree {
        folders: tree(rows),
    }))
}

/// `POST /api/v1/drive/folders`
pub async fn create_folder(
    State(state): State<AppState>,
    auth: Auth,
    Json(input): Json<NewFolder>,
) -> ApiResult<Response> {
    auth.require_scope("write:drive")?;
    let name = required_name(&input.name)?;
    let parent = parse_id(input.parent_id.as_deref())?;
    let row = drive::create_folder(state.store().pool(), &auth.0.account.id, parent, &name)
        .await
        .map_err(|error| {
            // A parent that is not in this account trips the composite foreign key, and
            // a folder that is not in this account does not exist: both are a 404.
            if is_foreign_key_violation(&error) {
                ApiError::not_found("Record not found")
            } else {
                ApiError::from(error)
            }
        })?;
    Ok((StatusCode::CREATED, Json(FolderDto::flat(&row))).into_response())
}

/// `PATCH /api/v1/drive/folders/{id}` — rename, re-parent, or both.
pub async fn update_folder(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(input): Json<FolderChanges>,
) -> ApiResult<Json<FolderDto>> {
    auth.require_scope("write:drive")?;
    let account = &auth.0.account.id;
    let pool = state.store().pool();
    let id = parse_uuid(&id)?;
    if input.name.is_none() && input.parent_id.is_none() {
        return Err(ApiError::unprocessable("nothing to change"));
    }
    // The move runs first: a cycle is refused before the rename is written, so a
    // rejected move leaves the folder exactly as it was.
    if let Some(parent) = input.parent_id {
        let parent = parse_id(parent.as_deref())?;
        match drive::move_folder(pool, account, id, parent).await {
            Ok(()) => {}
            Err(MoveError::Cycle) => {
                return Err(ApiError::unprocessable(
                    "a folder cannot be moved inside itself",
                ));
            }
            Err(MoveError::NotFound | MoveError::Db(_)) => {
                return Err(ApiError::not_found("Record not found"));
            }
        }
    }
    if let Some(name) = input.name {
        let name = required_name(&name)?;
        if !drive::rename_folder(pool, account, id, &name).await? {
            return Err(ApiError::not_found("Record not found"));
        }
    }
    let row = drive::folder(pool, account, id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    Ok(Json(FolderDto::flat(&row)))
}

/// `DELETE /api/v1/drive/folders/{id}` — the subtree, and the bytes nothing else needs.
pub async fn delete_folder(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    auth.require_scope("write:drive")?;
    let account = &auth.0.account.id;
    let pool = state.store().pool();
    let id = parse_uuid(&id)?;
    if drive::folder(pool, account, id).await?.is_none() {
        return Err(ApiError::not_found("Record not found"));
    }
    for digest in drive::delete_folder(pool, account, id).await? {
        release_digest(&state, account, &digest).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/drive/files?folder_id=&limit=&offset=`
pub async fn list_files(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<FileQuery>,
) -> ApiResult<Json<Vec<ObjectDto>>> {
    auth.require_scope("read:drive")?;
    let folder = parse_id(query.folder_id.as_deref())?;
    let size = PageSize::clamp(query.limit, PAGE_MAX);
    let offset = query.offset.unwrap_or(0).max(0);
    let rows = drive::objects(
        state.store().pool(),
        &auth.0.account.id,
        folder,
        size.as_i64(),
        offset,
    )
    .await?;
    Ok(Json(rows.iter().map(ObjectDto::from).collect()))
}

/// `POST /api/v1/drive/files` — multipart `file`, optional `folder_id`, `visibility`.
pub async fn upload_file(
    State(state): State<AppState>,
    auth: Auth,
    mut multipart: Multipart,
) -> ApiResult<Response> {
    auth.require_scope("write:drive")?;
    let mut bytes: Option<Vec<u8>> = None;
    let mut filename = "upload.bin".to_owned();
    let mut mime_type = "application/octet-stream".to_owned();
    let mut folder: Option<String> = None;
    let mut visibility = Visibility::Private;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| ApiError::unprocessable("Malformed multipart body"))?
    {
        match field.name().unwrap_or_default() {
            "file" => {
                if let Some(name) = field.file_name() {
                    let name = clean_filename(name);
                    if !name.is_empty() {
                        filename = name;
                    }
                }
                if let Some(value) = field.content_type() {
                    mime_type = value.to_owned();
                }
                bytes = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|_| ApiError::unprocessable("Could not read the upload"))?
                        .to_vec(),
                );
            }
            "folder_id" => {
                let value = field
                    .text()
                    .await
                    .map_err(|_| ApiError::unprocessable("Invalid folder_id"))?;
                folder = Some(value);
            }
            "visibility" => {
                let value = field
                    .text()
                    .await
                    .map_err(|_| ApiError::unprocessable("Invalid visibility"))?;
                visibility = Visibility::parse(value.trim()).ok_or_else(|| {
                    ApiError::unprocessable(
                        "visibility must be private, unlisted_link or public_federated",
                    )
                })?;
            }
            _ => {}
        }
    }

    let bytes = bytes.ok_or_else(|| ApiError::unprocessable("A file is required"))?;
    if bytes.is_empty() {
        return Err(ApiError::unprocessable("The upload is empty"));
    }
    let folder = parse_id(folder.as_deref())?;
    let account = &auth.0.account.id;
    let pool = state.store().pool();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let byte_size = i64::try_from(bytes.len()).unwrap_or(i64::MAX);

    // The dedupe question comes before the quota question: bytes the account already
    // holds are already paid for, and this upload writes nothing.
    let existing = drive::object_by_sha(pool, account, &digest).await?;
    let ready = existing
        .as_ref()
        .is_some_and(|row| row.processing_state == ProcessingState::Ready.as_str());

    let processing = if ready {
        ProcessingState::Ready
    } else {
        let quota = quota_bytes();
        let used = drive::stored_bytes(pool, account).await?;
        if used.saturating_add(byte_size) > quota {
            // Refused before a byte is written, so a full drive leaves nothing behind.
            return Err(ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "the drive is full",
            ));
        }
        if store_blob(&digest, &bytes).await {
            ProcessingState::Ready
        } else {
            // The row is written anyway: the user can see what failed instead of the
            // upload vanishing.
            ProcessingState::Failed
        }
    };

    let row = drive::create_object(
        pool, account, folder, &filename, &mime_type, &digest, byte_size,
    )
    .await
    .map_err(|error| {
        if is_foreign_key_violation(&error) {
            ApiError::not_found("Record not found")
        } else {
            ApiError::from(error)
        }
    })?;
    drive::set_state(pool, account, row.id, processing).await?;
    // `create_object` writes the closed default (`private`); anything wider is a second
    // statement, which is the safe order — a failure in between leaves the file private.
    if visibility != Visibility::Private {
        drive::set_visibility(pool, account, row.id, visibility).await?;
    }
    let mut dto = ObjectDto::from(&row);
    dto.processing_state = processing.as_str().to_owned();
    dto.visibility = visibility.as_str().to_owned();
    Ok((StatusCode::CREATED, Json(dto)).into_response())
}

/// `PATCH /api/v1/drive/files/{id}`
pub async fn update_file(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(input): Json<ObjectChanges>,
) -> ApiResult<Json<ObjectDto>> {
    auth.require_scope("write:drive")?;
    let account = &auth.0.account.id;
    let pool = state.store().pool();
    let id = parse_uuid(&id)?;
    if drive::object(pool, account, id).await?.is_none() {
        return Err(ApiError::not_found("Record not found"));
    }
    if let Some(name) = input.filename {
        let name = clean_filename(&name);
        if name.is_empty() {
            return Err(ApiError::unprocessable("filename cannot be empty"));
        }
        drive::rename_object(pool, account, id, &name).await?;
    }
    if let Some(folder) = input.folder_id {
        let folder = parse_id(folder.as_deref())?;
        drive::move_object(pool, account, id, folder)
            .await
            .map_err(|error| {
                if is_foreign_key_violation(&error) {
                    ApiError::not_found("Record not found")
                } else {
                    ApiError::from(error)
                }
            })?;
    }
    if let Some(visibility) = input.visibility {
        let visibility = Visibility::parse(visibility.trim()).ok_or_else(|| {
            ApiError::unprocessable("visibility must be private, unlisted_link or public_federated")
        })?;
        drive::set_visibility(pool, account, id, visibility).await?;
    }
    let row = drive::object(pool, account, id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    Ok(Json(ObjectDto::from(&row)))
}

/// `DELETE /api/v1/drive/files/{id}`
pub async fn delete_file(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    auth.require_scope("write:drive")?;
    let account = &auth.0.account.id;
    let id = parse_uuid(&id)?;
    let Some(digest) = drive::delete_object(state.store().pool(), account, id).await? else {
        return Err(ApiError::not_found("Record not found"));
    };
    release_digest(&state, account, &digest).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The body of `POST /api/v1/drive/files/{id}/share`. Everything is optional, so a
/// caller that wants the default can post `{}` — or no body at all.
#[derive(Debug, Deserialize)]
pub struct ShareRequest {
    #[serde(default)]
    pub expires_in_seconds: Option<u64>,
}

/// A minted link, as the owner reads it.
#[derive(Debug, Serialize)]
pub struct ShareLink {
    /// Absolute and unauthenticated: `{instance}/media/share/{token}`.
    pub url: String,
    pub expires_at: DateTime<Utc>,
}

/// `POST /api/v1/drive/files/{id}/share` — a link a stranger can read.
///
/// The token is the whole grant: it names the digest, so reading it needs no account and
/// no database. That is also why it may only be minted for a file whose visibility is not
/// private — a private object has no audience outside its owner, and minting a link for it
/// would quietly undo the choice.
///
/// Without `NODUS_DRIVE_SHARE_SECRET` this route refuses rather than signing with a
/// default: a token nobody can verify is worse than a clear "not configured".
pub async fn share_file(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    body: Option<Json<ShareRequest>>,
) -> ApiResult<Json<ShareLink>> {
    auth.require_scope("write:drive")?;
    let Some(secret) = share_secret() else {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "share links are not configured",
        ));
    };
    let id = parse_uuid(&id)?;
    let row = drive::object(state.store().pool(), &auth.0.account.id, id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    if row.visibility == Visibility::Private.as_str() {
        return Err(ApiError::new(StatusCode::CONFLICT, "this file is private"));
    }

    let seconds = body
        .and_then(|Json(body)| body.expires_in_seconds)
        .unwrap_or(DEFAULT_SHARE_SECONDS);
    if seconds == 0 || seconds > MAX_SHARE_SECONDS {
        return Err(ApiError::unprocessable(
            "expires_in_seconds must be between 1 and 2592000",
        ));
    }
    let expires_at = SystemTime::now() + Duration::from_secs(seconds);
    let token = Capability::mint(&secret, &row.sha256, SHARE_VARIANT, expires_at);
    Ok(Json(ShareLink {
        url: state.instance().url(&format!("/media/share/{token}")),
        expires_at: DateTime::<Utc>::from(expires_at),
    }))
}

/// `GET /media/share/{token}` — a minted link's bytes, for no one in particular.
///
/// There is deliberately no `State` extractor here: the token is verified in memory and
/// the bytes come from the blob store, so serving a share link issues **zero database
/// queries**. Two consequences follow, and both are on purpose:
///
/// - A token that is malformed, signed under another secret, naming another variant, or
///   past its expiry is a `404`, never a `403`. To a stranger a link that never existed
///   and one that ran out look the same, and neither answer confirms that a digest exists.
/// - The type is `application/octet-stream`: the mime type lives in the catalogue, and
///   reading it would be exactly the query this route exists without.
///   TODO(3c): carry the type inside the capability so a share of a video plays inline
///   instead of downloading.
pub async fn shared_content(Path(token): Path<String>, headers: HeaderMap) -> Response {
    let Some(secret) = share_secret() else {
        // No secret was ever configured, so no token can be genuine here.
        return ApiError::not_found("Record not found").into_response();
    };
    let now = SystemTime::now();
    let claims = match Capability::verify(&secret, &token, now) {
        Ok(claims) if claims.allows(SHARE_VARIANT) => claims,
        _ => return ApiError::not_found("Record not found").into_response(),
    };
    // The link's remaining lifetime is the only thing this response may be cached for.
    let remaining = claims
        .expires_at
        .duration_since(now)
        .map_or(0, |left| left.as_secs());

    let store = LocalDiskBlobStore::new(storage_dir());
    // A range is resolved against the length, and only the local copy knows its length
    // without being read. A cluster-only digest is fetched whole, and those bytes answer
    // the next question rather than being fetched twice.
    let mut whole: Option<Vec<u8>> = None;
    let len = if let Some(len) = store.size(&claims.digest).await {
        len
    } else {
        match read_blob(&claims.digest, None).await {
            Ok(bytes) => {
                let len = u64::try_from(bytes.len()).unwrap_or(0);
                whole = Some(bytes);
                len
            }
            // The token is genuine but the bytes are not here, which is still nothing a
            // stranger may see.
            Err(_) => return ApiError::not_found("Record not found").into_response(),
        }
    };

    // Same policy as the owner's own content route: a header this store cannot read is
    // ignored (the whole body), a header that parses but names no byte is a 416.
    let requested = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .map(ByteRange::parse);
    let ranged = match requested {
        Some(Ok(range)) => match range.resolve(len) {
            Ok((start, end)) => Some((range, start, end)),
            Err(_) => return unsatisfiable(len),
        },
        Some(Err(RangeError::Unsatisfiable)) => return unsatisfiable(len),
        Some(Err(RangeError::Malformed)) | None => None,
    };

    let body = match (whole, ranged) {
        (Some(bytes), None) => bytes,
        (Some(bytes), Some((_, start, end))) => {
            bytes[usize::try_from(start).unwrap_or(0)..=usize::try_from(end).unwrap_or(0)].to_vec()
        }
        (None, None) => match read_blob(&claims.digest, None).await {
            Ok(bytes) => bytes,
            Err(_) => return ApiError::not_found("Record not found").into_response(),
        },
        (None, Some((range, _, _))) => match read_blob(&claims.digest, Some(range)).await {
            Ok(bytes) => bytes,
            Err(_) => return ApiError::not_found("Record not found").into_response(),
        },
    };

    let status = if ranged.is_some() {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    let mut response = Response::builder().status(status);
    response = response
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, body.len())
        .header(header::ACCEPT_RANGES, "bytes")
        .header(
            header::CACHE_CONTROL,
            format!("private, max-age={remaining}"),
        );
    if let Some((_, start, end)) = ranged {
        response = response.header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}"));
    }
    response
        .body(axum::body::Body::from(body))
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not build the response",
            )
        })
        .unwrap_or_else(IntoResponse::into_response)
}

/// `GET /api/v1/drive/files/{id}/content` — the caller's own bytes, with ranges.
pub async fn file_content(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    auth.require_scope("read:drive")?;
    let id = parse_uuid(&id)?;
    let row = drive::object(state.store().pool(), &auth.0.account.id, id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    let len = u64::try_from(row.byte_size).unwrap_or(0);

    // A header this store cannot read is ignored and the whole body is served, which is
    // what RFC 9110 asks of a server that does not honour a range; a header that parses
    // but names no byte is the one answer that must be a 416.
    let requested = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .map(ByteRange::parse);
    let ranged = match requested {
        Some(Ok(range)) => match range.resolve(len) {
            Ok((start, end)) => Some((range, start, end)),
            Err(_) => return Ok(unsatisfiable(len)),
        },
        Some(Err(RangeError::Unsatisfiable)) => return Ok(unsatisfiable(len)),
        // Malformed, or no header at all: the whole representation.
        Some(Err(RangeError::Malformed)) | None => None,
    };

    let body = match ranged {
        Some((range, _, _)) => read_blob(&row.sha256, Some(range)).await?,
        None => read_blob(&row.sha256, None).await?,
    };

    let status = if ranged.is_some() {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    let mut response = Response::builder().status(status);
    let content_type = if row.mime_type.trim().is_empty() {
        "application/octet-stream".to_owned()
    } else {
        row.mime_type.clone()
    };
    if let Ok(value) = HeaderValue::from_str(&content_type) {
        response = response.header(header::CONTENT_TYPE, value);
    }
    if let Ok(value) = HeaderValue::from_str(&content_disposition(&row.filename)) {
        response = response.header(header::CONTENT_DISPOSITION, value);
    }
    response = response
        .header(header::CONTENT_LENGTH, body.len())
        .header(header::ACCEPT_RANGES, "bytes");
    if let Some((_, start, end)) = ranged {
        if let Ok(value) = HeaderValue::from_str(&format!("bytes {start}-{end}/{len}")) {
            response = response.header(header::CONTENT_RANGE, value);
        }
    }
    response.body(axum::body::Body::from(body)).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not build the response",
        )
    })
}

/// `416` with the `Content-Range` that says how long the file actually is.
fn unsatisfiable(len: u64) -> Response {
    let mut response = ApiError::new(
        StatusCode::RANGE_NOT_SATISFIABLE,
        "the range names no byte of this file",
    )
    .into_response();
    if let Ok(value) = HeaderValue::from_str(&format!("bytes */{len}")) {
        response.headers_mut().insert(header::CONTENT_RANGE, value);
    }
    response
}

/// Builds the tree from one flat, name-ordered list.
///
/// Every row is inserted as a child of its parent, and rows whose parent is missing
/// (a folder deleted between two queries) become roots rather than disappearing.
fn tree(rows: Vec<DriveFolder>) -> Vec<FolderDto> {
    let known: HashSet<Uuid> = rows.iter().map(|row| row.id).collect();
    let mut children: HashMap<Option<Uuid>, Vec<FolderDto>> = HashMap::new();
    for row in &rows {
        children
            .entry(row.parent_id)
            .or_default()
            .push(FolderDto::flat(row));
    }
    let mut roots = children.remove(&None).unwrap_or_default();
    attach(&mut roots, &mut children);

    // A folder whose parent is not in the listing (deleted between the two queries)
    // would never be reached from a root, so it is promoted to one instead.
    while !children.is_empty() {
        let mut missing: Vec<Option<Uuid>> = children
            .keys()
            .copied()
            .filter(|key| key.is_some_and(|id| !known.contains(&id)))
            .collect();
        if missing.is_empty() {
            break;
        }
        missing.sort();
        for key in missing {
            if let Some(mut group) = children.remove(&key) {
                roots.append(&mut group);
            }
        }
        roots.sort_by(|a, b| a.name.cmp(&b.name));
        attach(&mut roots, &mut children);
    }
    roots
}

fn attach(nodes: &mut [FolderDto], children: &mut HashMap<Option<Uuid>, Vec<FolderDto>>) {
    for node in nodes.iter_mut() {
        let id = Uuid::parse_str(&node.id).ok();
        if let Some(id) = id {
            if let Some(mut nested) = children.remove(&Some(id)) {
                attach(&mut nested, children);
                node.children = nested;
            }
        }
    }
}

/// Stores the bytes under `digest`, through the cluster when one is configured.
///
/// `true` means the digest is storable from now on. A cluster that refuses falls back
/// to the local disk exactly as `POST /api/v1/media` does: the user has already sent the
/// bytes, and a media node that is down must not turn that into a lost file.
async fn store_blob(digest: &str, bytes: &[u8]) -> bool {
    if let Some(cluster) = ClusterUpload::from_env() {
        match cluster.put(digest, bytes).await {
            Ok(()) => return true,
            Err(error) => {
                tracing::warn!(%error, %digest, "the media cluster refused a drive upload");
            }
        }
    }
    let store = LocalDiskBlobStore::new(storage_dir());
    match store.put(digest, bytes).await {
        Ok(_) => true,
        Err(error) => {
            tracing::warn!(%error, %digest, "could not store a drive upload");
            false
        }
    }
}

/// Reads a digest, preferring this host's copy and falling back to the cluster.
///
/// An original accepted by a media node is not on this disk at all, so a local miss is
/// not a missing file: it is the queue for the cluster read. Only when neither has the
/// bytes does the request fail, and it fails as a server error — the row says `ready`.
async fn read_blob(digest: &str, range: Option<ByteRange>) -> ApiResult<Vec<u8>> {
    let store = LocalDiskBlobStore::new(storage_dir());
    match store.read(digest, range).await {
        Ok(bytes) => return Ok(bytes),
        Err(BlobError::NotFound(_)) => {}
        Err(error) => {
            tracing::error!(%error, %digest, "could not read a drive file");
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the file could not be read",
            ));
        }
    }
    if let (Some(base), Some(token)) = (
        env_value("NODUS_MEDIA_CLUSTER_URL"),
        env_value("NODUS_MEDIA_CLUSTER_TOKEN"),
    ) {
        if let Some(bytes) = cluster::fetch(&base, &token, digest).await {
            return match range {
                None => Ok(bytes),
                Some(range) => {
                    let len = u64::try_from(bytes.len()).unwrap_or(0);
                    let (start, end) = range.resolve(len).map_err(|_| {
                        ApiError::new(
                            StatusCode::RANGE_NOT_SATISFIABLE,
                            "the range names no byte of this file",
                        )
                    })?;
                    Ok(bytes[start as usize..=end as usize].to_vec())
                }
            };
        }
    }
    tracing::warn!(%digest, "a drive file's bytes are in neither the disk nor the cluster");
    Err(ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "the file's bytes are missing from storage",
    ))
}

/// Deletes the bytes behind a digest nobody references any more.
///
/// Two things can still need them, and both are checked after the row is gone: another
/// drive row in the same account with the same digest (`object_by_sha`), and a
/// `media_attachment` a post still shows. Only when neither does is the blob unlinked,
/// and the unlink is the cluster-aware one, so every node loses its copy.
async fn release_digest(state: &AppState, account: &str, digest: &str) -> ApiResult<()> {
    let pool = state.store().pool();
    if drive::object_by_sha(pool, account, digest).await?.is_some() {
        return Ok(());
    }
    if nodus_server_store::media::original_digest_referenced(pool, digest).await? {
        return Ok(());
    }
    crate::media::delete_original(digest).await;
    Ok(())
}

fn quota_bytes() -> i64 {
    std::env::var("NODUS_DRIVE_QUOTA_BYTES")
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_QUOTA_BYTES)
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// The key share links are signed with, when the deployment has set one.
fn share_secret() -> Option<Vec<u8>> {
    env_value("NODUS_DRIVE_SHARE_SECRET").map(String::into_bytes)
}

/// Parses an optional id from a query string or form field. `None` is the root.
fn parse_id(value: Option<&str>) -> ApiResult<Option<Uuid>> {
    match value.map(str::trim) {
        None | Some("") | Some("root") => Ok(None),
        Some(value) => Uuid::parse_str(value)
            .map(Some)
            .map_err(|_| ApiError::unprocessable("not a valid id")),
    }
}

/// A path segment is an id this API minted, so anything else is a `404`: the row it
/// would name does not exist.
fn parse_uuid(value: &str) -> ApiResult<Uuid> {
    Uuid::parse_str(value.trim()).map_err(|_| ApiError::not_found("Record not found"))
}

fn required_name(value: &str) -> ApiResult<String> {
    let name = value.trim();
    if name.is_empty() {
        return Err(ApiError::unprocessable("name cannot be empty"));
    }
    Ok(name.to_owned())
}

/// A filename is echoed in a header and shown in a listing: no separators, no controls.
fn clean_filename(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != '\\')
        .collect::<String>()
        .trim()
        .to_owned()
}

/// `attachment; filename="…"`, with anything a header cannot carry replaced.
fn content_disposition(filename: &str) -> String {
    let safe: String = filename
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| {
            if c.is_ascii() && c != '"' && c != '\\' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let safe = if safe.trim().is_empty() {
        "download".to_owned()
    } else {
        safe
    };
    format!("attachment; filename=\"{safe}\"")
}

/// True for SQLSTATE 23503, the composite foreign key saying "not in this account".
fn is_foreign_key_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code == "23503")
}

/// The router fragment, mounted by `crate::router`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/drive", get(show))
        .route("/api/v1/drive/folders", get(folders).post(create_folder))
        .route(
            "/api/v1/drive/folders/{id}",
            patch(update_folder).delete(delete_folder),
        )
        .route("/api/v1/drive/files", get(list_files).post(upload_file))
        .route(
            "/api/v1/drive/files/{id}",
            patch(update_file).delete(delete_file),
        )
        .route("/api/v1/drive/files/{id}/content", get(file_content))
        .route("/api/v1/drive/files/{id}/share", post(share_file))
        // Unauthenticated on purpose: the token is the credential. It lives in this
        // router rather than the media service's because verifying it needs no database,
        // and the bytes may be on either host.
        .route("/media/share/{token}", get(shared_content))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(id: Uuid, parent: Option<Uuid>, name: &str) -> DriveFolder {
        DriveFolder {
            account_id: "acct".to_owned(),
            id,
            parent_id: parent,
            name: name.to_owned(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// The 503 branch of `share_file` is only reachable this way, so the gate itself is
    /// what the test pins: no secret, no signing.
    #[test]
    fn a_share_link_has_no_secret_to_sign_with_when_none_is_configured() {
        let before = std::env::var_os("NODUS_DRIVE_SHARE_SECRET");
        std::env::remove_var("NODUS_DRIVE_SHARE_SECRET");
        assert_eq!(share_secret(), None);

        std::env::set_var("NODUS_DRIVE_SHARE_SECRET", "a-key");
        assert_eq!(share_secret().as_deref(), Some(b"a-key".as_slice()));

        std::env::remove_var("NODUS_DRIVE_SHARE_SECRET");
        if let Some(before) = before {
            std::env::set_var("NODUS_DRIVE_SHARE_SECRET", before);
        }
    }

    #[test]
    fn the_tree_nests_children_under_their_parent() {
        let root = Uuid::now_v7();
        let child = Uuid::now_v7();
        let grandchild = Uuid::now_v7();
        let flat = vec![
            folder(root, None, "root"),
            folder(child, Some(root), "child"),
            folder(grandchild, Some(child), "grandchild"),
        ];
        let tree = tree(flat);
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].children.len(), 1);
        assert_eq!(tree[0].children[0].children.len(), 1);
        assert_eq!(tree[0].children[0].children[0].name, "grandchild");
    }

    #[test]
    fn an_orphan_becomes_a_root_instead_of_disappearing() {
        let orphan = Uuid::now_v7();
        let tree = tree(vec![folder(orphan, Some(Uuid::now_v7()), "orphan")]);
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].name, "orphan");
    }

    #[test]
    fn a_filename_is_escaped_for_its_header() {
        assert_eq!(
            content_disposition("mood \"board\".png"),
            "attachment; filename=\"mood _board_.png\""
        );
        assert_eq!(
            content_disposition("\n"),
            "attachment; filename=\"download\""
        );
    }

    #[test]
    fn a_patch_can_tell_a_missing_field_from_a_null_one() {
        let absent: FolderChanges = serde_json::from_str(r#"{"name":"x"}"#).unwrap();
        assert_eq!(absent.parent_id, None);
        let root: FolderChanges = serde_json::from_str(r#"{"parent_id":null}"#).unwrap();
        assert_eq!(root.parent_id, Some(None));
        let moved: FolderChanges =
            serde_json::from_str(r#"{"parent_id":"01890a5d-ac96-774b-bcce-b302099a8057"}"#)
                .unwrap();
        assert!(moved.parent_id.unwrap().is_some());
    }
}
