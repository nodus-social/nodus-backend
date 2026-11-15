//! Fine-grained, per-account client metadata endpoints (`/api/v1/nodus/account/metadata`).
//!
//! Stores arbitrary client-owned preferences (session images, navigation layout,
//! third-party client settings) keyed by validated identifiers without schema changes.

use axum::extract::{Path, RawQuery, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use nodus_server_core::client_metadata::validate_key;
use nodus_server_core::limits::CLIENT_METADATA_MAX_KEYS;
use nodus_server_store::accounts::{self, ClientMetadataStoreError};

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Client metadata routes merged under the Nodus surface.
pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/nodus/account/metadata",
            get(get_all)
                .patch(patch_all)
                .put(replace_all)
                .delete(clear_or_delete_keys),
        )
        .route(
            "/api/v1/nodus/account/metadata/{key}",
            get(get_key).put(set_key).delete(delete_key),
        )
}

#[derive(Debug, Serialize)]
struct MetadataResponse {
    metadata: Map<String, Value>,
}

#[derive(Debug, Serialize)]
struct MetadataKeyResponse {
    key: String,
    value: Value,
}

#[derive(Debug, Deserialize)]
struct MetadataMapBody {
    metadata: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
struct MetadataValueBody {
    value: Value,
}

fn map_store_error(error: ClientMetadataStoreError) -> ApiError {
    match error {
        ClientMetadataStoreError::AccountNotFound => ApiError::not_found("Account not found"),
        ClientMetadataStoreError::Validation(err) => ApiError::unprocessable(err.to_string()),
        ClientMetadataStoreError::Sqlx(err) => ApiError::from(err),
    }
}

fn validate_key_param(key: &str) -> ApiResult<()> {
    validate_key(key).map_err(|err| ApiError::unprocessable(err.to_string()))
}

fn parse_requested_keys(raw_query: Option<&str>) -> ApiResult<Option<Vec<String>>> {
    let Some(raw) = raw_query.filter(|q| !q.is_empty()) else {
        return Ok(None);
    };
    let mut saw_param = false;
    let mut keys = Vec::new();
    for (name, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        if name == "keys" {
            saw_param = true;
            for part in value.split(',') {
                validate_key_param(part)?;
                if !keys.iter().any(|existing| existing == part) {
                    keys.push(part.to_owned());
                }
            }
        } else if name == "key" || name == "keys[]" {
            saw_param = true;
            validate_key_param(&value)?;
            if !keys.iter().any(|existing| existing == value.as_ref()) {
                keys.push(value.into_owned());
            }
        }
    }
    if !saw_param {
        return Ok(None);
    }
    if keys.is_empty() {
        return Err(ApiError::unprocessable("keys must not be empty"));
    }
    if keys.len() > CLIENT_METADATA_MAX_KEYS {
        return Err(ApiError::unprocessable(format!(
            "cannot request more than {CLIENT_METADATA_MAX_KEYS} keys"
        )));
    }
    Ok(Some(keys))
}

async fn get_all(
    State(state): State<AppState>,
    auth: Auth,
    RawQuery(raw_query): RawQuery,
) -> ApiResult<Json<MetadataResponse>> {
    auth.require_scope("read:accounts")?;
    let requested = parse_requested_keys(raw_query.as_deref())?;
    let metadata = match requested {
        Some(keys) => {
            accounts::client_metadata_get_keys(state.store().pool(), &auth.0.account.id, &keys)
                .await?
        }
        None => accounts::client_metadata_all(state.store().pool(), &auth.0.account.id).await?,
    }
    .ok_or_else(|| ApiError::not_found("Account not found"))?;
    Ok(Json(MetadataResponse { metadata }))
}

async fn patch_all(
    State(state): State<AppState>,
    auth: Auth,
    Json(body): Json<MetadataMapBody>,
) -> ApiResult<Json<MetadataResponse>> {
    auth.require_scope("write:accounts")?;
    let metadata =
        accounts::client_metadata_patch(state.store().pool(), &auth.0.account.id, &body.metadata)
            .await
            .map_err(map_store_error)?;
    Ok(Json(MetadataResponse { metadata }))
}

async fn replace_all(
    State(state): State<AppState>,
    auth: Auth,
    Json(body): Json<MetadataMapBody>,
) -> ApiResult<Json<MetadataResponse>> {
    auth.require_scope("write:accounts")?;
    let metadata =
        accounts::client_metadata_replace(state.store().pool(), &auth.0.account.id, &body.metadata)
            .await
            .map_err(map_store_error)?;
    Ok(Json(MetadataResponse { metadata }))
}

async fn clear_or_delete_keys(
    State(state): State<AppState>,
    auth: Auth,
    RawQuery(raw_query): RawQuery,
) -> ApiResult<Json<MetadataResponse>> {
    auth.require_scope("write:accounts")?;
    let requested = parse_requested_keys(raw_query.as_deref())?;
    let metadata = if let Some(keys) = requested {
        accounts::client_metadata_delete_keys(state.store().pool(), &auth.0.account.id, &keys)
            .await
            .map_err(map_store_error)?
    } else {
        accounts::client_metadata_clear(state.store().pool(), &auth.0.account.id)
            .await
            .map_err(map_store_error)?;
        Map::new()
    };
    Ok(Json(MetadataResponse { metadata }))
}

async fn get_key(
    State(state): State<AppState>,
    auth: Auth,
    Path(key): Path<String>,
) -> ApiResult<Json<MetadataKeyResponse>> {
    auth.require_scope("read:accounts")?;
    validate_key_param(&key)?;
    let value = accounts::client_metadata_get_key(state.store().pool(), &auth.0.account.id, &key)
        .await?
        .ok_or_else(|| ApiError::not_found("Metadata key not found"))?;
    Ok(Json(MetadataKeyResponse { key, value }))
}

async fn set_key(
    State(state): State<AppState>,
    auth: Auth,
    Path(key): Path<String>,
    Json(body): Json<MetadataValueBody>,
) -> ApiResult<Json<MetadataKeyResponse>> {
    auth.require_scope("write:accounts")?;
    validate_key_param(&key)?;
    if body.value.is_null() {
        return Err(ApiError::unprocessable(
            "value must not be null; use DELETE to clear a key",
        ));
    }
    accounts::client_metadata_set_key(
        state.store().pool(),
        &auth.0.account.id,
        &key,
        body.value.clone(),
    )
    .await
    .map_err(map_store_error)?;
    Ok(Json(MetadataKeyResponse {
        key,
        value: body.value,
    }))
}

async fn delete_key(
    State(state): State<AppState>,
    auth: Auth,
    Path(key): Path<String>,
) -> ApiResult<Json<Value>> {
    auth.require_scope("write:accounts")?;
    validate_key_param(&key)?;
    accounts::client_metadata_delete_keys(
        state.store().pool(),
        &auth.0.account.id,
        std::slice::from_ref(&key),
    )
    .await
    .map_err(map_store_error)?;
    Ok(Json(json!({ "ok": true })))
}
