//! `POST /api/v1/apps`: client registration.
//!
//! Mastodon clients call this before OAuth. The response is the only time the raw
//! client secret exists outside the client.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use nodus_server_core::Id;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct AppRequest {
    #[serde(alias = "name")]
    pub client_name: String,
    #[serde(default)]
    pub website: Option<String>,
    #[serde(default)]
    pub redirect_uris: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub scopes: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AppResponse {
    pub id: String,
    pub name: String,
    pub website: Option<String>,
    pub redirect_uri: String,
    pub client_id: String,
    pub client_secret: String,
    pub vapid_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AppError {
    pub error: String,
}

pub async fn register(
    State(state): State<AppState>,
    Json(request): Json<AppRequest>,
) -> ApiResult<Json<AppResponse>> {
    let name = request.client_name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::unprocessable(
            "client_name must be between 1 and 100 characters",
        ));
    }
    let mut redirects: Vec<String> = request
        .redirect_uris
        .as_deref()
        .or(request.redirect_uri.as_deref())
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    redirects.dedup();
    if redirects.is_empty() {
        return Err(ApiError::unprocessable("redirect_uris is required"));
    }
    for redirect in &redirects {
        if url::Url::parse(redirect).is_err() {
            return Err(ApiError::unprocessable(format!(
                "invalid redirect_uri: {redirect}"
            )));
        }
    }
    let scopes: Vec<String> = request
        .scopes
        .as_deref()
        .unwrap_or("read write follow push")
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    if scopes.is_empty() {
        return Err(ApiError::unprocessable("scopes must not be empty"));
    }

    let id = Id::new().to_string();
    let client_id = random_token(16);
    let client_secret = random_token(32);
    let secret_hash = hex_lower(&Sha256::digest(client_secret.as_bytes()));
    let app = nodus_server_store::apps::register(
        state.store().pool(),
        &id,
        &client_id,
        &secret_hash,
        name,
        request.website.as_deref().filter(|value| !value.is_empty()),
        &redirects,
        &scopes,
    )
    .await?;

    Ok(Json(AppResponse {
        id: app.id,
        name: app.name,
        website: app.website,
        redirect_uri: app.redirect_uris.first().cloned().unwrap_or_default(),
        client_id: app.client_id,
        client_secret,
        vapid_key: None,
    }))
}

fn random_token(bytes: usize) -> String {
    let value: Vec<u8> = (0..bytes).map(|_| rand::random::<u8>()).collect();
    hex_lower(&value)
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
