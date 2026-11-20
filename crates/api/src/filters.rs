//! Mastodon v2 keyword filters, plus a v1 adapter over the same rows.
//!
//! The v1 shape predates keyword lists: one row is one phrase and a boolean
//! `irreversible` stands in for v2's `filter_action`. The SDK still calls
//! `/api/v1/filters`, so the v1 routes below adapt the same `filter` and
//! `filter_keyword` rows instead of introducing a second store:
//!
//! * `phrase`       <-> the first keyword's text, falling back to the filter title
//! * `whole_word`   <-> that keyword's `whole_word` flag
//! * `irreversible` <-> `filter_action == "hide"`
//!
//! Writing through v1 collapses a v2 filter to the single phrase sent, because v1 has
//! no way to express a keyword list; reading a v2 filter with several keywords surfaces
//! the first. That is the genuine conflict between the shapes, and this is where it
//! shows.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Debug, Serialize)]
struct KeywordDto {
    id: String,
    keyword: String,
    whole_word: bool,
}

#[derive(Debug, Serialize)]
struct FilterDto {
    id: String,
    title: String,
    context: Vec<String>,
    expires_at: Option<DateTime<Utc>>,
    filter_action: String,
    keywords: Vec<KeywordDto>,
}

async fn dto(
    state: &AppState,
    row: nodus_server_store::filters::FilterRow,
) -> ApiResult<FilterDto> {
    let keywords = nodus_server_store::filters::keywords(state.store().pool(), &row.id)
        .await?
        .into_iter()
        .map(|keyword| KeywordDto {
            id: keyword.id,
            keyword: keyword.keyword,
            whole_word: keyword.whole_word,
        })
        .collect();
    Ok(FilterDto {
        id: row.id,
        title: row.title,
        context: row.context,
        expires_at: row.expires_at,
        filter_action: row.action,
        keywords,
    })
}

#[derive(Debug, Deserialize)]
struct KeywordRequest {
    keyword: String,
    #[serde(default)]
    whole_word: bool,
}

#[derive(Debug, Deserialize)]
struct FilterRequest {
    title: String,
    #[serde(default = "default_context")]
    context: Vec<String>,
    #[serde(default = "warn")]
    filter_action: String,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    keywords: Vec<KeywordRequest>,
}

fn default_context() -> Vec<String> {
    vec![
        "home".to_owned(),
        "notifications".to_owned(),
        "public".to_owned(),
        "thread".to_owned(),
    ]
}

fn warn() -> String {
    "warn".to_owned()
}

fn expiry(seconds: Option<i64>) -> Option<DateTime<Utc>> {
    seconds
        .filter(|seconds| *seconds > 0)
        .map(|seconds| Utc::now() + chrono::Duration::seconds(seconds))
}

async fn list(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<FilterDto>>> {
    let rows =
        nodus_server_store::filters::filters(state.store().pool(), &auth.0.account.id, 200).await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(dto(&state, row).await?);
    }
    Ok(Json(out))
}

fn validate_filter_request(body: &FilterRequest) -> ApiResult<&str> {
    let title = body.title.trim();
    if title.is_empty() {
        return Err(ApiError::unprocessable("title is required"));
    }
    if !matches!(body.filter_action.as_str(), "warn" | "hide") {
        return Err(ApiError::unprocessable(
            "filter_action must be warn or hide",
        ));
    }
    Ok(title)
}

async fn create(
    State(state): State<AppState>,
    auth: Auth,
    Json(body): Json<FilterRequest>,
) -> ApiResult<Json<FilterDto>> {
    let title = validate_filter_request(&body)?;
    let row = nodus_server_store::filters::create(
        state.store().pool(),
        &auth.0.account.id,
        title,
        &body.context,
        &body.filter_action,
        expiry(body.expires_in),
    )
    .await?;
    for keyword in &body.keywords {
        if !keyword.keyword.trim().is_empty() {
            nodus_server_store::filters::add_keyword(
                state.store().pool(),
                &row.id,
                keyword.keyword.trim(),
                keyword.whole_word,
            )
            .await?;
        }
    }
    Ok(Json(dto(&state, row).await?))
}

async fn show(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<FilterDto>> {
    let row = nodus_server_store::filters::filter(state.store().pool(), &auth.0.account.id, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("filter does not exist"))?;
    Ok(Json(dto(&state, row).await?))
}

async fn update(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(body): Json<FilterRequest>,
) -> ApiResult<Json<FilterDto>> {
    let title = validate_filter_request(&body)?;
    let row = nodus_server_store::filters::update(
        state.store().pool(),
        &auth.0.account.id,
        &id,
        title,
        &body.context,
        &body.filter_action,
        expiry(body.expires_in),
    )
    .await?
    .ok_or_else(|| ApiError::not_found("filter does not exist"))?;
    Ok(Json(dto(&state, row).await?))
}

async fn destroy(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<axum::http::StatusCode> {
    if !nodus_server_store::filters::delete(state.store().pool(), &auth.0.account.id, &id).await? {
        return Err(ApiError::not_found("filter does not exist"));
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn add_keyword(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(body): Json<KeywordRequest>,
) -> ApiResult<Json<KeywordDto>> {
    if nodus_server_store::filters::filter(state.store().pool(), &auth.0.account.id, &id)
        .await?
        .is_none()
    {
        return Err(ApiError::not_found("filter does not exist"));
    }
    let keyword = body.keyword.trim();
    if keyword.is_empty() {
        return Err(ApiError::unprocessable("keyword is required"));
    }
    let row = nodus_server_store::filters::add_keyword(
        state.store().pool(),
        &id,
        keyword,
        body.whole_word,
    )
    .await?;
    Ok(Json(KeywordDto {
        id: row.id,
        keyword: row.keyword,
        whole_word: row.whole_word,
    }))
}

async fn remove_keyword(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, keyword_id)): Path<(String, String)>,
) -> ApiResult<axum::http::StatusCode> {
    if !nodus_server_store::filters::delete_keyword(
        state.store().pool(),
        &auth.0.account.id,
        &id,
        &keyword_id,
    )
    .await?
    {
        return Err(ApiError::not_found("keyword does not exist"));
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v2/filters", get(list).post(create))
        .route(
            "/api/v2/filters/{id}",
            get(show).put(update).delete(destroy),
        )
        .route("/api/v2/filters/{id}/keywords", post(add_keyword))
        .route(
            "/api/v2/filters/{id}/keywords/{keyword_id}",
            axum::routing::delete(remove_keyword),
        )
        .merge(router_v1())
}

// ------------------------------------------------------------------ v1 filter
//
// The adapter described in the module doc. `filter_keyword` rows keep their order of
// insertion, so "the first keyword" is stable.

#[derive(Debug, Serialize)]
struct FilterV1Dto {
    id: String,
    phrase: String,
    context: Vec<String>,
    expires_at: Option<DateTime<Utc>>,
    irreversible: bool,
    whole_word: bool,
}

#[derive(Debug, Default, Deserialize)]
struct FilterV1Request {
    #[serde(default)]
    phrase: String,
    context: Vec<String>,
    expires_in: Option<i64>,
    irreversible: bool,
    whole_word: bool,
}

/// Reads a v1 filter write from JSON or from the SDK's form encoding.
///
/// `serde_urlencoded` cannot collect repeated `context[]` keys into a list, so a form is
/// walked here by hand; the JSON body lints itself through serde.
fn parse_v1_request(headers: &HeaderMap, body: &Bytes) -> ApiResult<FilterV1Request> {
    let form_encoded = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("application/x-www-form-urlencoded")
        });
    if !form_encoded {
        return serde_json::from_slice(body)
            .map_err(|error| ApiError::unprocessable(format!("invalid request body: {error}")));
    }
    let mut request = FilterV1Request::default();
    for (key, value) in url::form_urlencoded::parse(body) {
        match key.as_ref() {
            "phrase" => request.phrase = value.into_owned(),
            "context[]" | "context" => request.context.push(value.into_owned()),
            "expires_in" if !value.trim().is_empty() => {
                request.expires_in = Some(value.parse::<i64>().map_err(|_| {
                    ApiError::unprocessable("expires_in must be a number of seconds")
                })?);
            }
            "irreversible" => request.irreversible = truthy(&value),
            "whole_word" => request.whole_word = truthy(&value),
            _ => {}
        }
    }
    Ok(request)
}

fn truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "on"
    )
}

async fn dto_v1(
    state: &AppState,
    row: nodus_server_store::filters::FilterRow,
) -> ApiResult<FilterV1Dto> {
    let keyword = nodus_server_store::filters::keywords(state.store().pool(), &row.id)
        .await?
        .into_iter()
        .next();
    let (phrase, whole_word) = match keyword {
        Some(keyword) => (keyword.keyword, keyword.whole_word),
        None => (row.title.clone(), false),
    };
    Ok(FilterV1Dto {
        id: row.id,
        phrase,
        context: row.context,
        expires_at: row.expires_at,
        irreversible: row.action == "hide",
        whole_word,
    })
}

fn validate_v1_request(body: &FilterV1Request) -> ApiResult<&str> {
    let phrase = body.phrase.trim();
    if phrase.is_empty() {
        return Err(ApiError::unprocessable("phrase is required"));
    }
    Ok(phrase)
}

/// `GET /api/v1/filters`
async fn list_v1(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<FilterV1Dto>>> {
    auth.require_scope("read:filters")?;
    let rows =
        nodus_server_store::filters::filters(state.store().pool(), &auth.0.account.id, 200).await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(dto_v1(&state, row).await?);
    }
    Ok(Json(out))
}

/// `POST /api/v1/filters`
async fn create_v1(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<FilterV1Dto>> {
    auth.require_scope("write:filters")?;
    let body = parse_v1_request(&headers, &body)?;
    let phrase = validate_v1_request(&body)?;
    let context = if body.context.is_empty() {
        default_context()
    } else {
        body.context.clone()
    };
    let action = if body.irreversible { "hide" } else { "warn" };
    let row = nodus_server_store::filters::create(
        state.store().pool(),
        &auth.0.account.id,
        phrase,
        &context,
        action,
        expiry(body.expires_in),
    )
    .await?;
    nodus_server_store::filters::add_keyword(
        state.store().pool(),
        &row.id,
        phrase,
        body.whole_word,
    )
    .await?;
    Ok(Json(dto_v1(&state, row).await?))
}

/// `PUT /api/v1/filters/{id}`
async fn update_v1(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<FilterV1Dto>> {
    auth.require_scope("write:filters")?;
    let body = parse_v1_request(&headers, &body)?;
    let phrase = validate_v1_request(&body)?;
    let context = if body.context.is_empty() {
        default_context()
    } else {
        body.context.clone()
    };
    let action = if body.irreversible { "hide" } else { "warn" };
    let row = nodus_server_store::filters::update(
        state.store().pool(),
        &auth.0.account.id,
        &id,
        phrase,
        &context,
        action,
        expiry(body.expires_in),
    )
    .await?
    .ok_or_else(|| ApiError::not_found("filter does not exist"))?;
    // v1 cannot express more than one phrase, so a v1 write replaces the keyword list.
    for keyword in nodus_server_store::filters::keywords(state.store().pool(), &row.id).await? {
        nodus_server_store::filters::delete_keyword(
            state.store().pool(),
            &auth.0.account.id,
            &row.id,
            &keyword.id,
        )
        .await?;
    }
    nodus_server_store::filters::add_keyword(
        state.store().pool(),
        &row.id,
        phrase,
        body.whole_word,
    )
    .await?;
    Ok(Json(dto_v1(&state, row).await?))
}

/// `DELETE /api/v1/filters/{id}`
async fn destroy_v1(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<axum::http::StatusCode> {
    auth.require_scope("write:filters")?;
    if !nodus_server_store::filters::delete(state.store().pool(), &auth.0.account.id, &id).await? {
        return Err(ApiError::not_found("filter does not exist"));
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

fn router_v1() -> Router<AppState> {
    Router::new()
        .route("/api/v1/filters", get(list_v1).post(create_v1))
        .route("/api/v1/filters/{id}", put(update_v1).delete(destroy_v1))
}
