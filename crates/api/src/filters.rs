//! Mastodon v2 keyword filters.

use axum::extract::{Path, State};
use axum::routing::{get, post};
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

async fn create(
    State(state): State<AppState>,
    auth: Auth,
    Json(body): Json<FilterRequest>,
) -> ApiResult<Json<FilterDto>> {
    let title = body.title.trim();
    if title.is_empty() {
        return Err(ApiError::unprocessable("title is required"));
    }
    if body.filter_action != "warn" && body.filter_action != "hide" {
        return Err(ApiError::unprocessable(
            "filter_action must be warn or hide",
        ));
    }
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
    let title = body.title.trim();
    if title.is_empty() {
        return Err(ApiError::unprocessable("title is required"));
    }
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
}
