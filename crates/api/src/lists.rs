//! Mastodon lists: client-owned groups of followed accounts.

use axum::extract::{Path, RawForm, State};
use axum::routing::get;
use axum::{Form, Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Debug, Serialize)]
struct ListDto {
    id: String,
    title: String,
    replies_policy: String,
    exclusive: bool,
}

impl From<nodus_server_store::lists::ListRow> for ListDto {
    fn from(row: nodus_server_store::lists::ListRow) -> Self {
        Self {
            id: row.id,
            title: row.title,
            replies_policy: row.replies_policy,
            exclusive: row.exclusive,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ListForm {
    title: String,
    #[serde(default = "default_policy")]
    replies_policy: String,
    #[serde(default)]
    exclusive: bool,
}

fn default_policy() -> String {
    "list".to_owned()
}

fn account_ids(body: &[u8]) -> Vec<String> {
    url::form_urlencoded::parse(body)
        .filter(|(key, _)| key == "account_ids[]" || key == "account_ids")
        .map(|(_, value)| value.into_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

async fn lists(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<ListDto>>> {
    let rows =
        nodus_server_store::lists::lists(state.store().pool(), &auth.0.account.id, 200).await?;
    Ok(Json(rows.into_iter().map(ListDto::from).collect()))
}

async fn create(
    State(state): State<AppState>,
    auth: Auth,
    Form(form): Form<ListForm>,
) -> ApiResult<Json<ListDto>> {
    let title = form.title.trim();
    if title.is_empty() {
        return Err(ApiError::unprocessable("title is required"));
    }
    let row = nodus_server_store::lists::create(
        state.store().pool(),
        &auth.0.account.id,
        title,
        &form.replies_policy,
        form.exclusive,
    )
    .await?;
    Ok(Json(row.into()))
}

async fn show(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<ListDto>> {
    let row = nodus_server_store::lists::list(state.store().pool(), &auth.0.account.id, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("list does not exist"))?;
    Ok(Json(row.into()))
}

async fn update(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Form(form): Form<ListForm>,
) -> ApiResult<Json<ListDto>> {
    let title = form.title.trim();
    if title.is_empty() {
        return Err(ApiError::unprocessable("title is required"));
    }
    let row = nodus_server_store::lists::update(
        state.store().pool(),
        &auth.0.account.id,
        &id,
        title,
        &form.replies_policy,
        form.exclusive,
    )
    .await?
    .ok_or_else(|| ApiError::not_found("list does not exist"))?;
    Ok(Json(row.into()))
}

async fn destroy(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<axum::http::StatusCode> {
    if !nodus_server_store::lists::delete(state.store().pool(), &auth.0.account.id, &id).await? {
        return Err(ApiError::not_found("list does not exist"));
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn accounts(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<crate::dto::AccountDto>>> {
    if nodus_server_store::lists::list(state.store().pool(), &auth.0.account.id, &id)
        .await?
        .is_none()
    {
        return Err(ApiError::not_found("list does not exist"));
    }
    let ids = nodus_server_store::lists::account_ids(state.store().pool(), &id, 200).await?;
    let mut out = Vec::with_capacity(ids.len());
    for account_id in ids {
        if let Some(row) =
            nodus_server_store::accounts::by_id(state.store().pool(), &account_id).await?
        {
            out.push(crate::dto::AccountDto::from_row(&row, state.instance()));
        }
    }
    Ok(Json(out))
}

async fn add_accounts(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    RawForm(body): RawForm,
) -> ApiResult<Json<serde_json::Value>> {
    if nodus_server_store::lists::list(state.store().pool(), &auth.0.account.id, &id)
        .await?
        .is_none()
    {
        return Err(ApiError::not_found("list does not exist"));
    }
    for account_id in account_ids(&body) {
        nodus_server_store::lists::add_account(state.store().pool(), &id, &account_id).await?;
    }
    Ok(Json(serde_json::json!({})))
}

async fn remove_accounts(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    RawForm(body): RawForm,
) -> ApiResult<Json<serde_json::Value>> {
    if nodus_server_store::lists::list(state.store().pool(), &auth.0.account.id, &id)
        .await?
        .is_none()
    {
        return Err(ApiError::not_found("list does not exist"));
    }
    for account_id in account_ids(&body) {
        nodus_server_store::lists::remove_account(state.store().pool(), &id, &account_id).await?;
    }
    Ok(Json(serde_json::json!({})))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/lists", get(lists).post(create))
        .route("/api/v1/lists/{id}", get(show).put(update).delete(destroy))
        .route(
            "/api/v1/lists/{id}/accounts",
            get(accounts).post(add_accounts).delete(remove_accounts),
        )
}
