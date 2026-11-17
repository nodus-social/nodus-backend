//! Mastodon lists: client-owned groups of followed accounts.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::Auth;
use crate::body::JsonOrForm;
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

/// The accounts a membership change names, in whichever spelling the client sent.
///
/// Mastodon clients form-encode `account_ids[]=1&account_ids[]=2`; anything sending JSON
/// sends `{"account_ids": ["1"]}`. Both land here, because a 415 on the second shape is a
/// failure the client cannot see coming.
#[derive(Debug, Default, Deserialize)]
struct MembershipForm {
    #[serde(default)]
    account_ids: Vec<String>,
    #[serde(default, rename = "account_ids[]")]
    bracketed_ids: Vec<String>,
    #[serde(default)]
    single_id: Option<String>,
}

impl MembershipForm {
    fn ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .account_ids
            .iter()
            .chain(self.bracketed_ids.iter())
            .chain(self.single_id.iter())
            .filter(|value| !value.is_empty())
            .cloned()
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }
}

async fn lists(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<ListDto>>> {
    let rows =
        nodus_server_store::lists::lists(state.store().pool(), &auth.0.account.id, 200).await?;
    Ok(Json(rows.into_iter().map(ListDto::from).collect()))
}

fn validate_list_form(form: &ListForm) -> ApiResult<&str> {
    let title = form.title.trim();
    if title.is_empty() {
        return Err(ApiError::unprocessable("title is required"));
    }
    if !matches!(form.replies_policy.as_str(), "followed" | "list" | "none") {
        return Err(ApiError::unprocessable(
            "replies_policy must be followed, list, or none",
        ));
    }
    Ok(title)
}

async fn create(
    State(state): State<AppState>,
    auth: Auth,
    JsonOrForm(form): JsonOrForm<ListForm>,
) -> ApiResult<Json<ListDto>> {
    let title = validate_list_form(&form)?;
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
    JsonOrForm(form): JsonOrForm<ListForm>,
) -> ApiResult<Json<ListDto>> {
    let title = validate_list_form(&form)?;
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
    JsonOrForm(body): JsonOrForm<MembershipForm>,
) -> ApiResult<Json<serde_json::Value>> {
    if nodus_server_store::lists::list(state.store().pool(), &auth.0.account.id, &id)
        .await?
        .is_none()
    {
        return Err(ApiError::not_found("list does not exist"));
    }
    for account_id in body.ids() {
        nodus_server_store::lists::add_account(state.store().pool(), &id, &account_id).await?;
    }
    Ok(Json(serde_json::json!({})))
}

async fn remove_accounts(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    JsonOrForm(body): JsonOrForm<MembershipForm>,
) -> ApiResult<Json<serde_json::Value>> {
    if nodus_server_store::lists::list(state.store().pool(), &auth.0.account.id, &id)
        .await?
        .is_none()
    {
        return Err(ApiError::not_found("list does not exist"));
    }
    for account_id in body.ids() {
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
