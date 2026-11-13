//! Account lookup, follow graph and relationship endpoints.

use axum::extract::{Path, Query, RawQuery, State};
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use nodus_server_core::PageSize;
use nodus_server_store::accounts::AccountRow;
use nodus_server_store::social::{FollowOutcome, Relationship};

use crate::auth::Auth;
use crate::dto::AccountDto;
use crate::error::{ApiError, ApiResult};
use crate::mastodon::PageQuery;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct RelationshipDto {
    pub id: String,
    pub following: bool,
    pub showing_reblogs: bool,
    pub notifying: bool,
    pub requested: bool,
    pub blocked: bool,
    pub muting: bool,
    pub muting_notifications: bool,
    pub domain_blocking: bool,
    pub endorsed: bool,
    pub languages: Vec<String>,
}

impl RelationshipDto {
    fn new(id: &str, relationship: &Relationship) -> Self {
        Self {
            id: id.to_owned(),
            following: relationship.following,
            showing_reblogs: relationship.showing_reblogs,
            notifying: relationship.notifying,
            requested: relationship.requested,
            blocked: relationship.blocked,
            muting: relationship.muting,
            muting_notifications: relationship.muting_notifications,
            domain_blocking: false,
            endorsed: false,
            languages: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LookupQuery {
    pub acct: String,
}

pub async fn show(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<AccountDto>> {
    let account = nodus_server_store::accounts::by_id(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    Ok(Json(AccountDto::from_row(&account, state.instance())))
}

pub async fn lookup(
    State(state): State<AppState>,
    Query(query): Query<LookupQuery>,
) -> ApiResult<Json<AccountDto>> {
    let account = nodus_server_store::accounts::lookup(state.store().pool(), &query.acct)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    Ok(Json(AccountDto::from_row(&account, state.instance())))
}

pub async fn followers(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<PageQuery>,
) -> ApiResult<Response> {
    follow_list(state, id, query, true).await
}

pub async fn following(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<PageQuery>,
) -> ApiResult<Response> {
    follow_list(state, id, query, false).await
}

async fn follow_list(
    state: AppState,
    id: String,
    query: PageQuery,
    followers: bool,
) -> ApiResult<Response> {
    let params = query.params()?;
    let size = PageSize::clamp(params.limit, nodus_server_core::limits::PAGE_MAX_ACCOUNTS);
    let rows = nodus_server_store::accounts::follow_page(
        state.store().pool(),
        &id,
        followers,
        params.max_id.map(|id| id.to_string()).as_deref(),
        i64::from(size.get()) + 1,
    )
    .await?;
    let next = rows
        .get(size.get() as usize)
        .map(|_| rows[size.get() as usize - 1].id.clone());
    let items: Vec<_> = rows
        .into_iter()
        .take(size.get() as usize)
        .map(|row| AccountDto::from_row(&row, state.instance()))
        .collect();
    if let Some(next) = next {
        let path = format!(
            "/api/v1/accounts/{id}/{}",
            if followers { "followers" } else { "following" }
        );
        let link = params.next_link(&path, next.parse().ok(), size);
        let mut response = Json(items).into_response();
        if let Some(link) = link {
            if let Ok(value) = HeaderValue::from_str(&link) {
                response
                    .headers_mut()
                    .insert(axum::http::header::LINK, value);
            }
        }
        return Ok(response);
    }
    Ok(Json(items).into_response())
}

pub async fn follow(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<RelationshipDto>> {
    auth.require_scope("write:follows")?;
    let target = target(&state, &id).await?;
    let outcome = nodus_server_store::social::follow(
        state.store().pool(),
        &auth.0.account.id,
        &target.id,
        true,
        false,
    )
    .await?;
    if outcome == FollowOutcome::Following {
        nodus_server_store::social::notify(
            state.store().pool(),
            &target.id,
            "follow",
            &auth.0.account.id,
            None,
        )
        .await?;
    }
    let relationship =
        nodus_server_store::social::relationship(state.store().pool(), &auth.0.account.id, &id)
            .await?;
    Ok(Json(RelationshipDto::new(&id, &relationship)))
}

pub async fn unfollow(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<RelationshipDto>> {
    auth.require_scope("write:follows")?;
    nodus_server_store::social::unfollow(state.store().pool(), &auth.0.account.id, &id).await?;
    let relationship =
        nodus_server_store::social::relationship(state.store().pool(), &auth.0.account.id, &id)
            .await?;
    Ok(Json(RelationshipDto::new(&id, &relationship)))
}

pub async fn block(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<RelationshipDto>> {
    auth.require_scope("write:blocks")?;
    nodus_server_store::social::block(state.store().pool(), &auth.0.account.id, &id).await?;
    let relationship =
        nodus_server_store::social::relationship(state.store().pool(), &auth.0.account.id, &id)
            .await?;
    Ok(Json(RelationshipDto::new(&id, &relationship)))
}

pub async fn unblock(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<RelationshipDto>> {
    auth.require_scope("write:blocks")?;
    nodus_server_store::social::unblock(state.store().pool(), &auth.0.account.id, &id).await?;
    let relationship =
        nodus_server_store::social::relationship(state.store().pool(), &auth.0.account.id, &id)
            .await?;
    Ok(Json(RelationshipDto::new(&id, &relationship)))
}

pub async fn mute(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    axum::extract::RawForm(body): axum::extract::RawForm,
) -> ApiResult<Json<RelationshipDto>> {
    auth.require_scope("write:mutes")?;
    let notifications = !url::form_urlencoded::parse(&body)
        .any(|(key, value)| key == "notifications" && value == "false");
    nodus_server_store::social::mute(state.store().pool(), &auth.0.account.id, &id, notifications)
        .await?;
    let relationship =
        nodus_server_store::social::relationship(state.store().pool(), &auth.0.account.id, &id)
            .await?;
    Ok(Json(RelationshipDto::new(&id, &relationship)))
}

pub async fn unmute(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<RelationshipDto>> {
    auth.require_scope("write:mutes")?;
    nodus_server_store::social::unmute(state.store().pool(), &auth.0.account.id, &id).await?;
    let relationship =
        nodus_server_store::social::relationship(state.store().pool(), &auth.0.account.id, &id)
            .await?;
    Ok(Json(RelationshipDto::new(&id, &relationship)))
}

pub async fn blocks(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<AccountDto>>> {
    auth.require_scope("read:blocks")?;
    let rows =
        nodus_server_store::social::relations(state.store().pool(), &auth.0.account.id, "block")
            .await?;
    Ok(Json(
        rows.iter()
            .map(|row| AccountDto::from_row(row, state.instance()))
            .collect(),
    ))
}

pub async fn mutes(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<AccountDto>>> {
    auth.require_scope("read:mutes")?;
    let rows =
        nodus_server_store::social::relations(state.store().pool(), &auth.0.account.id, "mute")
            .await?;
    Ok(Json(
        rows.iter()
            .map(|row| AccountDto::from_row(row, state.instance()))
            .collect(),
    ))
}

pub async fn relationships(
    State(state): State<AppState>,
    auth: Auth,
    RawQuery(query): RawQuery,
) -> ApiResult<Json<Vec<RelationshipDto>>> {
    auth.require_scope("read:follows")?;
    let ids = parse_id_list(query.as_deref().unwrap_or_default());
    let mut relationships = Vec::with_capacity(ids.len());
    for id in ids {
        let relationship =
            nodus_server_store::social::relationship(state.store().pool(), &auth.0.account.id, &id)
                .await?;
        relationships.push(RelationshipDto::new(&id, &relationship));
    }
    Ok(Json(relationships))
}

fn parse_id_list(raw: &str) -> Vec<String> {
    url::form_urlencoded::parse(raw.as_bytes())
        .filter(|(key, _)| key == "id[]" || key == "id")
        .map(|(_, value)| value.into_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

async fn target(state: &AppState, id: &str) -> ApiResult<AccountRow> {
    nodus_server_store::accounts::by_id(state.store().pool(), id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))
}
