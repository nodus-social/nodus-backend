//! Mastodon conversations: direct-message threads.
//!
//! A conversation is derived, not stored — see `nodus_server_store::conversations` for
//! why. The payload is the newest status in the thread plus its participants, which is
//! everything a client needs to render an inbox row.

use std::collections::HashMap;

use axum::extract::{Path, State};
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use nodus_server_core::limits::PAGE_MAX;
use nodus_server_core::pagination::PageSize;

use crate::auth::Auth;
use crate::dto::{accounts_with_pictures, AccountDto, StatusDto};
use crate::error::{ApiError, ApiResult};
use crate::mastodon::PageQuery;
use crate::state::AppState;
use crate::statuses;

#[derive(Debug, Serialize)]
pub struct ConversationDto {
    pub id: String,
    pub unread: bool,
    pub muted: bool,
    pub accounts: Vec<AccountDto>,
    pub last_status: Option<StatusDto>,
}

#[derive(Debug, Deserialize)]
pub struct ReadInput {
    pub last_status_id: Option<String>,
}

/// `GET /api/v1/conversations`
pub async fn list(
    State(state): State<AppState>,
    auth: Auth,
    axum::extract::Query(query): axum::extract::Query<PageQuery>,
) -> ApiResult<Response> {
    auth.require_scope("read:statuses")?;
    let params = query.params()?;
    let size = PageSize::clamp(params.limit, PAGE_MAX);
    let cursor = params.max_id.map(|id| id.to_string());
    let pool = state.store().pool();
    let rows = nodus_server_store::conversations::page(
        pool,
        &auth.0.account.id,
        cursor.as_deref(),
        i64::from(size.get()),
    )
    .await?;

    let roots: Vec<String> = rows.iter().map(|row| row.root_id.clone()).collect();
    let muted =
        nodus_server_store::conversations::muted_roots(pool, &auth.0.account.id, &roots).await?;
    let mut by_root: HashMap<String, Vec<String>> = HashMap::new();
    for (root, account) in
        nodus_server_store::conversations::participants(pool, &auth.0.account.id, &roots).await?
    {
        by_root.entry(root).or_default().push(account);
    }
    // The join above still names participants; one batch then fetches their rows, so a
    // page of twenty threads costs one account query rather than one per participant.
    let mut participant_ids: Vec<String> = by_root.values().flatten().cloned().collect();
    participant_ids.sort_unstable();
    participant_ids.dedup();
    let mut participant_outcome = None;
    if !participant_ids.is_empty() {
        participant_outcome = Some(
            state
                .store()
                .batch()
                .accounts(&participant_ids)
                .profile_pictures(&participant_ids)
                .run()
                .await?,
        );
    }

    // The inbox is a page: its threads' last statuses are named in one read and painted
    // by one page hydration, so a page of twenty does not pay twenty status builds. The
    // unread/muted flags and participant order still come from `rows`.
    let last_ids: Vec<String> = rows.iter().map(|row| row.last_status_id.clone()).collect();
    let last_rows = nodus_server_store::statuses::by_ids(pool, &last_ids).await?;
    let viewer = Some(auth.0.account.id.as_str());
    let (hydrated, _, _) =
        crate::pages::hydrate_statuses(&state, last_rows, viewer, &[], None).await?;
    let mut last_statuses: HashMap<String, StatusDto> = hydrated
        .into_iter()
        .map(|dto| (dto.id.clone(), dto))
        .collect();

    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        let participants = by_root.get(&row.root_id).map_or(&[][..], Vec::as_slice);
        let accounts = match &participant_outcome {
            Some(outcome) => {
                let ordered: Vec<&nodus_server_store::accounts::AccountRow> = participants
                    .iter()
                    .filter_map(|id| outcome.accounts.get(id))
                    .collect();
                accounts_with_pictures(ordered, outcome, state.instance())
            }
            None => Vec::new(),
        };
        let last_status = last_statuses.remove(&row.last_status_id);
        // Unread means the newest status arrived after the reader last opened the thread
        // and is not their own. A muted thread is still listed but stops asking for
        // attention, which is what muting a conversation is for.
        let muted = muted.contains(&row.root_id);
        let unread = !muted
            && row.last_author_id != auth.0.account.id
            && row
                .last_read_id
                .as_ref()
                .is_none_or(|read| *read < row.last_status_id);
        items.push(ConversationDto {
            id: row.root_id.clone(),
            unread,
            muted,
            accounts,
            last_status,
        });
    }

    let mut response = Json(items).into_response();
    if let Some(link) = rows
        .last()
        .and_then(|row| params.next_link("/api/v1/conversations", row.root_id.parse().ok(), size))
        .and_then(|link| HeaderValue::from_str(&link).ok())
    {
        response
            .headers_mut()
            .insert(axum::http::header::LINK, link);
    }
    Ok(response)
}

/// `POST /api/v1/conversations/{id}/read`
pub async fn read(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    body: Option<Json<ReadInput>>,
) -> ApiResult<Json<ConversationDto>> {
    auth.require_scope("write:conversations")?;
    let pool = state.store().pool();
    // The conversation must be one of the reader's, which the derived page already knows.
    let rows = nodus_server_store::conversations::page(pool, &auth.0.account.id, None, 100).await?;
    let row = rows
        .iter()
        .find(|row| row.root_id == id)
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    let last_read = body
        .and_then(|Json(input)| input.last_status_id)
        .unwrap_or_else(|| row.last_status_id.clone());
    nodus_server_store::markers::mark_conversation_read(
        pool,
        &auth.0.account.id,
        &row.root_id,
        &last_read,
    )
    .await?;
    let mut accounts = participant_dtos(&state, &auth, &id).await?;
    accounts.shrink_to_fit();
    let last_status = match nodus_server_store::statuses::by_id(pool, &row.last_status_id).await? {
        Some(status) => Some(statuses::dto(&state, &status, Some(&auth)).await?),
        None => None,
    };
    let muted = nodus_server_store::conversations::muted_roots(
        pool,
        &auth.0.account.id,
        std::slice::from_ref(&id),
    )
    .await?;
    Ok(Json(ConversationDto {
        id: row.root_id.clone(),
        unread: false,
        muted: !muted.is_empty(),
        accounts,
        last_status,
    }))
}

/// `POST /api/v1/conversations/{id}/mute`
pub async fn muted(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<ConversationDto>> {
    set_muted(&state, &auth, &id, true).await
}

/// `DELETE /api/v1/conversations/{id}/mute`
pub async fn unmuted(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<ConversationDto>> {
    set_muted(&state, &auth, &id, false).await
}

async fn set_muted(
    state: &AppState,
    auth: &Auth,
    id: &str,
    silenced: bool,
) -> ApiResult<Json<ConversationDto>> {
    auth.require_scope("write:conversations")?;
    let pool = state.store().pool();
    // Only a conversation the reader is part of can be muted; the derived page is the
    // authority on that.
    let rows = nodus_server_store::conversations::page(pool, &auth.0.account.id, None, 500).await?;
    let row = rows
        .iter()
        .find(|row| row.root_id == id)
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    nodus_server_store::conversations::set_muted(pool, &auth.0.account.id, id, silenced).await?;
    Ok(Json(conversation_dto(state, auth, row).await?))
}

/// One conversation row rendered as a payload.
async fn conversation_dto(
    state: &AppState,
    auth: &Auth,
    row: &nodus_server_store::conversations::ConversationRow,
) -> ApiResult<ConversationDto> {
    let pool = state.store().pool();
    let accounts = participant_dtos(state, auth, &row.root_id).await?;
    // One thread is a single subject: its newest status is painted by the single-status
    // path. The inbox list, which paints a page of them, hydrates them together instead.
    let last_status = match nodus_server_store::statuses::by_id(pool, &row.last_status_id).await? {
        Some(status) => Some(statuses::dto(state, &status, Some(auth)).await?),
        None => None,
    };
    let muted = nodus_server_store::conversations::muted_roots(
        pool,
        &auth.0.account.id,
        std::slice::from_ref(&row.root_id),
    )
    .await?;
    Ok(ConversationDto {
        id: row.root_id.clone(),
        unread: false,
        muted: !muted.is_empty(),
        accounts,
        last_status,
    })
}

/// One thread's participants as payloads, their rows read in one statement.
///
/// A thread is a single subject, but its participants are a page of accounts: the
/// participant list names them all, and one batch answers for all of them.
async fn participant_dtos(state: &AppState, auth: &Auth, root: &str) -> ApiResult<Vec<AccountDto>> {
    let mut ids: Vec<String> = nodus_server_store::conversations::participants(
        state.store().pool(),
        &auth.0.account.id,
        std::slice::from_ref(&root.to_owned()),
    )
    .await?
    .into_iter()
    .map(|(_, account_id)| account_id)
    .collect();
    // The join can name a person once per message; ask for each of them once.
    let mut seen = std::collections::HashSet::new();
    ids.retain(|id| seen.insert(id.clone()));
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let outcome = state
        .store()
        .batch()
        .accounts(&ids)
        .profile_pictures(&ids)
        .run()
        .await?;
    // A participant whose account row is gone is omitted rather than defaulted.
    let ordered: Vec<&nodus_server_store::accounts::AccountRow> = ids
        .iter()
        .filter_map(|id| outcome.accounts.get(id))
        .collect();
    Ok(accounts_with_pictures(ordered, &outcome, state.instance()))
}

/// The router fragment, mounted by `crate::router`.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/api/v1/conversations", get(list))
        .route("/api/v1/conversations/{id}/read", post(read))
        .route(
            "/api/v1/conversations/{id}/mute",
            post(muted).delete(unmuted),
        )
}
