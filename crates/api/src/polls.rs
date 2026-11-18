//! Polls: one document, two doors.
//!
//! `GET` is readable signed out; `POST .../votes` needs a token. The document is the one
//! the console already renders (`web`'s `PollBlock` and the SDK's `Poll` model), so the
//! same shape is used inside a status and at `/api/v1/polls/{id}`.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde_json::Value;

use nodus_server_store::polls::{self, PollRow};

use crate::auth::{Auth, MaybeAuth};
use crate::dto::{PollDto, PollOptionDto};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::statuses::visible_status_for_viewer;

/// A poll's public document, built from the stored row and its votes.
pub(crate) async fn document(
    state: &AppState,
    row: &PollRow,
    viewer: Option<&str>,
) -> ApiResult<PollDto> {
    let pool = state.store().pool();
    // A local poll counts its own `poll_vote` rows; a federated poll keeps the snapshot
    // the peer sent, because nobody here voted and inventing voters would double count.
    let (counts, voter_count) = if row.local {
        let counts: HashMap<i32, i64> = polls::option_counts(pool, &row.id)
            .await?
            .into_iter()
            .map(|count| (count.option_index, count.votes))
            .collect();
        (counts, polls::voters_count(pool, &row.id).await?)
    } else {
        let counts: HashMap<i32, i64> = polls::tally_counts(pool, &row.id)
            .await?
            .into_iter()
            .map(|count| (count.option_index, count.votes))
            .collect();
        (counts, row.voters_count)
    };
    let total_votes = counts.values().sum();
    let expired = row.expires_at.is_some_and(|at| at <= Utc::now());
    let (voted, own_votes) = match viewer {
        Some(account_id) => (
            Some(polls::has_voted(pool, &row.id, account_id).await?),
            Some(
                polls::own_votes(pool, &row.id, account_id)
                    .await?
                    .into_iter()
                    .map(|index| usize::try_from(index).unwrap_or(0))
                    .collect(),
            ),
        ),
        None => (None, None),
    };
    Ok(PollDto {
        id: row.id.clone(),
        expires_at: row.expires_at,
        expired,
        multiple: row.multiple,
        votes_count: total_votes,
        voters_count: voter_count,
        voted,
        own_votes,
        options: row
            .options
            .0
            .iter()
            .enumerate()
            .map(|(index, title)| PollOptionDto {
                title: title.clone(),
                votes_count: counts
                    .get(&i32::try_from(index).unwrap_or(i32::MAX))
                    .copied()
                    .unwrap_or(0),
            })
            .collect(),
    })
}

/// The `poll` field of a status, or `None` when the status has no poll.
pub(crate) async fn status_poll(
    state: &AppState,
    status_id: &str,
    viewer: Option<&str>,
) -> ApiResult<Option<Value>> {
    let Some(row) = polls::by_status(state.store().pool(), status_id).await? else {
        return Ok(None);
    };
    let document = document(state, &row, viewer).await?;
    serde_json::to_value(document).map(Some).map_err(|error| {
        ApiError::new(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            error.to_string(),
        )
    })
}

/// `GET /api/v1/polls/{id}`
pub async fn show(
    State(state): State<AppState>,
    MaybeAuth(auth): MaybeAuth,
    Path(id): Path<String>,
) -> ApiResult<Json<PollDto>> {
    let viewer = auth.as_ref().map(|auth| auth.0.account.id.as_str());
    let row = load(&state, &id, viewer).await?;
    Ok(Json(document(&state, &row, viewer).await?))
}

/// `POST /api/v1/polls/{id}/votes`
///
/// Mastodon's clients send `choices[]=0&choices[]=1` form-encoded; JSON is accepted too
/// for callers that speak it. The poll is returned after the write, not a separate
/// receipt, because the console replaces its status with the response body.
pub async fn vote(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<PollDto>> {
    auth.require_scope("write:statuses")?;
    let account_id = auth.0.account.id.as_str();
    let row = load(&state, &id, Some(account_id)).await?;

    if !row.local {
        return Err(ApiError::unprocessable(
            "Validation failed: this poll belongs to another instance",
        ));
    }
    if row.expires_at.is_some_and(|at| at <= Utc::now()) {
        return Err(ApiError::unprocessable(
            "Validation failed: this poll has ended",
        ));
    }

    let choices = parse_choices(&headers, &body)?;
    if choices.is_empty() {
        return Err(ApiError::unprocessable(
            "Validation failed: choices must not be empty",
        ));
    }
    let option_count = i64::try_from(row.options.0.len()).unwrap_or(i64::MAX);
    for choice in &choices {
        if *choice < 0 || *choice >= option_count {
            return Err(ApiError::unprocessable(format!(
                "Validation failed: choice {choice} is out of range"
            )));
        }
    }
    if !row.multiple && choices.len() > 1 {
        return Err(ApiError::unprocessable(
            "Validation failed: this poll does not allow multiple choices",
        ));
    }

    let choices: Vec<i32> = choices
        .into_iter()
        .map(|choice| i32::try_from(choice).unwrap_or(0))
        .collect();
    polls::vote(state.store().pool(), &row.id, account_id, &choices).await?;
    Ok(Json(document(&state, &row, Some(account_id)).await?))
}

/// Loads a poll and checks the reader may see the status it belongs to. An invisible
/// poll is a `404`, exactly like an invisible status.
async fn load(state: &AppState, id: &str, viewer: Option<&str>) -> ApiResult<PollRow> {
    let row = polls::by_id(state.store().pool(), id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    visible_status_for_viewer(state, viewer, &row.status_id).await?;
    Ok(row)
}

/// Reads the chosen indexes from the two bodies Mastodon clients send.
fn parse_choices(headers: &HeaderMap, body: &Bytes) -> ApiResult<Vec<i64>> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if content_type.starts_with("application/x-www-form-urlencoded") {
        let mut choices = Vec::new();
        for (key, value) in url::form_urlencoded::parse(body) {
            if key == "choices[]" || key == "choices" {
                let index = value.parse::<i64>().map_err(|_| {
                    ApiError::unprocessable("Validation failed: choices must be a list of indexes")
                })?;
                choices.push(index);
            }
        }
        return Ok(choices);
    }

    if body.is_empty() {
        return Ok(Vec::new());
    }
    let value: Value = serde_json::from_slice(body).map_err(|_| {
        ApiError::unprocessable("Validation failed: choices must be a list of indexes")
    })?;
    let raw = value
        .get("choices")
        .or_else(|| value.get("choices[]"))
        .cloned();
    match raw {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .into_iter()
            .map(|item| {
                item.as_i64().ok_or_else(|| {
                    ApiError::unprocessable("Validation failed: choices must be a list of indexes")
                })
            })
            .collect(),
        Some(_) => Err(ApiError::unprocessable(
            "Validation failed: choices must be a list of indexes",
        )),
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/polls/{id}", get(show))
        .route("/api/v1/polls/{id}/votes", post(vote))
}
