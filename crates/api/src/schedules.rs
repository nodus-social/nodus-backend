//! Posts waiting to go out.
//!
//! A scheduled post is created through `POST /api/v1/statuses` with `scheduled_at`, and
//! then published by [`run`]. The row is deleted only after the status exists, so a crash
//! between the two cannot lose the post; a crash *after* the status exists but before the
//! delete would publish it twice, which is why the delete is the last thing that happens
//! and is retried on the next pass by the unique id.

use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::statuses::CreateStatus;

/// The composed post, echoed back exactly as stored.
#[derive(Debug, Serialize, Deserialize)]
pub struct ScheduledParams {
    #[serde(default)]
    pub text: String,
    pub visibility: String,
    pub sensitive: bool,
    pub spoiler_text: String,
    #[serde(default)]
    pub media_ids: Vec<String>,
    #[serde(default)]
    pub in_reply_to_id: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
}

/// One queued post, as Mastodon shapes it.
#[derive(Debug, Serialize)]
pub struct ScheduledStatusDto {
    pub id: String,
    pub scheduled_at: String,
    pub params: ScheduledParams,
}

impl ScheduledStatusDto {
    fn from_row(row: &nodus_server_store::schedules::ScheduledRow) -> Self {
        // A row written by an older build could carry a shape we no longer parse; showing
        // an empty draft is better than failing the whole list.
        let params = serde_json::from_value::<ScheduledParams>(row.params.clone()).unwrap_or(
            ScheduledParams {
                text: String::new(),
                visibility: "public".to_owned(),
                sensitive: false,
                spoiler_text: String::new(),
                media_ids: Vec::new(),
                in_reply_to_id: None,
                language: None,
            },
        );
        Self {
            id: row.id.clone(),
            scheduled_at: row.scheduled_at.to_rfc3339(),
            params,
        }
    }
}

/// `GET /api/v1/scheduled_statuses`
pub async fn list(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<Vec<ScheduledStatusDto>>> {
    auth.require_scope("read:statuses")?;
    let rows =
        nodus_server_store::schedules::list(state.store().pool(), &auth.0.account.id).await?;
    Ok(Json(
        rows.iter().map(ScheduledStatusDto::from_row).collect(),
    ))
}

/// `DELETE /api/v1/scheduled_statuses/{id}`
pub async fn cancel(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    auth.require_scope("write:statuses")?;
    let removed =
        nodus_server_store::schedules::cancel(state.store().pool(), &auth.0.account.id, &id)
            .await?;
    if !removed {
        return Err(ApiError::not_found("Record not found"));
    }
    Ok(StatusCode::OK)
}

/// Stores a queued post. Called from `statuses::create` when the client sends
/// `scheduled_at`.
pub(crate) async fn store(
    state: &AppState,
    account_id: &str,
    at: DateTime<Utc>,
    request: &CreateStatus,
) -> ApiResult<ScheduledStatusDto> {
    let params = ScheduledParams {
        text: request.status.clone(),
        visibility: request
            .visibility
            .clone()
            .unwrap_or_else(|| "public".to_owned())
            .to_ascii_lowercase(),
        sensitive: request.sensitive.unwrap_or(false),
        spoiler_text: request.spoiler_text.clone().unwrap_or_default(),
        media_ids: request.media_ids.clone(),
        in_reply_to_id: request.in_reply_to_id.clone(),
        language: request.language.clone().filter(|value| !value.is_empty()),
    };
    let value = serde_json::to_value(&params)
        .map_err(|error| ApiError::unprocessable(format!("could not store the post: {error}")))?;
    let row = nodus_server_store::schedules::create(
        state.store().pool(),
        &nodus_server_core::Id::new().to_string(),
        account_id,
        at,
        &value,
    )
    .await?;
    Ok(ScheduledStatusDto::from_row(&row))
}

/// Publishes every post whose time has come. Returns how many went out.
pub async fn publish_due(state: &AppState) -> ApiResult<usize> {
    let rows = nodus_server_store::schedules::due(state.store().pool(), 50).await?;
    let mut published = 0;
    for row in &rows {
        let Ok(params) = serde_json::from_value::<ScheduledParams>(row.params.clone()) else {
            // A row we cannot read is one we will never publish; drop it rather than fail
            // the same way every half minute forever.
            tracing::warn!(id = %row.id, "dropping an unreadable scheduled post");
            nodus_server_store::schedules::remove(state.store().pool(), &row.id).await?;
            continue;
        };
        let request = CreateStatus {
            status: params.text,
            visibility: Some(params.visibility),
            sensitive: Some(params.sensitive),
            spoiler_text: Some(params.spoiler_text),
            language: params.language,
            in_reply_to_id: params.in_reply_to_id,
            media_ids: params.media_ids,
            content_type: None,
            scheduled_at: None,
        };
        match crate::statuses::publish(state, &row.account_id, request).await {
            Ok(status) => {
                nodus_server_store::schedules::remove(state.store().pool(), &row.id).await?;
                published += 1;
                tracing::info!(id = %row.id, status = %status.id, "scheduled post published");
            }
            // Leaving the row means the next pass tries again: the common reason is a
            // post that becomes valid later, such as media that finished processing.
            Err(error) => {
                tracing::warn!(id = %row.id, error = %error.message(), "scheduled post not published");
            }
        }
    }
    Ok(published)
}

/// Publishes due posts every half minute, for the life of the process.
pub async fn run(state: AppState) {
    let mut ticker = tokio::time::interval(Duration::from_secs(30));
    // The first tick fires immediately; skipping it keeps startup cheap.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        match publish_due(&state).await {
            Ok(0) => {}
            Ok(count) => tracing::info!(count, "scheduled posts published"),
            Err(error) => tracing::warn!(error = %error.message(), "scheduled post sweep failed"),
        }
    }
}

/// The router fragment, mounted by `crate::router`.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::{delete, get};
    axum::Router::new()
        .route("/api/v1/scheduled_statuses", get(list))
        .route("/api/v1/scheduled_statuses/{id}", delete(cancel))
}
