//! Mastodon notification endpoints.
//!
//! Notifications are written by the follow, favourite, reblog and mention paths through
//! `social::notify`; this module only reads and acknowledges them, so a notification can
//! never be produced by a read.

use axum::extract::{Path, Query, RawQuery, State};
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Serialize;

use nodus_server_core::limits::PAGE_MAX;
use nodus_server_core::pagination::PageSize;
use nodus_server_store::social::NotificationRow;

use crate::auth::Auth;
use crate::dto::{AccountDto, StatusDto};
use crate::error::{ApiError, ApiResult};
use crate::mastodon::PageQuery;
use crate::state::AppState;
use crate::statuses;

/// Every kind this server can produce. Mastodon also has `update` (an edited status) and
/// `admin.sign_up`; both are accepted as filters and simply match nothing.
const KINDS: [&str; 6] = ["follow", "favourite", "reblog", "mention", "status", "poll"];

/// One notification, in Mastodon's shape.
#[derive(Debug, Serialize)]
pub struct NotificationDto {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub created_at: DateTime<Utc>,
    pub account: AccountDto,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusDto>,
    /// Clients group duplicates by this; we notify once per event, so it is per row.
    pub group_key: String,
    /// How many events this line covers. A poll with twenty voters is one line with the
    /// latest voter in `account` and 20 here; every other kind reports 1.
    pub group_count: i32,
}

/// The filter parameters Mastodon accepts as repeated `types[]` keys.
///
/// `serde_urlencoded` cannot express an array, so these are read from the raw query
/// string rather than through a `Query<T>` extractor.
#[derive(Debug, Default)]
struct NotificationFilter {
    types: Vec<String>,
    exclude_types: Vec<String>,
}

impl NotificationFilter {
    fn parse(raw: Option<&str>) -> Self {
        let mut filter = Self::default();
        for (key, value) in url::form_urlencoded::parse(raw.unwrap_or_default().as_bytes()) {
            match key.as_ref() {
                "types[]" | "types" => filter.types.extend(split_list(&value)),
                "exclude_types[]" | "exclude_types" => {
                    filter.exclude_types.extend(split_list(&value));
                }
                _ => {}
            }
        }
        filter
    }

    /// The kinds to ask the store for.
    ///
    /// An unknown `types[]` value is ignored rather than rejected: Mastodon returns only
    /// the kinds it knows, and a client that asks for `admin.sign_up` should get an empty
    /// page, not a `422`.
    fn kinds(&self) -> Vec<String> {
        let wanted: Vec<String> = if self.types.is_empty() {
            KINDS.iter().map(ToString::to_string).collect()
        } else {
            KINDS
                .iter()
                .filter(|kind| self.types.iter().any(|asked| asked == *kind))
                .map(ToString::to_string)
                .collect()
        };
        wanted
            .into_iter()
            .filter(|kind| !self.exclude_types.iter().any(|skip| skip == kind))
            .collect()
    }
}

/// Accepts both `types[]=a&types[]=b` and the comma-separated form some clients send.
fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// `GET /api/v1/notifications`
pub async fn list(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<PageQuery>,
    RawQuery(raw): RawQuery,
) -> ApiResult<Response> {
    auth.require_scope("read:notifications")?;
    let params = query.params()?;
    let size = PageSize::clamp(params.limit, PAGE_MAX);
    let filter = NotificationFilter::parse(raw.as_deref());
    let kinds = filter.kinds();
    if kinds.is_empty() {
        // Every kind was excluded, so the page is empty by construction. Novel kinds are
        // not an error, which is why this is checked here and not in the filter parser.
        return Ok((
            axum::http::StatusCode::OK,
            Json(Vec::<NotificationDto>::new()),
        )
            .into_response());
    }
    let cursor = params.max_id.map(|id| id.to_string());
    let rows = nodus_server_store::social::notifications(
        state.store().pool(),
        &auth.0.account.id,
        cursor.as_deref(),
        i64::from(size.get()),
        &kinds,
    )
    .await?;

    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        items.push(dto(&state, row, Some(&auth)).await?);
    }

    let next = rows.last().map(|row| row.id.clone());
    let mut response = Json(items).into_response();
    if let Some(link) = next.and_then(|id| {
        params
            .next_link("/api/v1/notifications", id.parse().ok(), size)
            .and_then(|link| HeaderValue::from_str(&link).ok())
    }) {
        response
            .headers_mut()
            .insert(axum::http::header::LINK, link);
    }
    Ok(response)
}

/// `GET /api/v1/notifications/{id}`
pub async fn show(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<NotificationDto>> {
    auth.require_scope("read:notifications")?;
    let row = notification(&state, &auth, &id).await?;
    Ok(Json(dto(&state, &row, Some(&auth)).await?))
}

/// `POST /api/v1/notifications/{id}` — marks one notification seen.
pub async fn mark_seen(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<NotificationDto>> {
    auth.require_scope("write:notifications")?;
    let row = notification(&state, &auth, &id).await?;
    nodus_server_store::social::mark_seen(state.store().pool(), &auth.0.account.id, &id).await?;
    Ok(Json(dto(&state, &row, Some(&auth)).await?))
}

/// `POST /api/v1/notifications/{id}/dismiss`
pub async fn dismiss(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<NotificationDto>> {
    auth.require_scope("write:notifications")?;
    let row = notification(&state, &auth, &id).await?;
    nodus_server_store::social::dismiss_notification(state.store().pool(), &auth.0.account.id, &id)
        .await?;
    Ok(Json(dto(&state, &row, Some(&auth)).await?))
}

/// `POST /api/v1/notifications/clear`
pub async fn clear(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_scope("write:notifications")?;
    nodus_server_store::social::clear_notifications(state.store().pool(), &auth.0.account.id)
        .await?;
    Ok(Json(serde_json::json!({})))
}

/// One of the reader's own notifications, or a `404` that says nothing about others'.
async fn notification(state: &AppState, auth: &Auth, id: &str) -> ApiResult<NotificationRow> {
    // There is no single-row lookup in the store, and a page of one is not worth a query
    // of its own; the list is bounded by the reader's own newest hundred.
    let rows = nodus_server_store::social::notifications(
        state.store().pool(),
        &auth.0.account.id,
        None,
        100,
        &KINDS.iter().map(ToString::to_string).collect::<Vec<_>>(),
    )
    .await?;
    rows.into_iter()
        .find(|row| row.id == id)
        .ok_or_else(|| ApiError::not_found("Record not found"))
}

/// Builds the payload, loading the sender and the status it refers to.
async fn dto(
    state: &AppState,
    row: &NotificationRow,
    viewer: Option<&Auth>,
) -> ApiResult<NotificationDto> {
    let account = nodus_server_store::accounts::by_id(state.store().pool(), &row.from_account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    let status = match &row.status_id {
        None => None,
        Some(id) => match nodus_server_store::statuses::by_id(state.store().pool(), id).await? {
            Some(status) => Some(statuses::dto(state, &status, viewer).await?),
            // A notification whose status was deleted stays readable as the event it
            // records; a client shows "liked your post" without a post body.
            None => None,
        },
    };
    let kind = KINDS
        .iter()
        .find(|kind| **kind == row.kind)
        .copied()
        .unwrap_or("status");
    Ok(NotificationDto {
        id: row.id.clone(),
        kind,
        created_at: row.created_at,
        account: AccountDto::from_row(&account, state.instance()),
        status,
        group_key: format!(
            "{}:{}",
            kind,
            row.status_id.as_deref().unwrap_or(&row.from_account_id)
        ),
        group_count: row.group_count,
    })
}

/// The router fragment, mounted by `crate::router`.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/api/v1/notifications", get(list))
        .route("/api/v1/notifications/clear", post(clear))
        .route("/api/v1/notifications/{id}", get(show).post(mark_seen))
        .route("/api/v1/notifications/{id}/dismiss", post(dismiss))
}
