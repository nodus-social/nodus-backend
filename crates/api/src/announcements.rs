//! Instance announcements: the public strip and staff publishing.

use axum::extract::{Path, State};
use axum::routing::{get, post, put};
use axum::{Form, Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use nodus_server_store::announcements::{self, AnnouncementRow, NewAnnouncement};

use crate::auth::{Auth, MaybeAuth};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/announcements", get(list))
        .route("/api/v1/announcements/{id}/dismiss", post(dismiss))
        .route("/api/v1/admin/announcements", get(list_all).post(create))
        .route(
            "/api/v1/admin/announcements/{id}",
            put(update).delete(remove),
        )
}

#[derive(Debug, Serialize)]
struct AnnouncementDto {
    id: String,
    content: String,
    published: bool,
    all_day: bool,
    published_at: Option<DateTime<Utc>>,
    starts_at: Option<DateTime<Utc>>,
    ends_at: Option<DateTime<Utc>>,
    read: bool,
}

fn dto(row: AnnouncementRow) -> AnnouncementDto {
    AnnouncementDto {
        id: row.id,
        content: row.content,
        published: row.published,
        all_day: row.all_day,
        published_at: row.published.then_some(row.created_at),
        starts_at: row.starts_at,
        ends_at: row.ends_at,
        read: row.read,
    }
}

async fn list(
    State(state): State<AppState>,
    auth: MaybeAuth,
) -> ApiResult<Json<Vec<AnnouncementDto>>> {
    let account = auth.0.as_ref().map(|auth| auth.0.account.id.as_str());
    let rows = announcements::list_for(state.store().pool(), account, 100).await?;
    Ok(Json(rows.into_iter().map(dto).collect()))
}

async fn dismiss(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    announcements::dismiss(state.store().pool(), &auth.0.account.id, &id).await?;
    Ok(Json(serde_json::json!({})))
}

async fn list_all(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<Vec<AnnouncementDto>>> {
    auth.require_scope("admin:read")?;
    let rows = announcements::list_all(state.store().pool(), 100).await?;
    Ok(Json(rows.into_iter().map(dto).collect()))
}

#[derive(Debug, Deserialize)]
struct AnnouncementForm {
    content: String,
    #[serde(default)]
    published: bool,
    #[serde(default)]
    all_day: bool,
    #[serde(default)]
    starts_at: Option<String>,
    #[serde(default)]
    ends_at: Option<String>,
}

fn when(raw: Option<&str>, field: &str) -> ApiResult<Option<DateTime<Utc>>> {
    let Some(raw) = raw.filter(|value| !value.trim().is_empty()) else {
        return Ok(None);
    };
    DateTime::parse_from_rfc3339(raw)
        .map(|value| Some(value.with_timezone(&Utc)))
        .map_err(|_| ApiError::unprocessable(format!("{field} must be an RFC 3339 timestamp")))
}

fn entry(form: &AnnouncementForm) -> ApiResult<NewAnnouncement<'_>> {
    let content = form.content.trim();
    if content.is_empty() {
        return Err(ApiError::unprocessable("content is required"));
    }
    let starts_at = when(form.starts_at.as_deref(), "starts_at")?;
    let ends_at = when(form.ends_at.as_deref(), "ends_at")?;
    if starts_at
        .zip(ends_at)
        .is_some_and(|(start, end)| end <= start)
    {
        return Err(ApiError::unprocessable("ends_at must be after starts_at"));
    }
    Ok(NewAnnouncement {
        content,
        published: form.published,
        all_day: form.all_day,
        starts_at,
        ends_at,
    })
}

async fn create(
    State(state): State<AppState>,
    auth: Auth,
    Form(form): Form<AnnouncementForm>,
) -> ApiResult<Json<AnnouncementDto>> {
    auth.require_scope("admin:write")?;
    let entry = entry(&form)?;
    let row = announcements::create(state.store().pool(), &entry).await?;
    Ok(Json(dto(row)))
}

async fn update(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Form(form): Form<AnnouncementForm>,
) -> ApiResult<Json<AnnouncementDto>> {
    auth.require_scope("admin:write")?;
    let entry = entry(&form)?;
    let row = announcements::update(state.store().pool(), &id, &entry)
        .await?
        .ok_or_else(|| ApiError::not_found("announcement does not exist"))?;
    Ok(Json(dto(row)))
}

async fn remove(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_scope("admin:write")?;
    if !announcements::delete(state.store().pool(), &id).await? {
        return Err(ApiError::not_found("announcement does not exist"));
    }
    Ok(Json(serde_json::json!({})))
}
