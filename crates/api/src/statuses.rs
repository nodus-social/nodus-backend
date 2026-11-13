//! Mastodon status endpoints.
//!
//! A Nodus status is the source of truth; the wire shape is only an adapter. Handlers
//! here validate ownership and visibility, then hand the write to the store.

use std::collections::HashSet;

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use nodus_server_core::limits::STATUS_MAX_CHARS;
use nodus_server_core::Id;
use nodus_server_store::social::ViewerFlags;
use nodus_server_store::statuses::{NewStatus, StatusRow};

use crate::auth::{Auth, MaybeAuth};
use crate::dto::StatusDto;
use crate::error::{ApiError, ApiResult};
use crate::mastodon::PageQuery;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateStatus {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub visibility: Option<String>,
    #[serde(default)]
    pub sensitive: Option<bool>,
    #[serde(default)]
    pub spoiler_text: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub in_reply_to_id: Option<String>,
    #[serde(default)]
    pub media_ids: Vec<String>,
    #[serde(default)]
    pub content_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ContextDto {
    pub ancestors: Vec<StatusDto>,
    pub descendants: Vec<StatusDto>,
}

pub async fn create(
    State(state): State<AppState>,
    auth: Auth,
    Json(request): Json<CreateStatus>,
) -> ApiResult<Json<StatusDto>> {
    auth.require_scope("write:statuses")?;
    let text = request.status.trim();
    if text.chars().count() > STATUS_MAX_CHARS as usize {
        return Err(ApiError::unprocessable(format!(
            "status must be at most {STATUS_MAX_CHARS} characters"
        )));
    }
    let visibility = request
        .visibility
        .as_deref()
        .unwrap_or("public")
        .to_ascii_lowercase();
    if !matches!(
        visibility.as_str(),
        "public" | "unlisted" | "private" | "direct"
    ) {
        return Err(ApiError::unprocessable("invalid visibility"));
    }
    if text.is_empty() && request.media_ids.is_empty() {
        return Err(ApiError::unprocessable("status must contain text or media"));
    }
    let media_ids = validate_media(&state, &auth, &request.media_ids).await?;
    let mention_ids = resolve_mentions(&state, text).await?;
    let tags = tags(text);
    let in_reply_to = match request.in_reply_to_id.as_deref() {
        Some(id) => {
            let parent = nodus_server_store::statuses::by_id(state.store().pool(), id)
                .await?
                .ok_or_else(|| ApiError::not_found("Record not found"))?;
            Some(parent)
        }
        None => None,
    };
    let id = Id::new().to_string();
    let rendered = render(text);
    let row = nodus_server_store::statuses::create(
        state.store().pool(),
        &NewStatus {
            id: &id,
            account_id: &auth.0.account.id,
            content: text,
            content_html: &rendered,
            content_source: Some(text),
            content_format: "html",
            spoiler_text: request.spoiler_text.as_deref().unwrap_or_default(),
            visibility: &visibility,
            sensitive: request.sensitive.unwrap_or(false),
            in_reply_to_id: in_reply_to.as_ref().map(|row| row.id.as_str()),
            in_reply_to_account_id: in_reply_to.as_ref().map(|row| row.account_id.as_str()),
            reblog_of_id: None,
            language: request
                .language
                .as_deref()
                .filter(|language| !language.is_empty()),
        },
        &media_ids,
        &mention_ids,
        &tags,
    )
    .await?;
    if let Some(parent) = &in_reply_to {
        nodus_server_store::social::notify(
            state.store().pool(),
            &parent.account_id,
            "mention",
            &auth.0.account.id,
            Some(&row.id),
        )
        .await?;
    }
    for mention in &mention_ids {
        nodus_server_store::social::notify(
            state.store().pool(),
            mention,
            "mention",
            &auth.0.account.id,
            Some(&row.id),
        )
        .await?;
    }
    Ok(Json(dto(&state, &row, Some(&auth)).await?))
}

pub async fn show(
    State(state): State<AppState>,
    MaybeAuth(auth): MaybeAuth,
    Path(id): Path<String>,
) -> ApiResult<Json<StatusDto>> {
    let row = visible_status(&state, auth.as_ref(), &id).await?;
    Ok(Json(dto(&state, &row, auth.as_ref()).await?))
}

pub async fn destroy(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    auth.require_scope("write:statuses")?;
    let row = nodus_server_store::statuses::by_id(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    if row.account_id != auth.0.account.id {
        return Err(ApiError::forbidden(
            "You are not allowed to delete this status",
        ));
    }
    let json = Json(dto(&state, &row, Some(&auth)).await?);
    nodus_server_store::statuses::delete_owned(state.store().pool(), &id, &auth.0.account.id)
        .await?;
    Ok(json.into_response())
}

pub async fn favourite(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<StatusDto>> {
    auth.require_scope("write:favourites")?;
    let row = visible_status(&state, Some(&auth), &id).await?;
    nodus_server_store::social::favourite(state.store().pool(), &auth.0.account.id, &id).await?;
    Ok(Json(dto(&state, &row, Some(&auth)).await?))
}

pub async fn unfavourite(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<StatusDto>> {
    auth.require_scope("write:favourites")?;
    let row = visible_status(&state, Some(&auth), &id).await?;
    nodus_server_store::social::unfavourite(state.store().pool(), &auth.0.account.id, &id).await?;
    Ok(Json(dto(&state, &row, Some(&auth)).await?))
}

pub async fn bookmark(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<StatusDto>> {
    auth.require_scope("write:bookmarks")?;
    let row = visible_status(&state, Some(&auth), &id).await?;
    nodus_server_store::social::bookmark(state.store().pool(), &auth.0.account.id, &id).await?;
    Ok(Json(dto(&state, &row, Some(&auth)).await?))
}

pub async fn unbookmark(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<StatusDto>> {
    auth.require_scope("write:bookmarks")?;
    let row = visible_status(&state, Some(&auth), &id).await?;
    nodus_server_store::social::unbookmark(state.store().pool(), &auth.0.account.id, &id).await?;
    Ok(Json(dto(&state, &row, Some(&auth)).await?))
}

pub async fn reblog(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<StatusDto>> {
    auth.require_scope("write:statuses")?;
    let _ = visible_status(&state, Some(&auth), &id).await?;
    let row = nodus_server_store::statuses::reblog(state.store().pool(), &auth.0.account.id, &id)
        .await?
        .ok_or_else(|| ApiError::unprocessable("This status cannot be boosted"))?;
    let original = nodus_server_store::statuses::by_id(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    nodus_server_store::social::notify(
        state.store().pool(),
        &original.account_id,
        "reblog",
        &auth.0.account.id,
        Some(&id),
    )
    .await?;
    Ok(Json(dto(&state, &row, Some(&auth)).await?))
}

pub async fn unreblog(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<StatusDto>> {
    auth.require_scope("write:statuses")?;
    let original = visible_status(&state, Some(&auth), &id).await?;
    sqlx_query_unreblog(&state, &auth, &id).await?;
    Ok(Json(dto(&state, &original, Some(&auth)).await?))
}

pub async fn context(
    State(state): State<AppState>,
    MaybeAuth(auth): MaybeAuth,
    Path(id): Path<String>,
) -> ApiResult<Json<ContextDto>> {
    let _ = visible_status(&state, auth.as_ref(), &id).await?;
    let (ancestors, descendants) =
        nodus_server_store::statuses::context(state.store().pool(), &id).await?;
    let mut context = ContextDto {
        ancestors: Vec::new(),
        descendants: Vec::new(),
    };
    for row in ancestors {
        if can_view(&state, auth.as_ref(), &row).await? {
            context
                .ancestors
                .push(dto(&state, &row, auth.as_ref()).await?);
        }
    }
    for row in descendants {
        if can_view(&state, auth.as_ref(), &row).await? {
            context
                .descendants
                .push(dto(&state, &row, auth.as_ref()).await?);
        }
    }
    Ok(Json(context))
}

pub async fn account_statuses(
    State(state): State<AppState>,
    MaybeAuth(auth): MaybeAuth,
    Path(id): Path<String>,
    Query(query): Query<PageQuery>,
) -> ApiResult<Response> {
    let account = nodus_server_store::accounts::by_id(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    let params = query.params()?;
    let page =
        nodus_server_store::statuses::account_page(state.store().pool(), &id, params).await?;
    let mut items = Vec::with_capacity(page.items.len());
    for row in page.items {
        if can_view(&state, auth.as_ref(), &row).await? {
            items.push(dto(&state, &row, auth.as_ref()).await?);
        }
    }
    let mut response = Json(items).into_response();
    if let Some(next) = page.next_max_id {
        let size = nodus_server_core::PageSize::default_max(params.limit);
        if let Some(link) = params.next_link(
            &format!("/api/v1/accounts/{}/statuses", account.id),
            next.parse().ok(),
            size,
        ) {
            if let Ok(value) = axum::http::HeaderValue::from_str(&link) {
                response
                    .headers_mut()
                    .insert(axum::http::header::LINK, value);
            }
        }
    }
    Ok(response)
}

pub(crate) async fn dto(
    state: &AppState,
    row: &StatusRow,
    viewer: Option<&Auth>,
) -> ApiResult<StatusDto> {
    let account = nodus_server_store::accounts::by_id(state.store().pool(), &row.account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    let media = nodus_server_store::media::by_status(state.store().pool(), &row.id).await?;
    let mut dto = StatusDto::from_row_with_media(row, &account, state.instance(), &media);
    if let Some(original_id) = &row.reblog_of_id {
        if let Some(original) =
            nodus_server_store::statuses::by_id(state.store().pool(), original_id).await?
        {
            let original_account =
                nodus_server_store::accounts::by_id(state.store().pool(), &original.account_id)
                    .await?
                    .ok_or_else(|| ApiError::not_found("Record not found"))?;
            let original_media =
                nodus_server_store::media::by_status(state.store().pool(), &original.id).await?;
            dto.reblog = Some(Box::new(StatusDto::from_row_with_media(
                &original,
                &original_account,
                state.instance(),
                &original_media,
            )));
        }
    }
    if let Some(viewer) = viewer {
        let mut ids = vec![row.id.clone()];
        if let Some(reblog) = &dto.reblog {
            ids.push(reblog.id.clone());
        }
        let flags = nodus_server_store::social::viewer_flags(
            state.store().pool(),
            &viewer.0.account.id,
            &ids,
        )
        .await?;
        if let Some(flag) = flags.get(&row.id) {
            apply_flags(&mut dto, *flag);
        }
        if let (Some(reblog), Some(flag)) = (dto.reblog.as_mut(), flags.get(&ids[ids.len() - 1])) {
            apply_flags(reblog, *flag);
        }
    }
    Ok(dto)
}

fn apply_flags(dto: &mut StatusDto, flags: ViewerFlags) {
    dto.favourited = flags.favourited;
    dto.reblogged = flags.reblogged;
    dto.bookmarked = flags.bookmarked;
}

async fn visible_status(state: &AppState, auth: Option<&Auth>, id: &str) -> ApiResult<StatusRow> {
    let row = nodus_server_store::statuses::by_id(state.store().pool(), id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    if can_view(state, auth, &row).await? {
        Ok(row)
    } else {
        Err(ApiError::not_found("Record not found"))
    }
}

async fn can_view(state: &AppState, auth: Option<&Auth>, row: &StatusRow) -> ApiResult<bool> {
    if row.visibility == "public" || row.visibility == "unlisted" {
        return Ok(true);
    }
    let Some(auth) = auth else {
        return Ok(false);
    };
    if row.account_id == auth.0.account.id {
        return Ok(true);
    }
    if row.visibility == "direct" {
        let mentioned: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM status_mention WHERE status_id = $1 AND account_id = $2)",
        )
        .bind(&row.id)
        .bind(&auth.0.account.id)
        .fetch_one(state.store().pool())
        .await?;
        return Ok(mentioned);
    }
    nodus_server_store::social::relationship(
        state.store().pool(),
        &auth.0.account.id,
        &row.account_id,
    )
    .await
    .map(|relationship| relationship.following)
    .map_err(Into::into)
}

async fn validate_media(state: &AppState, auth: &Auth, ids: &[String]) -> ApiResult<Vec<String>> {
    if ids.len() > nodus_server_core::limits::MEDIA_MAX_ATTACHMENTS {
        return Err(ApiError::unprocessable("too many media attachments"));
    }
    for id in ids {
        let Some(media) = nodus_server_store::media::by_id(state.store().pool(), id).await? else {
            return Err(ApiError::unprocessable("unknown media attachment"));
        };
        if media.account_id != auth.0.account.id || media.status_id.is_some() {
            return Err(ApiError::unprocessable("media attachment is not available"));
        }
    }
    Ok(ids.to_vec())
}

async fn resolve_mentions(state: &AppState, text: &str) -> ApiResult<Vec<String>> {
    let mut seen = HashSet::new();
    let mut ids = Vec::new();
    for word in text.split_whitespace() {
        let Some(handle) = word.strip_prefix('@') else {
            continue;
        };
        let handle =
            handle.trim_end_matches(|c: char| !c.is_alphanumeric() && c != '@' && c != '_');
        let mut parts = handle.split('@');
        let Some(username) = parts.next() else {
            continue;
        };
        let domain = parts.next();
        if let Some(domain) = domain {
            if domain != state.instance().domain {
                continue;
            }
        }
        if let Some(account) =
            nodus_server_store::accounts::local_by_username(state.store().pool(), username).await?
        {
            if seen.insert(account.id.clone()) {
                ids.push(account.id);
            }
        }
    }
    Ok(ids)
}

fn tags(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut tags = Vec::new();
    for word in text.split_whitespace() {
        let Some(tag) = word.strip_prefix('#') else {
            continue;
        };
        let tag = tag.trim_end_matches(|c: char| !c.is_alphanumeric() && c != '_');
        if tag.is_empty() {
            continue;
        }
        let tag = tag.to_lowercase();
        if seen.insert(tag.clone()) {
            tags.push(tag);
        }
    }
    tags
}

fn render(text: &str) -> String {
    let mut paragraphs = Vec::new();
    for paragraph in text.split("\n\n") {
        if paragraph.trim().is_empty() {
            continue;
        }
        let mut html = String::from("<p>");
        for (index, line) in paragraph.split('\n').enumerate() {
            if index > 0 {
                html.push_str("<br />");
            }
            html.push_str(&escape(line));
        }
        html.push_str("</p>");
        paragraphs.push(html);
    }
    paragraphs.join("")
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

async fn sqlx_query_unreblog(state: &AppState, auth: &Auth, id: &str) -> ApiResult<()> {
    sqlx::query(
        "DELETE FROM status WHERE reblog_of_id = $1 AND account_id = $2 AND deleted_at IS NULL",
    )
    .bind(id)
    .bind(&auth.0.account.id)
    .execute(state.store().pool())
    .await?;
    sqlx::query(
        "UPDATE status SET reblogs_count = \
             (SELECT count(*) FROM status WHERE reblog_of_id = $1 AND deleted_at IS NULL) \
         WHERE id = $1",
    )
    .bind(id)
    .execute(state.store().pool())
    .await?;
    Ok(())
}
