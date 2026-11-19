//! Mastodon status endpoints.
//!
//! A Nodus status is the source of truth; the wire shape is only an adapter. Handlers
//! here validate ownership and visibility, then hand the write to the store.

use std::collections::HashSet;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use nodus_server_core::limits::STATUS_MAX_CHARS;
use nodus_server_core::Id;
use nodus_server_store::social::ViewerFlags;
use nodus_server_store::statuses::{NewStatus, StatusRow};

use crate::auth::{Auth, MaybeAuth};
use crate::dto::{account_url, StatusDto};
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
    /// Set to queue the post instead of publishing it.
    #[serde(default)]
    pub scheduled_at: Option<String>,
    /// Mastodon's nested `poll` object: `{"options": [...], "expires_in": 300, ...}`.
    #[serde(default)]
    pub poll: Option<PollForm>,
    /// The same fields as a form body spells them: `poll[options][]=yes`.
    #[serde(default, rename = "poll[options][]")]
    pub(crate) poll_options: Vec<String>,
    #[serde(default, rename = "poll[options]")]
    pub(crate) poll_options_unbracketed: Vec<String>,
    #[serde(default, rename = "poll[expires_in]")]
    pub(crate) poll_expires_in: Option<i64>,
    #[serde(default, rename = "poll[expires_at]")]
    pub(crate) poll_expires_at: Option<String>,
    #[serde(default, rename = "poll[multiple]")]
    pub(crate) poll_multiple: Option<bool>,
    #[serde(default, rename = "poll[hide_totals]")]
    pub(crate) poll_hide_totals: Option<bool>,
}

/// The `poll` a status is composed with.
///
/// Both JSON (`"poll": {...}`) and Mastodon's bracket form (`poll[options][]`) land in
/// this shape, because a client that posts form-encoded is not making a mistake.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PollForm {
    #[serde(default)]
    pub options: Vec<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub multiple: Option<bool>,
    #[serde(default)]
    pub hide_totals: Option<bool>,
}

impl CreateStatus {
    /// The poll parameters, whichever spelling carried them.
    fn poll_form(&self) -> Option<PollForm> {
        if let Some(poll) = &self.poll {
            return Some(poll.clone());
        }
        let bracketed = !self.poll_options.is_empty()
            || !self.poll_options_unbracketed.is_empty()
            || self.poll_expires_in.is_some()
            || self.poll_expires_at.is_some()
            || self.poll_multiple.is_some()
            || self.poll_hide_totals.is_some();
        bracketed.then(|| PollForm {
            options: self
                .poll_options
                .iter()
                .chain(self.poll_options_unbracketed.iter())
                .cloned()
                .collect(),
            expires_in: self.poll_expires_in,
            expires_at: self.poll_expires_at.clone(),
            multiple: self.poll_multiple,
            hide_totals: self.poll_hide_totals,
        })
    }
}

/// A poll that passed the compose rules, ready to write.
struct NewPollRequest {
    options: Vec<String>,
    multiple: bool,
    hide_totals: bool,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
pub struct ContextDto {
    pub ancestors: Vec<StatusDto>,
    pub descendants: Vec<StatusDto>,
}

pub async fn create(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    auth.require_scope("write:statuses")?;
    let request = parse_create_request(&headers, &body)?;
    if let Some(at) = request.scheduled_at.as_deref() {
        let at = chrono::DateTime::parse_from_rfc3339(at.trim())
            .map_err(|_| ApiError::unprocessable("scheduled_at must be an ISO 8601 timestamp"))?
            .with_timezone(&chrono::Utc);
        if at <= chrono::Utc::now() {
            return Err(ApiError::unprocessable(
                "scheduled_at must be in the future",
            ));
        }
        // The draft is checked now as well as when it goes out, so a reader is told about
        // an empty post while they are still looking at it.
        validated(&request)?;
        let queued = crate::schedules::store(&state, &auth.0.account.id, at, &request).await?;
        return Ok(Json(queued).into_response());
    }
    let row = publish(&state, &auth.0.account.id, request).await?;
    Ok(Json(dto(&state, &row, Some(&auth)).await?).into_response())
}

/// Reads a compose request from JSON or Mastodon's bracket form encoding.
///
/// `serde_urlencoded` cannot collect repeated `poll[options][]` keys into a list, so the
/// form is expanded here: bracket keys become the nested `poll` object the JSON body
/// already uses, and repeated keys become arrays.
fn parse_create_request(headers: &HeaderMap, body: &Bytes) -> ApiResult<CreateStatus> {
    let form_encoded = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("application/x-www-form-urlencoded")
        });
    if !form_encoded {
        return serde_json::from_slice(body)
            .map_err(|error| ApiError::unprocessable(format!("invalid request body: {error}")));
    }
    let mut root = serde_json::Map::new();
    let mut media_ids = Vec::new();
    let mut poll = serde_json::Map::new();
    for (key, value) in url::form_urlencoded::parse(body) {
        let key = key.as_ref();
        match key {
            "media_ids[]" | "media_ids" => {
                media_ids.push(serde_json::Value::String(value.into_owned()));
            }
            _ if key.starts_with("poll[") && key.ends_with(']') => {
                let inner = &key["poll[".len()..key.len() - 1];
                let inner = inner.strip_suffix("][").unwrap_or(inner);
                match inner {
                    "options[]" | "options" => {
                        let entry = poll
                            .entry("options")
                            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
                        if let serde_json::Value::Array(options) = entry {
                            options.push(serde_json::Value::String(value.into_owned()));
                        }
                    }
                    "multiple" | "hide_totals" => {
                        poll.insert(inner.to_owned(), serde_json::Value::Bool(truthy(&value)));
                    }
                    "expires_in" => {
                        let seconds = value.parse::<i64>().map_err(|_| {
                            ApiError::unprocessable(
                                "Validation failed: poll expiry must be between 5 minutes and 7 days",
                            )
                        })?;
                        poll.insert(inner.to_owned(), serde_json::json!(seconds));
                    }
                    _ => {
                        poll.insert(
                            inner.to_owned(),
                            serde_json::Value::String(value.into_owned()),
                        );
                    }
                }
            }
            _ => {
                let value = if key == "sensitive" {
                    serde_json::Value::Bool(truthy(&value))
                } else {
                    serde_json::Value::String(value.into_owned())
                };
                root.insert(key.to_owned(), value);
            }
        }
    }
    if !media_ids.is_empty() {
        root.insert("media_ids".to_owned(), serde_json::Value::Array(media_ids));
    }
    if !poll.is_empty() {
        root.insert("poll".to_owned(), serde_json::Value::Object(poll));
    }
    serde_json::from_value(serde_json::Value::Object(root))
        .map_err(|error| ApiError::unprocessable(format!("invalid request body: {error}")))
}

fn truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "on"
    )
}

/// Publishes a post for `account_id`.
///
/// Kept apart from [`create`] because the scheduler publishes posts that no request asked
/// for, and both paths must apply exactly the same rules.
pub(crate) async fn publish(
    state: &AppState,
    account_id: &str,
    request: CreateStatus,
) -> ApiResult<StatusRow> {
    let visibility = validated(&request)?;
    let poll = validated_poll(&request)?;
    let text = request.status.trim();
    let media_ids = validate_media(state, account_id, &request.media_ids).await?;
    let mention_ids = resolve_mentions(state, text).await?;
    let tags = extract_tags(text);
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
    let poll_id = poll.as_ref().map(|_| format!("{id}:poll"));
    let new_poll = match (&poll, &poll_id) {
        (Some(poll), Some(poll_id)) => Some(nodus_server_store::polls::NewPoll {
            id: poll_id,
            status_id: &id,
            options: &poll.options,
            multiple: poll.multiple,
            hide_totals: poll.hide_totals,
            expires_at: poll.expires_at,
        }),
        _ => None,
    };
    let row = nodus_server_store::statuses::create_with_poll(
        state.store().pool(),
        &NewStatus {
            id: &id,
            account_id,
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
        new_poll.as_ref(),
    )
    .await?;
    // The instance's rules act on what its own accounts publish too. This runs after the
    // row exists, so a rule that suspends the author still leaves the audit trail that
    // explains the suspension.
    crate::rulewatch::screen(
        state.store().pool(),
        "local",
        &row.id,
        account_id,
        &row.content,
    )
    .await;
    notify_mentions(
        state.store().pool(),
        account_id,
        &row.id,
        in_reply_to
            .as_ref()
            .map(|parent| parent.account_id.as_str()),
        &mention_ids,
    )
    .await?;
    // The post exists and is visible here; telling the peers is somebody else's job, so a
    // peer that is down cannot fail the post itself.
    crate::outbox::deliver_create(state, account_id, &row).await;
    Ok(row)
}

/// The checks a post must pass whether it goes out now or later, and the visibility the
/// post is stored with.
fn validated(request: &CreateStatus) -> ApiResult<String> {
    let text = request.status.trim();
    if text.chars().count() > STATUS_MAX_CHARS as usize {
        return Err(ApiError::unprocessable(format!(
            "status must be at most {STATUS_MAX_CHARS} characters"
        )));
    }
    if text.is_empty() && request.media_ids.is_empty() && request.poll_form().is_none() {
        return Err(ApiError::unprocessable(
            "status must contain text, media or a poll",
        ));
    }
    // A scheduled post is stored with its visibility, so it has to be normalised before
    // it is written, not when it is published.
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
    Ok(visibility)
}

/// Checks the compose rules Mastodon enforces on a poll, and resolves its expiry.
fn validated_poll(request: &CreateStatus) -> ApiResult<Option<NewPollRequest>> {
    let Some(form) = request.poll_form() else {
        return Ok(None);
    };
    if form.options.is_empty() || form.options.iter().any(|option| option.trim().is_empty()) {
        return Err(ApiError::unprocessable(
            "Validation failed: poll options must not be empty",
        ));
    }
    if form.options.len() < 2 {
        return Err(ApiError::unprocessable(
            "Validation failed: poll needs at least 2 options",
        ));
    }
    if form.options.len() > 4 {
        return Err(ApiError::unprocessable(
            "Validation failed: poll needs at most 4 options",
        ));
    }
    let options: Vec<String> = form
        .options
        .iter()
        .map(|option| option.trim().to_owned())
        .collect();
    if options.iter().any(|option| option.chars().count() > 50) {
        return Err(ApiError::unprocessable(
            "Validation failed: poll option is too long",
        ));
    }
    let now = chrono::Utc::now();
    let min = chrono::Duration::minutes(5);
    let max = chrono::Duration::days(7);
    let expires_at = if let Some(seconds) = form.expires_in {
        let seconds = chrono::Duration::seconds(seconds);
        if seconds < min || seconds > max {
            return Err(ApiError::unprocessable(
                "Validation failed: poll expiry must be between 5 minutes and 7 days",
            ));
        }
        Some(now + seconds)
    } else if let Some(raw) = form.expires_at.as_deref() {
        let at = chrono::DateTime::parse_from_rfc3339(raw.trim())
            .map_err(|_| {
                ApiError::unprocessable(
                    "Validation failed: poll expiry must be between 5 minutes and 7 days",
                )
            })?
            .with_timezone(&chrono::Utc);
        if at < now + min || at > now + max {
            return Err(ApiError::unprocessable(
                "Validation failed: poll expiry must be between 5 minutes and 7 days",
            ));
        }
        Some(at)
    } else {
        None
    };
    Ok(Some(NewPollRequest {
        options,
        multiple: form.multiple.unwrap_or(false),
        hide_totals: form.hide_totals.unwrap_or(false),
        expires_at,
    }))
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
    crate::outbox::deliver_delete(&state, &row.account_id, &row).await;
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
    crate::outbox::deliver_reaction(
        &state,
        &auth.0.account.id,
        &row,
        nodus_server_sdk::activitypub::ActivityKind::Like,
        true,
    )
    .await;
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
    crate::outbox::deliver_reaction(
        &state,
        &auth.0.account.id,
        &row,
        nodus_server_sdk::activitypub::ActivityKind::Like,
        false,
    )
    .await;
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
    let original = visible_status(&state, Some(&auth), &id).await?;
    let (row, created) =
        nodus_server_store::statuses::reblog_status(state.store().pool(), &auth.0.account.id, &id)
            .await?
            .ok_or_else(|| ApiError::unprocessable("This status cannot be boosted"))?;
    if created {
        crate::outbox::deliver_reaction(
            &state,
            &auth.0.account.id,
            &original,
            nodus_server_sdk::activitypub::ActivityKind::Announce,
            true,
        )
        .await;
        nodus_server_store::social::notify(
            state.store().pool(),
            &original.account_id,
            "reblog",
            &auth.0.account.id,
            Some(&id),
        )
        .await?;
    }
    Ok(Json(dto(&state, &row, Some(&auth)).await?))
}

pub async fn unreblog(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<StatusDto>> {
    auth.require_scope("write:statuses")?;
    let _ = visible_status(&state, Some(&auth), &id).await?;
    let original =
        nodus_server_store::statuses::unreblog(state.store().pool(), &auth.0.account.id, &id)
            .await?
            .ok_or_else(|| ApiError::not_found("Record not found"))?;
    crate::outbox::deliver_reaction(
        &state,
        &auth.0.account.id,
        &original,
        nodus_server_sdk::activitypub::ActivityKind::Announce,
        false,
    )
    .await;
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
    let viewer_id = viewer.map(|auth| auth.0.account.id.as_str());
    decorate(state, &mut dto, &row.id, viewer_id).await?;
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
            let mut boost = StatusDto::from_row_with_media(
                &original,
                &original_account,
                state.instance(),
                &original_media,
            );
            decorate(state, &mut boost, &original.id, viewer_id).await?;
            dto.reblog = Some(Box::new(boost));
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

/// Fills in the parts of a status payload that live in their own tables.
///
/// Hashtags and mentions are rows beside the status, not columns on it, so a payload built
/// from the status row alone renders `#nodus` as plain text and `@someone` as neither a
/// link nor a notification — which is what clients were getting before this ran.
async fn decorate(
    state: &AppState,
    dto: &mut StatusDto,
    status_id: &str,
    viewer_id: Option<&str>,
) -> ApiResult<()> {
    let pool = state.store().pool();
    let instance = state.instance();
    dto.poll = crate::polls::status_poll(state, status_id, viewer_id).await?;
    let tags = nodus_server_store::statuses::tags_of(pool, status_id).await?;
    dto.tags = tags
        .iter()
        .map(|tag| {
            serde_json::json!({
                "name": tag,
                "url": instance.url(&format!("/tags/{tag}")),
            })
        })
        .collect();
    let emojis = nodus_server_store::statuses::emojis_of(pool, status_id).await?;
    dto.emojis = emojis
        .into_iter()
        .map(|emoji| {
            serde_json::json!({
                "shortcode": emoji.shortcode,
                "url": emoji.url,
                "static_url": emoji.url,
                "visible_in_picker": true,
            })
        })
        .collect();
    let mentions = nodus_server_store::statuses::mentions_of(pool, status_id).await?;
    for account_id in mentions {
        let Some(account) = nodus_server_store::accounts::by_id(pool, &account_id).await? else {
            continue;
        };
        let acct = match &account.domain {
            Some(domain) => format!("{}@{domain}", account.username),
            None => account.username.clone(),
        };
        dto.mentions.push(serde_json::json!({
            "id": account.id,
            "username": account.username,
            "acct": acct,
            "url": account_url(&account, instance),
        }));
    }
    Ok(())
}

pub(crate) async fn visible_status(
    state: &AppState,
    auth: Option<&Auth>,
    id: &str,
) -> ApiResult<StatusRow> {
    visible_status_for_viewer(state, auth.map(|a| a.0.account.id.as_str()), id).await
}

pub(crate) async fn visible_status_for_viewer(
    state: &AppState,
    viewer_id: Option<&str>,
    id: &str,
) -> ApiResult<StatusRow> {
    let row = nodus_server_store::statuses::by_id(state.store().pool(), id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    if can_view_for_viewer(state, viewer_id, &row).await? {
        Ok(row)
    } else {
        Err(ApiError::not_found("Record not found"))
    }
}

pub(crate) async fn can_view(
    state: &AppState,
    auth: Option<&Auth>,
    row: &StatusRow,
) -> ApiResult<bool> {
    can_view_for_viewer(state, auth.map(|a| a.0.account.id.as_str()), row).await
}

pub(crate) async fn can_view_for_viewer(
    state: &AppState,
    viewer_id: Option<&str>,
    row: &StatusRow,
) -> ApiResult<bool> {
    // A suspended remote account disappears everywhere, its threads included, whether or
    // not a link pointed at it. Silence only keeps it off the public listings, so a status
    // URL it was linked by still resolves for whoever already has the link.
    let action = nodus_server_store::remote_moderation::action_for_account(
        state.store().pool(),
        &row.account_id,
    )
    .await?;
    if action.as_deref() == Some(nodus_server_store::remote_moderation::SUSPEND) {
        return Ok(false);
    }
    if row.visibility == "public" || row.visibility == "unlisted" {
        return Ok(true);
    }
    let Some(viewer_id) = viewer_id else {
        return Ok(false);
    };
    if row.account_id == viewer_id {
        return Ok(true);
    }
    if row.visibility == "direct" {
        return nodus_server_store::statuses::is_mentioned(
            state.store().pool(),
            &row.id,
            viewer_id,
        )
        .await
        .map_err(Into::into);
    }
    if row.visibility != "private" {
        return Ok(false);
    }
    nodus_server_store::social::relationship(state.store().pool(), viewer_id, &row.account_id)
        .await
        .map(|relationship| relationship.following)
        .map_err(Into::into)
}

async fn validate_media(
    state: &AppState,
    account_id: &str,
    ids: &[String],
) -> ApiResult<Vec<String>> {
    if ids.len() > nodus_server_core::limits::MEDIA_MAX_ATTACHMENTS {
        return Err(ApiError::unprocessable("too many media attachments"));
    }
    for id in ids {
        let Some(media) = nodus_server_store::media::by_id(state.store().pool(), id).await? else {
            return Err(ApiError::unprocessable("unknown media attachment"));
        };
        if media.account_id != account_id || media.status_id.is_some() {
            return Err(ApiError::unprocessable("media attachment is not available"));
        }
    }
    Ok(ids.to_vec())
}

pub(crate) async fn resolve_mentions(state: &AppState, text: &str) -> ApiResult<Vec<String>> {
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

pub(crate) fn extract_tags(text: &str) -> Vec<String> {
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

pub(crate) async fn notify_mentions(
    pool: &sqlx::PgPool,
    from_account_id: &str,
    status_id: &str,
    reply_to_account_id: Option<&str>,
    mention_ids: &[String],
) -> ApiResult<()> {
    let mut notified = HashSet::new();
    if let Some(target_id) = reply_to_account_id {
        if notified.insert(target_id) {
            nodus_server_store::social::notify(
                pool,
                target_id,
                "mention",
                from_account_id,
                Some(status_id),
            )
            .await?;
        }
    }
    for mention in mention_ids {
        if notified.insert(mention.as_str()) {
            nodus_server_store::social::notify(
                pool,
                mention,
                "mention",
                from_account_id,
                Some(status_id),
            )
            .await?;
        }
    }
    Ok(())
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
