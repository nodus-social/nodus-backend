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

use nodus_server_core::limits::{PAGE_MAX_ACCOUNTS, STATUS_MAX_CHARS};
use nodus_server_core::{Id, PageSize};
use nodus_server_store::hydrate::{ProfilePictures, RowMap};
use nodus_server_store::social::ViewerFlags;
use nodus_server_store::statuses::{InteractionAudience, NewStatus, StatusRow};

use crate::auth::{Auth, MaybeAuth};
use crate::dto::{account_url_parts, accounts_with_pictures, AccountDto, StatusDto};
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
    crate::auth::require_confirmed_email(&state, &auth.0.account.id).await?;
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
    // The author and every accepted follower get the id in their home timeline, mirroring
    // the `timeline_entry` rows the store just wrote. Best effort: the row is committed, so
    // a cache that does not answer costs a warning and the SQL read still finds the post.
    crate::home::fan_out(state, &row).await;
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

/// One revision in a status's edit history.
#[derive(Debug, Serialize)]
pub struct HistoryEntryDto {
    pub content: String,
    pub spoiler_text: String,
    pub sensitive: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub account: AccountDto,
}

/// `GET /api/v1/statuses/{id}/history`
///
/// The revisions a viewer may see, newest first. A post the viewer cannot see is a 404,
/// exactly like the post itself: an empty history would confirm that the id exists.
pub async fn history(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<HistoryEntryDto>>> {
    auth.require_scope("read:statuses")?;
    let row = visible_status(&state, Some(&auth), &id).await?;
    let author = state
        .store()
        .account(&row.account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    let pictures = state
        .store()
        .batch()
        .profile_pictures(std::slice::from_ref(&author.id))
        .run()
        .await?;
    let mut accounts =
        accounts_with_pictures(std::slice::from_ref(&author), &pictures, state.instance());
    let account = accounts.pop().expect("one account");
    let edits = nodus_server_store::statuses::edits(state.store().pool(), &row.id).await?;
    Ok(Json(
        edits
            .into_iter()
            .map(|edit| HistoryEntryDto {
                content: edit.content,
                spoiler_text: edit.spoiler_text,
                sensitive: edit.sensitive,
                created_at: edit.created_at,
                account: account.clone(),
            })
            .collect(),
    ))
}

/// Pagination for the accounts behind a status. `max_id` is the last account id the
/// client saw, because these lists are ordered by account id rather than by an
/// interaction id the client never receives.
#[derive(Debug, Deserialize)]
pub struct InteractionQuery {
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub offset: Option<i64>,
    #[serde(default)]
    pub max_id: Option<String>,
}

fn interaction_audience(row: &StatusRow) -> InteractionAudience<'_> {
    match row.visibility.as_str() {
        "private" => InteractionAudience::Followers(&row.account_id),
        "direct" => InteractionAudience::Participants(&row.account_id),
        _ => InteractionAudience::Everyone,
    }
}

/// `GET /api/v1/statuses/{id}/favourited_by`
///
/// The visibility of the status limits the list, not merely the viewer's right to read
/// it: a private post lists only accepted followers of its author, and a direct one only
/// its participants. A viewer who cannot see the post gets the same 404 as the post.
pub async fn favourited_by(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Query(query): Query<InteractionQuery>,
) -> ApiResult<Json<Vec<AccountDto>>> {
    auth.require_scope("read:statuses")?;
    let row = visible_status(&state, Some(&auth), &id).await?;
    let size = PageSize::clamp(query.limit, PAGE_MAX_ACCOUNTS);
    let accounts = nodus_server_store::statuses::favourited_by(
        state.store().pool(),
        &row.id,
        interaction_audience(&row),
        query.max_id.as_deref(),
        query.offset.unwrap_or(0).max(0),
        i64::from(size.get()),
    )
    .await?;
    let ids: Vec<String> = accounts.iter().map(|account| account.id.clone()).collect();
    let pictures = state.store().batch().profile_pictures(&ids).run().await?;
    Ok(Json(accounts_with_pictures(
        &accounts,
        &pictures,
        state.instance(),
    )))
}

/// `GET /api/v1/statuses/{id}/reblogged_by`
///
/// Same audience rule as [`favourited_by`], applied to boosts.
pub async fn reblogged_by(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Query(query): Query<InteractionQuery>,
) -> ApiResult<Json<Vec<AccountDto>>> {
    auth.require_scope("read:statuses")?;
    let row = visible_status(&state, Some(&auth), &id).await?;
    let size = PageSize::clamp(query.limit, PAGE_MAX_ACCOUNTS);
    let accounts = nodus_server_store::statuses::reblogged_by(
        state.store().pool(),
        &row.id,
        interaction_audience(&row),
        query.max_id.as_deref(),
        query.offset.unwrap_or(0).max(0),
        i64::from(size.get()),
    )
    .await?;
    let ids: Vec<String> = accounts.iter().map(|account| account.id.clone()).collect();
    let pictures = state.store().batch().profile_pictures(&ids).run().await?;
    Ok(Json(accounts_with_pictures(
        &accounts,
        &pictures,
        state.instance(),
    )))
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
    // Gone here means gone from every follower's cache: the row outlives the post, so
    // hydration could not tell a deleted id from a live one on its own.
    crate::home::hide(&state, &row.account_id, &id).await;
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
        // The boost is a status of its own, so it fans out like one; `fan_out` scans the
        // original's author to skip a self-boost, which adds nothing to a timeline.
        crate::home::fan_out(&state, &row).await;
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
    let mut visible_ancestors = Vec::with_capacity(ancestors.len());
    for row in ancestors {
        if can_view(&state, auth.as_ref(), &row).await? {
            visible_ancestors.push(row);
        }
    }
    let mut visible_descendants = Vec::with_capacity(descendants.len());
    for row in descendants {
        if can_view(&state, auth.as_ref(), &row).await? {
            visible_descendants.push(row);
        }
    }
    // The audience gate above stays one row at a time; the picture shapes for the whole
    // thread are one read, however many posts the thread holds.
    let pictures = pictures_for_rows(
        &state,
        visible_ancestors.iter().chain(visible_descendants.iter()),
    )
    .await?;
    let mut context = ContextDto {
        ancestors: Vec::with_capacity(visible_ancestors.len()),
        descendants: Vec::with_capacity(visible_descendants.len()),
    };
    for row in &visible_ancestors {
        context
            .ancestors
            .push(dto_with_pictures(&state, row, auth.as_ref(), Some(&pictures)).await?);
    }
    for row in &visible_descendants {
        context
            .descendants
            .push(dto_with_pictures(&state, row, auth.as_ref(), Some(&pictures)).await?);
    }
    Ok(Json(context))
}

pub async fn account_statuses(
    State(state): State<AppState>,
    MaybeAuth(auth): MaybeAuth,
    Path(id): Path<String>,
    Query(query): Query<PageQuery>,
) -> ApiResult<Response> {
    let account = state
        .store()
        .account(&id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    let params = query.params()?;
    let page =
        nodus_server_store::statuses::account_page(state.store().pool(), &id, params).await?;
    // One snapshot for the whole page. Looping `dto` here read the author, media,
    // decorations and viewer flags of every row separately: ~12 statements per status,
    // 245 for a 20-status page, all queueing for a pool connection.
    let viewer = auth.as_ref().map(|auth| auth.0.account.id.as_str());
    let (items, _, _) =
        crate::pages::hydrate_statuses(&state, page.items, viewer, &[], None).await?;
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

/// One status, with the author's picture shapes read for this status alone.
///
/// A caller that paints several statuses should read the pictures once with
/// [`pictures_for_rows`] and use [`dto_with_pictures`], so the extra read does not follow
/// the row count.
pub(crate) async fn dto(
    state: &AppState,
    row: &StatusRow,
    viewer: Option<&Auth>,
) -> ApiResult<StatusDto> {
    dto_with_pictures(state, row, viewer, None).await
}

/// Every picture shape the statuses in `rows` will paint, in one batch.
///
/// The map is keyed by account id and covers the author of every row plus the author of
/// every boost's original, which a row names only as a status id. An account with no
/// picture is absent from the map, never a padded entry: the DTO leaves both metas null.
pub(crate) async fn pictures_for_rows<'a, I>(
    state: &AppState,
    rows: I,
) -> ApiResult<RowMap<ProfilePictures>>
where
    I: IntoIterator<Item = &'a StatusRow>,
{
    let mut account_ids = Vec::new();
    let mut reblog_ids = Vec::new();
    for row in rows {
        account_ids.push(row.account_id.clone());
        if let Some(original_id) = &row.reblog_of_id {
            reblog_ids.push(original_id.clone());
        }
    }
    reblog_ids.sort_unstable();
    reblog_ids.dedup();
    if !reblog_ids.is_empty() {
        let originals =
            nodus_server_store::statuses::by_ids(state.store().pool(), &reblog_ids).await?;
        account_ids.extend(originals.into_iter().map(|row| row.account_id));
    }
    account_ids.sort_unstable();
    account_ids.dedup();
    if account_ids.is_empty() {
        return Ok(RowMap::new());
    }
    let pictures = state
        .store()
        .batch()
        .profile_pictures(&account_ids)
        .run()
        .await?;
    Ok(pictures.profile_pictures)
}

/// The same document as [`dto`], painted from an already-read picture map.
///
/// `None` is the single-status path and reads this author's picture here; `Some` trusts
/// the caller's batch for both the author and any boosted author.
pub(crate) async fn dto_with_pictures(
    state: &AppState,
    row: &StatusRow,
    viewer: Option<&Auth>,
    pictures: Option<&RowMap<ProfilePictures>>,
) -> ApiResult<StatusDto> {
    let account = state
        .store()
        .account(&row.account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    let media = nodus_server_store::media::by_status(state.store().pool(), &row.id).await?;
    let mut dto = StatusDto::from_row_with_media(row, &account, state.instance(), &media);
    if let Some(pictures) = pictures {
        dto.account.apply_pictures(pictures.get(&account.id));
    } else {
        let author_pictures = state
            .store()
            .batch()
            .profile_pictures(std::slice::from_ref(&account.id))
            .run()
            .await?;
        dto.apply_account_pictures(&author_pictures.profile_pictures);
    }
    let viewer_id = viewer.map(|auth| auth.0.account.id.as_str());
    decorate(state, &mut dto, &row.id, viewer_id).await?;
    if let Some(original_id) = &row.reblog_of_id {
        if let Some(original) =
            nodus_server_store::statuses::by_id(state.store().pool(), original_id).await?
        {
            let original_account = state
                .store()
                .account(&original.account_id)
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
            if let Some(pictures) = pictures {
                boost
                    .account
                    .apply_pictures(pictures.get(&original_account.id));
            } else {
                let original_pictures = state
                    .store()
                    .batch()
                    .profile_pictures(std::slice::from_ref(&original_account.id))
                    .run()
                    .await?;
                boost.apply_account_pictures(&original_pictures.profile_pictures);
            }
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

pub(crate) fn apply_flags(dto: &mut StatusDto, flags: ViewerFlags) {
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
    dto.poll = crate::polls::status_poll(state, status_id, viewer_id).await?;
    let tags = nodus_server_store::statuses::tags_of(pool, status_id).await?;
    let emojis = nodus_server_store::statuses::emojis_of(pool, status_id).await?;
    let mut mentions = Vec::new();
    for account_id in nodus_server_store::statuses::mentions_of(pool, status_id).await? {
        let Some(account) = state.store().account(&account_id).await? else {
            continue;
        };
        mentions.push(nodus_server_store::MentionRow {
            id: account.id,
            username: account.username,
            domain: account.domain,
        });
    }
    apply_decorations(
        dto,
        &nodus_server_store::StatusDecorations {
            tags,
            emojis,
            mentions,
        },
        state.instance(),
    );
    Ok(())
}

/// Writes a status's parked tags, custom emoji and mentions into its payload.
///
/// One implementation for both paths: the single-status read fills a
/// [`nodus_server_store::StatusDecorations`] from the per-id store functions, a page takes
/// its own from `Batch::decorations`, and neither can drift from the other's wire shape.
pub(crate) fn apply_decorations(
    dto: &mut StatusDto,
    decorations: &nodus_server_store::StatusDecorations,
    instance: &crate::state::InstanceConfig,
) {
    dto.tags = decorations
        .tags
        .iter()
        .map(|tag| {
            serde_json::json!({
                "name": tag,
                "url": instance.url(&format!("/tags/{tag}")),
            })
        })
        .collect();
    dto.emojis = decorations
        .emojis
        .iter()
        .map(|emoji| {
            serde_json::json!({
                "shortcode": emoji.shortcode,
                "url": emoji.url,
                "static_url": emoji.url,
                "visible_in_picker": true,
            })
        })
        .collect();
    dto.mentions = decorations
        .mentions
        .iter()
        .map(|mention| {
            let acct = match &mention.domain {
                Some(domain) => format!("{}@{domain}", mention.username),
                None => mention.username.clone(),
            };
            serde_json::json!({
                "id": mention.id,
                "username": mention.username,
                "acct": acct,
                "url": account_url_parts(&mention.username, mention.domain.as_deref(), instance),
            })
        })
        .collect();
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
    // A deleted account's posts stop being served at once, before the grace period has
    // erased anything. The row may still be there as a tombstone; its writing is not.
    if nodus_server_store::accounts::is_deleted(state.store().pool(), &row.account_id).await? {
        return Ok(false);
    }
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
