//! The Misskey client API.
//!
//! Misskey speaks JSON with a token in the body (`i`) and its own id space. The
//! handlers translate at the edge: storage stays Mastodon-shaped, and Misskey's
//! `aid` mapping lives in `external_id`.

use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hash, Hasher};

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use nodus_server_core::id::Id;
use nodus_server_core::limits::STATUS_MAX_CHARS;
use nodus_server_sdk::misskey::api::{Meta, Note, NoteVisibility, User};
use nodus_server_sdk::misskey::{Aid, Reaction};
use nodus_server_store::accounts::{self, AccountRow, Authenticated};
use nodus_server_store::external_ids;
use nodus_server_store::statuses::{self, StatusRow};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Misskey routes, with `AppState` still to be attached by the caller.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/meta", post(meta))
        .route("/api/i", post(me))
        .route("/api/notes/show", post(show_note))
        .route("/api/notes/create", post(create_note))
        .route("/api/notes/reactions/create", post(create_reaction))
        .route("/api/notes/reactions/delete", post(delete_reaction))
}

#[derive(Debug, Deserialize)]
struct TokenBody {
    #[serde(default)]
    i: Option<String>,
}

async fn authenticate(state: &AppState, token: Option<&str>) -> ApiResult<Authenticated> {
    let token = token.ok_or_else(|| ApiError::unauthorized("Authentication required"))?;
    let digest = format!("{:x}", Sha256::digest(token.as_bytes()));
    accounts::verify_token(state.store().pool(), &digest)
        .await?
        .ok_or_else(|| ApiError::unauthorized("Authentication required"))
}

async fn dialect_id(
    state: &AppState,
    kind: &str,
    local_id: &str,
    created_at: DateTime<Utc>,
) -> ApiResult<String> {
    let pool = state.store().pool();
    if let Some(existing) = external_ids::by_local(pool, kind, local_id).await? {
        return Ok(existing);
    }
    let timestamp_ms = u64::try_from(created_at.timestamp_millis()).unwrap_or_default();
    for attempt in 0..8_u16 {
        let mut hasher = DefaultHasher::new();
        local_id.hash(&mut hasher);
        attempt.hash(&mut hasher);
        let candidate = Aid::from_parts(
            timestamp_ms,
            u16::try_from(hasher.finish() % 1000).unwrap_or_default(),
        )
        .as_str();
        if let Some(id) = external_ids::get_or_create(pool, kind, local_id, &candidate).await? {
            return Ok(id);
        }
    }
    Err(ApiError::new(
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "Could not allocate an external id",
    ))
}

async fn user_for(state: &AppState, account: &AccountRow) -> ApiResult<User> {
    let id = dialect_id(state, "account", &account.id, account.created_at).await?;
    Ok(User {
        id,
        username: account.username.clone(),
        name: Some(account.display_name.clone()).filter(|name| !name.is_empty()),
        host: account.domain.clone(),
        description: Some(account.note.clone()).filter(|note| !note.is_empty()),
        avatar_url: account.avatar_ref.clone(),
        banner_url: account.header_ref.clone(),
        is_bot: account.bot,
        is_cat: false,
        is_admin: false,
        is_moderator: false,
        is_locked: account.locked,
        is_suspended: account.suspended_at.is_some(),
        followers_count: u64::try_from(account.followers_count).unwrap_or_default(),
        following_count: u64::try_from(account.following_count).unwrap_or_default(),
        notes_count: u64::try_from(account.statuses_count).unwrap_or_default(),
        created_at: Some(account.created_at.to_rfc3339()),
        uri: account.uri.clone(),
        moved_to_uri: None,
        also_known_as: Vec::new(),
    })
}

async fn note_for(state: &AppState, row: &StatusRow, account: &AccountRow) -> ApiResult<Note> {
    let id = dialect_id(state, "status", &row.id, row.created_at).await?;
    let user_id = dialect_id(state, "account", &account.id, account.created_at).await?;
    let reactions = statuses::reactions(state.store().pool(), &row.id).await?;
    let reaction_map: BTreeMap<String, u64> = reactions
        .into_iter()
        .map(|entry| {
            (
                entry.reaction,
                u64::try_from(entry.count).unwrap_or_default(),
            )
        })
        .collect();
    let reaction_count = reaction_map.values().sum();
    let renote_id = match &row.reblog_of_id {
        Some(reblog) => match statuses::by_id(state.store().pool(), reblog).await? {
            Some(inner) => Some(dialect_id(state, "status", &inner.id, inner.created_at).await?),
            None => None,
        },
        None => None,
    };
    let reply_id = match &row.in_reply_to_id {
        Some(reply) => match statuses::by_id(state.store().pool(), reply).await? {
            Some(inner) => Some(dialect_id(state, "status", &inner.id, inner.created_at).await?),
            None => None,
        },
        None => None,
    };
    Ok(Note {
        id,
        created_at: row.created_at.to_rfc3339(),
        user_id,
        user: Some(user_for(state, account).await?),
        text: Some(row.content.clone()).filter(|text| !text.is_empty()),
        cw: Some(row.spoiler_text.clone()).filter(|cw| !cw.is_empty()),
        visibility: visibility_out(&row.visibility),
        local_only: row.visibility == "unlisted",
        renote_count: u64::try_from(row.reblogs_count).unwrap_or_default(),
        replies_count: u64::try_from(row.replies_count).unwrap_or_default(),
        reactions: reaction_map,
        reaction_count,
        renote_id,
        renote: None,
        reply_id,
        reply: None,
        uri: row.uri.clone(),
        url: row
            .uri
            .clone()
            .or_else(|| Some(state.instance().url(&format!("/notes/{}", row.id)))),
        file_ids: Vec::new(),
        files: Vec::new(),
        tags: Vec::new(),
        poll: None,
        emojis: BTreeMap::new(),
        channel_id: None,
        is_hidden: row.visibility != "public",
    })
}

fn visibility_out(visibility: &str) -> NoteVisibility {
    match visibility {
        "private" => NoteVisibility::Followers,
        "direct" => NoteVisibility::Specified,
        _ => NoteVisibility::Public,
    }
}

fn visibility_in(visibility: Option<NoteVisibility>) -> &'static str {
    match visibility.unwrap_or_default() {
        NoteVisibility::Public => "public",
        NoteVisibility::Home => "unlisted",
        NoteVisibility::Followers => "private",
        NoteVisibility::Specified => "direct",
    }
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

async fn meta(State(state): State<AppState>) -> Json<Meta> {
    let instance = state.instance();
    Json(Meta {
        name: instance.title.clone(),
        version: instance.version.clone(),
        uri: instance.base_url.clone(),
        description: Some(instance.description.clone()),
        disable_registration: false,
        max_note_text_length: STATUS_MAX_CHARS,
    })
}

async fn me(State(state): State<AppState>, Json(body): Json<TokenBody>) -> ApiResult<Json<User>> {
    let auth = authenticate(&state, body.i.as_deref()).await?;
    Ok(Json(user_for(&state, &auth.account).await?))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NoteBody {
    #[serde(default)]
    i: Option<String>,
    note_id: String,
}

async fn show_note(
    State(state): State<AppState>,
    Json(body): Json<NoteBody>,
) -> ApiResult<Json<Note>> {
    let _auth = authenticate(&state, body.i.as_deref()).await?;
    let local_id = external_ids::resolve(state.store().pool(), "status", &body.note_id)
        .await?
        .ok_or_else(|| ApiError::not_found("No such note"))?;
    let row = statuses::by_id(state.store().pool(), &local_id)
        .await?
        .ok_or_else(|| ApiError::not_found("No such note"))?;
    let account = accounts::by_id(state.store().pool(), &row.account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("No such note"))?;
    Ok(Json(note_for(&state, &row, &account).await?))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateNoteBody {
    #[serde(default)]
    i: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    cw: Option<String>,
    #[serde(default)]
    visibility: Option<NoteVisibility>,
    #[serde(default)]
    sensitive: bool,
    #[serde(default)]
    reply_id: Option<String>,
    #[serde(default)]
    renote_id: Option<String>,
}

async fn create_note(
    State(state): State<AppState>,
    Json(body): Json<CreateNoteBody>,
) -> ApiResult<Json<Note>> {
    let auth = authenticate(&state, body.i.as_deref()).await?;
    if body.renote_id.is_some() {
        return Err(ApiError::unprocessable(
            "Renotes are not implemented on this endpoint yet",
        ));
    }
    let text = body.text.unwrap_or_default();
    if text.trim().is_empty() {
        return Err(ApiError::unprocessable("text is required"));
    }
    if text.chars().count() > usize::try_from(STATUS_MAX_CHARS).unwrap_or(usize::MAX) {
        return Err(ApiError::unprocessable("text is too long"));
    }
    let (reply_internal, reply_account) = match body.reply_id.as_deref() {
        Some(external) => {
            let local = external_ids::resolve(state.store().pool(), "status", external)
                .await?
                .ok_or_else(|| ApiError::not_found("No such reply target"))?;
            let reply = statuses::by_id(state.store().pool(), &local)
                .await?
                .ok_or_else(|| ApiError::not_found("No such reply target"))?;
            (Some(local), Some(reply.account_id))
        }
        None => (None, None),
    };
    let id = Id::new().to_string();
    let html = format!("<p>{}</p>", escape_html(&text).replace('\n', "<br>"));
    let cw = body.cw.unwrap_or_default();
    let row = statuses::insert(
        state.store().pool(),
        &statuses::NewStatus {
            id: &id,
            account_id: &auth.account.id,
            content: &text,
            content_html: &html,
            content_source: Some(&text),
            content_format: "mfm",
            spoiler_text: &cw,
            visibility: visibility_in(body.visibility),
            sensitive: body.sensitive,
            in_reply_to_id: reply_internal.as_deref(),
            in_reply_to_account_id: reply_account.as_deref(),
            language: None,
        },
    )
    .await?;
    let account = accounts::by_id(state.store().pool(), &row.account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("No such note"))?;
    Ok(Json(note_for(&state, &row, &account).await?))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReactionBody {
    #[serde(default)]
    i: Option<String>,
    note_id: String,
    reaction: String,
}

async fn create_reaction(
    State(state): State<AppState>,
    Json(body): Json<ReactionBody>,
) -> ApiResult<Json<Value>> {
    let auth = authenticate(&state, body.i.as_deref()).await?;
    let reaction = Reaction::parse(&body.reaction)
        .map_err(|error| ApiError::unprocessable(error.to_string()))?;
    let local_id = external_ids::resolve(state.store().pool(), "status", &body.note_id)
        .await?
        .ok_or_else(|| ApiError::not_found("No such note"))?;
    statuses::set_reaction(
        state.store().pool(),
        &local_id,
        &auth.account.id,
        reaction.as_str(),
    )
    .await?;
    Ok(Json(json!({})))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteReactionBody {
    #[serde(default)]
    i: Option<String>,
    note_id: String,
}

async fn delete_reaction(
    State(state): State<AppState>,
    Json(body): Json<DeleteReactionBody>,
) -> ApiResult<Json<Value>> {
    let auth = authenticate(&state, body.i.as_deref()).await?;
    let local_id = external_ids::resolve(state.store().pool(), "status", &body.note_id)
        .await?
        .ok_or_else(|| ApiError::not_found("No such note"))?;
    statuses::remove_reaction(state.store().pool(), &local_id, &auth.account.id).await?;
    Ok(Json(json!({})))
}
