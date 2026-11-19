//! The server side of ActivityPub: actors, notes, collections, WebFinger and inbox.
//!
//! Handlers build the same `nodus-activitypub-sdk` documents a reader parses, so a
//! server response and a remote parse cannot drift into two shapes. Storage and
//! policy stay in `nodus-server-store`; this module only maps rows to protocol
//! documents and protocol requests to store calls.

use std::net::{Ipv4Addr, Ipv6Addr};

use axum::body::Bytes;
use axum::extract::{OriginalUri, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::SecondsFormat;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::rand_core::OsRng;
use rsa::RsaPrivateKey;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use nodus_server_core::PageParams;
use nodus_server_federation::{prepare, verify_prepared};
use nodus_server_sdk::activitypub::{
    Activity, ActivityKind, ActivityObject, Actor, Attachment, Collection, CollectionPage, Note,
    Webfinger, WebfingerLink,
};
use nodus_server_store::accounts::{self, AccountRow};
use nodus_server_store::media;
use nodus_server_store::polls;
use nodus_server_store::statuses::{self, StatusRow};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// A protocol document with its media type.
trait Document {
    const CONTENT_TYPE: &'static str;

    fn document(&self) -> Value;
}

impl Document for Actor {
    const CONTENT_TYPE: &'static str = "application/activity+json";

    fn document(&self) -> Value {
        self.to_json()
    }
}

impl Document for Note {
    const CONTENT_TYPE: &'static str = "application/activity+json";

    fn document(&self) -> Value {
        self.to_json()
    }
}

impl Document for Value {
    const CONTENT_TYPE: &'static str = "application/activity+json";

    fn document(&self) -> Value {
        self.clone()
    }
}

impl Document for Collection {
    const CONTENT_TYPE: &'static str = "application/activity+json";

    fn document(&self) -> Value {
        self.to_json()
    }
}

impl Document for Webfinger {
    const CONTENT_TYPE: &'static str = "application/jrd+json";

    fn document(&self) -> Value {
        self.to_json()
    }
}

struct OutboxPage {
    value: Value,
}

impl Document for OutboxPage {
    const CONTENT_TYPE: &'static str = "application/activity+json";

    fn document(&self) -> Value {
        self.value.clone()
    }
}

struct InstanceActor(Value);

impl Document for InstanceActor {
    const CONTENT_TYPE: &'static str = "application/activity+json";

    fn document(&self) -> Value {
        self.0.clone()
    }
}

/// Builds the routes an ActivityPub peer calls. They live at the domain root, not under
/// `/api`, because a peer discovers them from WebFinger and the actor document.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/.well-known/webfinger", get(webfinger))
        .route("/inbox", post(shared_inbox))
        .route("/actor", get(instance_actor))
        .route("/users/{username}", get(actor))
        .route("/users/{username}/outbox", get(outbox))
        .route("/users/{username}/followers", get(followers))
        .route("/users/{username}/following", get(following))
        .route("/users/{username}/inbox", post(inbox))
        .route("/statuses/{id}", get(note))
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct WebfingerQuery {
    resource: String,
}

async fn webfinger(
    State(state): State<AppState>,
    Query(query): Query<WebfingerQuery>,
) -> ApiResult<Response> {
    let username = local_username(&query.resource, &state.instance().domain)
        .ok_or_else(|| ApiError::not_found("No such account"))?;
    // The key we sign outbound fetches with belongs to the instance actor, and peers
    // derive its handle from the actor document (`instance.actor@host`, the legacy
    // Mastodon name, or `host@host`, which Mastodon publishes now). None of those is a
    // row in `accounts`, so without this branch every enforcing peer sees a 404 the
    // moment it tries to resolve the signer.
    if is_instance_actor(&username, &state.instance().domain) {
        return Ok(document_response(&instance_webfinger(&state)));
    }
    let account = accounts::local_by_username(state.store().pool(), &username)
        .await?
        .ok_or_else(|| ApiError::not_found("No such account"))?;
    let account = ensure_identity(&state, account).await?;
    let actor = actor_url(&state, &account);
    let document = Webfinger::for_actor(
        &account.username,
        &state.instance().domain,
        &actor,
        &state.instance().url(&format!("/@{}", account.username)),
    );
    Ok(document_response(&document))
}

async fn actor(State(state): State<AppState>, Path(username): Path<String>) -> ApiResult<Response> {
    let account = accounts::local_by_username(state.store().pool(), &username)
        .await?
        .ok_or_else(|| ApiError::not_found("No such account"))?;
    let account = ensure_identity(&state, account).await?;
    Ok(document_response(&actor_document(&state, &account)))
}

/// The actor this instance signs as. It answers even before a key exists, because a peer
/// that cached this URL must not get a 404 the day the operator adds one.
async fn instance_actor(State(state): State<AppState>) -> Response {
    let id = state.instance().url("/actor");
    let inbox = state.instance().url("/inbox");
    let mut document = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": &id,
        "type": "Application",
        "preferredUsername": INSTANCE_ACTOR_USERNAME,
        "name": state.instance().title,
        "url": &id,
        "inbox": &inbox,
        "endpoints": { "sharedInbox": &inbox },
    });
    if let Some(key) = state.federation() {
        document["publicKey"] = json!({
            "id": key.key_id(),
            "owner": &id,
            "publicKeyPem": key.public_pem(),
        });
    }
    document_response(&InstanceActor(document))
}

#[derive(Debug, Deserialize)]
struct OutboxQuery {
    page: Option<bool>,
    max_id: Option<String>,
}

async fn outbox(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Query(query): Query<OutboxQuery>,
) -> ApiResult<Response> {
    let account = accounts::local_by_username(state.store().pool(), &username)
        .await?
        .ok_or_else(|| ApiError::not_found("No such account"))?;
    let account = ensure_identity(&state, account).await?;
    let actor = actor_url(&state, &account);
    let collection_url = format!("{actor}/outbox");
    if !query.page.unwrap_or(false) {
        return Ok(document_response(&Collection {
            id: collection_url.clone(),
            total_items: u64::try_from(account.statuses_count).unwrap_or_default(),
            first: Some(format!("{collection_url}?page=true")),
        }));
    }

    let max_id = query
        .max_id
        .as_deref()
        .map(|raw| {
            raw.parse::<nodus_server_core::Id>()
                .map_err(|_| ApiError::unprocessable("max_id must be a valid id"))
        })
        .transpose()?;
    let page = statuses::account_page(
        state.store().pool(),
        &account.id,
        PageParams::new().with_max_id(max_id).with_limit(Some(20)),
    )
    .await?;
    let mut items = Vec::with_capacity(page.items.len());
    for row in &page.items {
        items.push(status_activity(&state, row, &account).await?.to_json());
    }
    let next = page
        .next_max_id
        .map(|id| format!("{collection_url}?page=true&max_id={id}"));
    let page_id = match max_id {
        Some(id) => format!("{collection_url}?page=true&max_id={id}"),
        None => format!("{collection_url}?page=true"),
    };
    Ok(document_response(&OutboxPage {
        value: CollectionPage {
            items,
            next,
            total_items: u64::try_from(account.statuses_count).unwrap_or_default(),
        }
        .to_json(&page_id, &collection_url),
    }))
}

async fn followers(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> ApiResult<Response> {
    collection_for(&state, &username, "followers", |account| {
        u64::try_from(account.followers_count).unwrap_or_default()
    })
    .await
}

async fn following(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> ApiResult<Response> {
    collection_for(&state, &username, "following", |account| {
        u64::try_from(account.following_count).unwrap_or_default()
    })
    .await
}

async fn collection_for(
    state: &AppState,
    username: &str,
    name: &str,
    count: impl FnOnce(&AccountRow) -> u64,
) -> ApiResult<Response> {
    let account = accounts::local_by_username(state.store().pool(), username)
        .await?
        .ok_or_else(|| ApiError::not_found("No such account"))?;
    let account = ensure_identity(state, account).await?;
    let collection_url = format!("{}/{name}", actor_url(state, &account));
    Ok(document_response(&Collection {
        id: collection_url.clone(),
        total_items: count(&account),
        first: Some(format!("{collection_url}?page=true")),
    }))
}

async fn note(State(state): State<AppState>, Path(id): Path<String>) -> ApiResult<Response> {
    let row = statuses::by_id(state.store().pool(), &id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    if !matches!(row.visibility.as_str(), "public" | "unlisted") {
        return Err(ApiError::not_found("Record not found"));
    }
    let account = accounts::by_id(state.store().pool(), &row.account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Record not found"))?;
    let (value, _) = status_object(&state, &row, &account).await?;
    Ok(document_response(&value))
}

async fn inbox(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> ApiResult<StatusCode> {
    accept_activity(&state, Some(&username), &headers, &uri, &body).await
}

async fn shared_inbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> ApiResult<StatusCode> {
    accept_activity(&state, None, &headers, &uri, &body).await
}

async fn accept_activity(
    state: &AppState,
    username: Option<&str>,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
    body: &[u8],
) -> ApiResult<StatusCode> {
    if let Some(username) = username {
        let _ = accounts::local_by_username(state.store().pool(), username)
            .await?
            .ok_or_else(|| ApiError::not_found("No such account"))?;
    }
    let activity = verify_signature(state, headers, uri, body).await?;
    ingest_activity(state, &activity).await?;
    tracing::info!(
        kind = %activity.kind.as_str(),
        actor = %activity.actor,
        "accepted inbound activity"
    );
    Ok(StatusCode::ACCEPTED)
}

async fn verify_signature(
    state: &AppState,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
    body: &[u8],
) -> ApiResult<Activity> {
    let mut header_pairs = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        let value = value
            .to_str()
            .map_err(|_| ApiError::unauthorized("invalid header encoding"))?;
        header_pairs.push((name.as_str().to_owned(), value.to_owned()));
    }
    let prepared = prepare("POST", uri.path(), &header_pairs, body, chrono::Utc::now())
        .map_err(|error| ApiError::unauthorized(error.to_string()))?;

    let value: Value = serde_json::from_slice(body)
        .map_err(|_| ApiError::unprocessable("The activity is not JSON"))?;
    let activity = Activity::from_json(&value).or_else(|error| {
        flag_activity(&value).ok_or_else(|| ApiError::unprocessable(error.to_string()))
    })?;

    let key_actor = prepared
        .params
        .key_id
        .split('#')
        .next()
        .unwrap_or(&prepared.params.key_id);
    if key_actor.is_empty() || key_actor != activity.actor {
        return Err(ApiError::unauthorized(
            "signing key does not match activity actor",
        ));
    }

    let parsed_actor = validate_remote_url(key_actor)
        .map_err(|_| ApiError::unauthorized("signing key actor URL is invalid"))?;
    let domain = parsed_actor
        .host_str()
        .ok_or_else(|| ApiError::unauthorized("signing key actor URL has no host"))?;
    ensure_domain_allowed(state, domain).await?;

    if let Some(pem) = accounts::by_uri(state.store().pool(), key_actor)
        .await?
        .and_then(|account| account.public_key_pem)
    {
        if verify_prepared(&prepared, &pem).is_ok() {
            return Ok(activity);
        }
    }
    let actor = state
        .fediverse_client()
        .actor_url(key_actor)
        .await
        .map_err(|error| ApiError::unauthorized(error.to_string()))?;
    if actor.id != key_actor {
        return Err(ApiError::unauthorized(
            "fetched actor id does not match signing key",
        ));
    }
    if let Some(public_key_id) = actor.public_key_id.as_deref() {
        if public_key_id != prepared.params.key_id {
            return Err(ApiError::unauthorized(
                "signing key id does not match actor public key",
            ));
        }
    }
    let pem = actor
        .public_key_pem
        .clone()
        .ok_or_else(|| ApiError::unauthorized("Actor has no public key"))?;
    verify_prepared(&prepared, &pem).map_err(|error| ApiError::unauthorized(error.to_string()))?;
    let _ = upsert_remote_actor(state, key_actor, domain, &actor).await?;
    Ok(activity)
}

async fn ingest_activity(state: &AppState, activity: &Activity) -> ApiResult<()> {
    // A suspended actor is not talked to and does not get to talk: its activities are
    // acknowledged (so the sender stops retrying) and dropped before they touch anything.
    let action =
        nodus_server_store::remote_moderation::active_action(state.store().pool(), &activity.actor)
            .await?;
    if action.as_deref() == Some(nodus_server_store::remote_moderation::SUSPEND) {
        tracing::info!(
            actor = %activity.actor,
            kind = %activity.kind.as_str(),
            "dropped inbound activity from a suspended remote account"
        );
        return Ok(());
    }
    let remote = ensure_remote_actor(state, &activity.actor).await?;
    match activity.kind {
        ActivityKind::Follow => {
            if let Some(target) = activity_target_id(activity) {
                follow_local(state, &remote, target, activity.id.as_deref()).await?;
            }
        }
        ActivityKind::Undo => {
            if let ActivityObject::Activity(inner) = &activity.object {
                if inner.actor != activity.actor {
                    return Err(ApiError::forbidden(
                        "undo actor does not match inner activity actor",
                    ));
                }
                if inner.kind == ActivityKind::Follow {
                    if let Some(target) = activity_target_id(inner) {
                        unfollow_local(state, &remote, target).await?;
                    }
                }
            } else if let Some(target) = activity_target_id(activity) {
                unfollow_local(state, &remote, target).await?;
            }
        }
        ActivityKind::Like => {
            if let Some(target) = activity_target_id(activity) {
                like_local(state, &remote, target).await?;
            }
        }
        ActivityKind::Announce => {
            if let Some(target) = activity_target_id(activity) {
                boost_local(state, &remote, target).await?;
            }
        }
        ActivityKind::Create => {
            if let ActivityObject::Value(value) = &activity.object {
                ingest_note(state, &remote, value).await?;
            }
        }
        ActivityKind::Delete => delete_remote_object(state, &remote, activity).await?,
        ActivityKind::Update => update_remote_object(state, &remote, activity).await?,
        ActivityKind::Block => {
            nodus_server_store::blocks::record_remote_block(state.store().pool(), &activity.actor)
                .await?;
        }
        ActivityKind::Flag => report_remote_flag(state, &remote, activity).await?,
        ActivityKind::Move => move_remote_actor(state, &remote, activity).await?,
        _ => {}
    }
    Ok(())
}

/// A `Flag` whose object is a list.
///
/// Mastodon reports name the reported account and its posts together, and the SDK's object
/// parser only accepts one id or one embedded document. The signature covers the body, so
/// the same verification applies once the document is shaped into an activity here.
fn flag_activity(value: &Value) -> Option<Activity> {
    if value.get("type").and_then(Value::as_str) != Some("Flag")
        || !value.get("object").is_some_and(Value::is_array)
    {
        return None;
    }
    let mut extra = Map::new();
    for key in ["content", "summary"] {
        if let Some(field) = value.get(key) {
            extra.insert(key.to_owned(), field.clone());
        }
    }
    Some(Activity {
        id: value.get("id").and_then(Value::as_str).map(str::to_owned),
        kind: ActivityKind::Flag,
        actor: value.get("actor")?.as_str()?.to_owned(),
        object: ActivityObject::Value(value.get("object")?.clone()),
        to: Vec::new(),
        cc: Vec::new(),
        extra,
    })
}

fn activity_target_id(activity: &Activity) -> Option<&str> {
    match &activity.object {
        ActivityObject::Id(id) => Some(id),
        _ => None,
    }
}

fn delete_target_id(activity: &Activity) -> Option<&str> {
    match &activity.object {
        ActivityObject::Id(id) => Some(id),
        ActivityObject::Value(value) => value.get("id").and_then(Value::as_str),
        ActivityObject::Activity(_) => None,
    }
}

/// The actor URIs a document redirects to, as `alsoKnownAs`.
fn also_known_as(actor: &Actor) -> Vec<String> {
    let Some(value) = actor.extra.get("alsoKnownAs") else {
        return Vec::new();
    };
    let items: Vec<&str> = match value {
        Value::String(uri) => vec![uri.as_str()],
        Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    items
        .into_iter()
        .filter(|uri| validate_remote_url(uri).is_ok())
        .map(str::to_owned)
        .collect()
}

fn names_actor(aliases: &[String], actor: &str) -> bool {
    aliases.iter().any(|alias| alias == actor)
}

fn document_type(value: &Value) -> Option<&str> {
    match value.get("type")? {
        Value::String(kind) => Some(kind.as_str()),
        Value::Array(kinds) => kinds.iter().find_map(Value::as_str),
        _ => None,
    }
}

async fn delete_remote_object(
    state: &AppState,
    remote: &AccountRow,
    activity: &Activity,
) -> ApiResult<()> {
    let Some(id) = delete_target_id(activity) else {
        return Ok(());
    };
    if validate_remote_url(id).is_err() || !same_origin(id, &activity.actor) {
        return Err(ApiError::forbidden(
            "cannot delete object from another origin",
        ));
    }
    if id == activity.actor {
        if let Some(account) = accounts::by_uri(state.store().pool(), id).await? {
            statuses::delete_remote_actor(state.store().pool(), &account.id).await?;
        }
        return Ok(());
    }
    statuses::delete_remote(state.store().pool(), id, &remote.id).await?;
    Ok(())
}

async fn update_remote_object(
    state: &AppState,
    remote: &AccountRow,
    activity: &Activity,
) -> ApiResult<()> {
    let ActivityObject::Value(value) = &activity.object else {
        return Ok(());
    };
    let Some(id) = value.get("id").and_then(Value::as_str) else {
        return Ok(());
    };
    if validate_remote_url(id).is_err() || !same_origin(id, &activity.actor) {
        return Err(ApiError::forbidden(
            "cannot update object from another origin",
        ));
    }
    match document_type(value) {
        Some("Note" | "Question") => {
            let note = Note::from_json(value)
                .map_err(|error| ApiError::unprocessable(error.to_string()))?;
            update_remote_note(state, remote, activity, value, &note).await
        }
        Some("Person" | "Service" | "Application" | "Organization" | "Group") => {
            let actor = Actor::from_json(value)
                .map_err(|error| ApiError::unprocessable(error.to_string()))?;
            if actor.id != activity.actor {
                return Err(ApiError::forbidden("cannot update another actor's profile"));
            }
            update_remote_actor_document(state, value, &actor).await
        }
        _ => Ok(()),
    }
}

async fn update_remote_note(
    state: &AppState,
    remote: &AccountRow,
    activity: &Activity,
    value: &Value,
    note: &Note,
) -> ApiResult<()> {
    let actor_uri = remote.uri.as_deref().unwrap_or(&activity.actor);
    ensure_note_from_actor(state, remote, note, actor_uri).await?;
    let content_html = crate::html::sanitize_html(&note.content);
    let content = html_to_text(&content_html);
    let spoiler_text = crate::html::escape_text(&note.summary);
    let Some(row) = statuses::update_remote_content(
        state.store().pool(),
        &note.id,
        &remote.id,
        &content,
        &content_html,
        &spoiler_text,
        note.sensitive,
    )
    .await?
    else {
        return Ok(());
    };
    store_note_extras(state, remote, note, value, &row).await?;
    store_note_poll(state, value, &row).await
}

/// Applies a freshly fetched actor document to the stored row and says which fields moved.
///
/// Split out from the HTTP handler so the comparison is testable without a peer: the
/// federation client refuses loopback, so an integration test cannot stand one up. The
/// handler is still the only caller in production.
pub async fn apply_actor_refresh(
    state: &AppState,
    existing: &AccountRow,
    actor: &Actor,
) -> ApiResult<(Vec<String>, AccountRow)> {
    let pool = state.store().pool();
    let display_name = crate::html::escape_text(&actor.name);
    let note = crate::html::sanitize_html(&actor.summary);
    let avatar_url = actor
        .avatar
        .as_deref()
        .filter(|url| validate_remote_url(url).is_ok());
    let header_url = actor
        .header
        .as_deref()
        .filter(|url| validate_remote_url(url).is_ok());
    let mut changed = Vec::new();
    if existing.display_name != display_name {
        changed.push("display_name".to_owned());
    }
    if existing.note != note {
        changed.push("note".to_owned());
    }
    if let Some(url) = avatar_url {
        if existing.avatar_url.as_deref() != Some(url) {
            changed.push("avatar_url".to_owned());
        }
    }
    if let Some(url) = header_url {
        if existing.header_url.as_deref() != Some(url) {
            changed.push("header_url".to_owned());
        }
    }
    let updated = accounts::update_remote_profile(
        pool,
        &actor.id,
        &accounts::RemoteProfile {
            display_name: Some(&display_name),
            note: Some(&note),
            avatar_url,
            header_url,
        },
    )
    .await?
    .unwrap_or_else(|| existing.clone());

    // `movedTo` is not a typed field on `Actor`; it survives in `extra`. A document that
    // omits it says the actor is no longer moved, so it clears; an unusable value is
    // ignored rather than allowed to erase a redirect the peer already confirmed.
    let raw_moved_to = actor.extra.get("movedTo").and_then(Value::as_str);
    let moved_to = raw_moved_to.filter(|url| validate_remote_url(url).is_ok());
    let updated = if raw_moved_to.is_some() && moved_to.is_none() {
        updated
    } else if updated.moved_to.as_deref() != moved_to {
        changed.push("moved_to".to_owned());
        accounts::set_moved_to(pool, &updated.id, moved_to)
            .await?
            .unwrap_or(updated)
    } else {
        updated
    };
    accounts::set_also_known_as(pool, &actor.id, &also_known_as(actor)).await?;
    Ok((changed, updated))
}

async fn update_remote_actor_document(
    state: &AppState,
    value: &Value,
    actor: &Actor,
) -> ApiResult<()> {
    let display_name = value
        .get("name")
        .and_then(Value::as_str)
        .map(crate::html::escape_text);
    let note = value
        .get("summary")
        .and_then(Value::as_str)
        .map(crate::html::sanitize_html);
    let updated = accounts::update_remote_profile(
        state.store().pool(),
        &actor.id,
        &accounts::RemoteProfile {
            display_name: display_name.as_deref(),
            note: note.as_deref(),
            avatar_url: actor
                .avatar
                .as_deref()
                .filter(|url| validate_remote_url(url).is_ok()),
            header_url: actor
                .header
                .as_deref()
                .filter(|url| validate_remote_url(url).is_ok()),
        },
    )
    .await?;
    if updated.is_none() {
        tracing::debug!(actor = %actor.id, "ignored an update for an unknown actor");
        return Ok(());
    }
    accounts::set_also_known_as(state.store().pool(), &actor.id, &also_known_as(actor)).await?;
    Ok(())
}

/// A `Move` is a redirect the target has to confirm.
///
/// Without `alsoKnownAs` naming the mover on the target, any actor could point another
/// actor's followers at itself. The target's own document is the only place that consent
/// is expressed, so a move that fails the check is dropped rather than guessed at.
async fn move_remote_actor(
    state: &AppState,
    remote: &AccountRow,
    activity: &Activity,
) -> ApiResult<()> {
    let Some(target) = activity
        .extra
        .get("target")
        .and_then(Value::as_str)
        .filter(|target| !target.is_empty())
    else {
        return Ok(());
    };
    if target == activity.actor || validate_remote_url(target).is_err() {
        tracing::info!(actor = %activity.actor, target = %target, "ignored a move to an unusable target");
        return Ok(());
    }
    let pool = state.store().pool();
    let confirmed = match accounts::by_uri(pool, target).await? {
        // A target that has already published aliases has answered the question; asking
        // again would let a transient outage silently drop a consented redirect.
        Some(row) if !row.also_known_as.is_empty() => {
            names_actor(&row.also_known_as, &activity.actor)
        }
        _ => {
            let parsed = validate_remote_url(target)?;
            let domain = parsed
                .host_str()
                .ok_or_else(|| ApiError::unprocessable("move target has no host"))?;
            ensure_domain_allowed(state, domain).await?;
            match fetch_remote_actor(state, target, domain).await {
                Ok(row) => names_actor(&row.also_known_as, &activity.actor),
                Err(error) => {
                    tracing::info!(actor = %activity.actor, target = %target, error = %error.message(), "could not verify a move");
                    return Ok(());
                }
            }
        }
    };
    if !confirmed {
        tracing::info!(actor = %activity.actor, target = %target, "ignored a move the target does not confirm");
        return Ok(());
    }
    accounts::set_moved_to(pool, &remote.id, Some(target)).await?;
    Ok(())
}

/// The objects a `Flag` names.
fn flag_targets(activity: &Activity) -> Vec<String> {
    match &activity.object {
        ActivityObject::Id(id) => vec![id.clone()],
        ActivityObject::Value(Value::Array(items)) => items
            .iter()
            .filter_map(|item| match item {
                Value::String(id) => Some(id.clone()),
                other => other.get("id").and_then(Value::as_str).map(str::to_owned),
            })
            .collect(),
        ActivityObject::Value(value) => value
            .get("id")
            .and_then(Value::as_str)
            .map(|id| vec![id.to_owned()])
            .unwrap_or_default(),
        ActivityObject::Activity(_) => Vec::new(),
    }
}

async fn report_remote_flag(
    state: &AppState,
    remote: &AccountRow,
    activity: &Activity,
) -> ApiResult<()> {
    let pool = state.store().pool();
    if let Some(id) = activity.id.as_deref() {
        if nodus_server_store::moderation::report_for_activity(pool, id)
            .await?
            .is_some()
        {
            return Ok(());
        }
    }
    let mut status_ids = Vec::new();
    let mut target_account_id = None;
    for target in flag_targets(activity) {
        if let Some(account) = accounts::by_uri(pool, &target).await? {
            target_account_id.get_or_insert(account.id);
            continue;
        }
        if let Some(status) = statuses::by_uri(pool, &target).await? {
            // Only a local post is ours to act on; a cached remote one still names its author.
            if status.local {
                status_ids.push(status.id);
            }
            target_account_id.get_or_insert(status.account_id);
        }
    }
    let Some(target_account_id) = target_account_id else {
        tracing::warn!(actor = %activity.actor, "ignored a flag naming no known account");
        return Ok(());
    };
    status_ids.sort();
    status_ids.dedup();
    let comment = activity
        .extra
        .get("content")
        .and_then(Value::as_str)
        .map(crate::html::sanitize_html)
        .map(|html| html_to_plain(&html))
        .unwrap_or_default();
    nodus_server_store::moderation::create_report(
        pool,
        &nodus_server_store::moderation::NewReport {
            account_id: Some(&remote.id),
            target_account_id: &target_account_id,
            status_ids: &status_ids,
            category: "federation",
            comment: &comment,
            rule_ids: &[],
            activity_uri: activity.id.as_deref(),
        },
    )
    .await?;
    Ok(())
}

pub(crate) async fn ensure_domain_allowed(state: &AppState, domain: &str) -> ApiResult<()> {
    if nodus_server_store::moderation::blocked_domain(state.store().pool(), domain)
        .await?
        .is_some()
    {
        return Err(ApiError::forbidden("domain is blocked"));
    }
    Ok(())
}

pub(crate) async fn ensure_remote_actor(
    state: &AppState,
    actor_url: &str,
) -> ApiResult<AccountRow> {
    let parsed = validate_remote_url(actor_url)
        .map_err(|_| ApiError::unprocessable("actor URL must be a public HTTPS URL"))?;
    let domain = parsed
        .host_str()
        .ok_or_else(|| ApiError::unprocessable("actor URL has no host"))?;
    ensure_domain_allowed(state, domain).await?;
    if let Some(row) = accounts::by_uri(state.store().pool(), actor_url).await? {
        return Ok(row);
    }
    fetch_remote_actor(state, actor_url, domain).await
}

async fn fetch_remote_actor(
    state: &AppState,
    actor_url: &str,
    domain: &str,
) -> ApiResult<AccountRow> {
    let actor = state
        .fediverse_client()
        .actor_url(actor_url)
        .await
        .map_err(|error| ApiError::unprocessable(error.to_string()))?;
    if actor.id != actor_url {
        return Err(ApiError::unprocessable(
            "actor document id does not match requested actor URL",
        ));
    }
    upsert_remote_actor(state, actor_url, domain, &actor).await
}

pub(crate) fn validate_remote_url(raw: &str) -> ApiResult<url::Url> {
    let parsed = url::Url::parse(raw).map_err(|_| ApiError::unprocessable("URL must be valid"))?;
    if parsed.scheme() != "https" || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ApiError::unprocessable("URL must be a public HTTPS URL"));
    }
    match parsed.host() {
        Some(ref host) if check_url_host(host) => Ok(parsed),
        _ => Err(ApiError::unprocessable(
            "URL host is not a publicly routable destination",
        )),
    }
}

pub(crate) fn validate_remote_host(host: &str) -> ApiResult<()> {
    if host.is_empty()
        || host.contains(|c: char| {
            matches!(c, '/' | '\\' | '?' | '#' | ':' | '@') || c.is_whitespace()
        })
    {
        return Err(ApiError::unprocessable("domain must be a valid hostname"));
    }
    let parsed = url::Host::parse(host)
        .map_err(|_| ApiError::unprocessable("domain must be a valid hostname"))?;
    let allowed = match parsed {
        url::Host::Domain(ref domain) => !is_disallowed_domain(domain),
        url::Host::Ipv4(v4) => !is_disallowed_ipv4(v4),
        url::Host::Ipv6(v6) => !is_disallowed_ipv6(v6),
    };
    if allowed {
        Ok(())
    } else {
        Err(ApiError::unprocessable(
            "domain is not a publicly routable destination",
        ))
    }
}

pub(crate) fn same_origin(left: &str, right: &str) -> bool {
    let (Ok(a), Ok(b)) = (url::Url::parse(left), url::Url::parse(right)) else {
        return false;
    };
    a.origin().is_tuple() && a.origin() == b.origin()
}

fn check_url_host(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(domain) => !is_disallowed_domain(domain),
        url::Host::Ipv4(v4) => !is_disallowed_ipv4(*v4),
        url::Host::Ipv6(v6) => !is_disallowed_ipv6(*v6),
    }
}

fn is_disallowed_domain(domain: &str) -> bool {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return true;
    }
    ["localhost", "local", "internal", "localdomain", "home.arpa"]
        .iter()
        .any(|reserved| {
            d == *reserved
                || d.strip_suffix(reserved)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
}

pub(crate) fn is_disallowed_ipv4(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        || octets[0] == 0
        || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && (octets[1] & 0xfe) == 18)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 240
}

pub(crate) fn is_disallowed_ipv6(v6: Ipv6Addr) -> bool {
    if let Some(v4) = v6.to_ipv4() {
        if is_disallowed_ipv4(v4) {
            return true;
        }
    }
    let segments = v6.segments();
    if segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
    {
        let octets = v6.octets();
        let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
        if is_disallowed_ipv4(v4) {
            return true;
        }
    }
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || segments[0] == 0x0100
}

/// What a peer told us about who may read their note.
///
/// Reading the addressing rather than guessing keeps a direct message private on our side
/// too: a post stored as public would be served to anybody who asks for the thread.
fn addressed(to: &[String], cc: &[String]) -> &'static str {
    let public = "https://www.w3.org/ns/activitystreams#Public";
    let has = |list: &[String]| list.iter().any(|value| value == public);
    match (has(to), has(cc)) {
        (true, _) => "public",
        (false, true) => "unlisted",
        _ => {
            if to.iter().any(|value| value.ends_with("/followers")) {
                "private"
            } else {
                "direct"
            }
        }
    }
}

async fn upsert_remote_actor(
    state: &AppState,
    actor_url: &str,
    domain: &str,
    actor: &Actor,
) -> ApiResult<AccountRow> {
    let display_name = crate::html::escape_text(&actor.name);
    let note = crate::html::sanitize_html(&actor.summary);
    let row = accounts::upsert_remote(
        state.store().pool(),
        &accounts::RemoteAccount {
            uri: actor_url,
            username: &actor.username,
            domain,
            display_name: &display_name,
            note: &note,
            avatar_url: actor.avatar.as_deref(),
            header_url: actor.header.as_deref(),
            inbox_url: actor.inbox.as_deref(),
            shared_inbox_url: actor.shared_inbox.as_deref(),
            public_key_pem: actor.public_key_pem.as_deref(),
            locked: actor.manually_approves_followers,
            bot: actor.kind == "Service" || actor.kind == "Application",
        },
    )
    .await?;
    Ok(
        accounts::set_also_known_as(state.store().pool(), actor_url, &also_known_as(actor))
            .await?
            .unwrap_or(row),
    )
}

async fn local_target(state: &AppState, actor_url: &str) -> ApiResult<Option<AccountRow>> {
    let host = url::Url::parse(actor_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned));
    if host.as_deref() != Some(state.instance().domain.as_str()) {
        return Ok(None);
    }
    let username = actor_url.rsplit('/').next().unwrap_or_default();
    accounts::local_by_username(state.store().pool(), username)
        .await
        .map_err(Into::into)
}

async fn follow_local(
    state: &AppState,
    remote: &AccountRow,
    target: &str,
    follow_id: Option<&str>,
) -> ApiResult<()> {
    let Some(local) = local_target(state, target).await? else {
        return Ok(());
    };
    nodus_server_store::social::follow(state.store().pool(), &remote.id, &local.id, true, false)
        .await?;
    nodus_server_store::social::notify(state.store().pool(), &local.id, "follow", &remote.id, None)
        .await?;
    // An unlocked account has already accepted: the remote server is waiting for the
    // answer, and until it arrives the follow is stuck at "requested" on their side.
    if !local.locked {
        crate::outbox::deliver_follow_response(state, &local.id, &remote.id, true, follow_id).await;
    }
    Ok(())
}

async fn like_local(state: &AppState, remote: &AccountRow, target: &str) -> ApiResult<()> {
    let Some(row) = nodus_server_store::statuses::by_uri(state.store().pool(), target).await?
    else {
        return Ok(());
    };
    // Only a post this instance minted can be counted here: a remote post's favourite is
    // the other server's business, and the count is read from its own payload.
    if !row.local {
        return Ok(());
    }
    nodus_server_store::social::favourite(state.store().pool(), &remote.id, &row.id).await?;
    nodus_server_store::social::notify(
        state.store().pool(),
        &row.account_id,
        "favourite",
        &remote.id,
        Some(&row.id),
    )
    .await?;
    Ok(())
}

async fn boost_local(state: &AppState, remote: &AccountRow, target: &str) -> ApiResult<()> {
    let Some(row) = nodus_server_store::statuses::by_uri(state.store().pool(), target).await?
    else {
        return Ok(());
    };
    if !row.local {
        return Ok(());
    }
    nodus_server_store::statuses::reblog(state.store().pool(), &remote.id, &row.id).await?;
    nodus_server_store::social::notify(
        state.store().pool(),
        &row.account_id,
        "reblog",
        &remote.id,
        Some(&row.id),
    )
    .await?;
    Ok(())
}

async fn unfollow_local(state: &AppState, remote: &AccountRow, target: &str) -> ApiResult<()> {
    if let Some(local) = local_target(state, target).await? {
        nodus_server_store::social::unfollow(state.store().pool(), &remote.id, &local.id).await?;
    }
    Ok(())
}

pub(crate) async fn ingest_note(
    state: &AppState,
    remote: &AccountRow,
    value: &Value,
) -> ApiResult<()> {
    let note =
        Note::from_json(value).map_err(|error| ApiError::unprocessable(error.to_string()))?;
    let actor_uri = remote
        .uri
        .as_deref()
        .ok_or_else(|| ApiError::unprocessable("remote actor has no URI"))?;
    ensure_note_from_actor(state, remote, &note, actor_uri).await?;
    let parent = match &note.in_reply_to {
        Some(uri) => statuses::by_uri(state.store().pool(), uri).await?,
        None => None,
    };
    let created_at = chrono::DateTime::parse_from_rfc3339(&note.published).map_or_else(
        |_| chrono::Utc::now(),
        |date| date.with_timezone(&chrono::Utc),
    );
    let content_html = crate::html::sanitize_html(&note.content);
    let content = html_to_text(&content_html);
    let spoiler_text = crate::html::escape_text(&note.summary);
    let row = statuses::upsert_remote(
        state.store().pool(),
        &statuses::NewRemoteStatus {
            id: &nodus_server_core::Id::new().to_string(),
            account_id: &remote.id,
            uri: &note.id,
            content: &content,
            content_html: &content_html,
            spoiler_text: &spoiler_text,
            sensitive: note.sensitive,
            visibility: addressed(&note.to, &note.cc),
            in_reply_to_id: parent.as_ref().map(|row| row.id.as_str()),
            in_reply_to_account_id: parent.as_ref().map(|row| row.account_id.as_str()),
            created_at,
        },
    )
    .await?;
    store_note_extras(state, remote, &note, value, &row).await?;
    store_note_poll(state, value, &row).await
}

/// Checks that a note really is the sending actor's, and that no other account already
/// owns the URI.
async fn ensure_note_from_actor(
    state: &AppState,
    remote: &AccountRow,
    note: &Note,
    actor_uri: &str,
) -> ApiResult<()> {
    if validate_remote_url(&note.id).is_err() || !same_origin(&note.id, actor_uri) {
        return Err(ApiError::forbidden(
            "note id does not belong to actor origin",
        ));
    }
    if let Some(attributed_to) = note.attributed_to.as_deref() {
        if attributed_to != actor_uri {
            return Err(ApiError::forbidden(
                "note attributedTo does not match actor",
            ));
        }
    }
    if let Some(existing) = statuses::by_uri(state.store().pool(), &note.id).await? {
        if existing.account_id != remote.id {
            return Err(ApiError::forbidden(
                "cannot overwrite status owned by another actor",
            ));
        }
    }
    Ok(())
}

/// Keeps the parts of an ingested note that live outside the status row: who it mentions,
/// its hashtags, its custom emoji and its media.
async fn store_note_extras(
    state: &AppState,
    remote: &AccountRow,
    note: &Note,
    value: &Value,
    row: &StatusRow,
) -> ApiResult<()> {
    let pool = state.store().pool();
    let mut mentions = Vec::new();
    for uri in &note.mentions {
        if let Some(account) = accounts::by_uri(pool, uri).await? {
            mentions.push(account.id);
        } else {
            tracing::debug!(mention = %uri, "mentioned actor is unknown");
        }
    }
    mentions.sort();
    mentions.dedup();
    statuses::replace_mentions(pool, &row.id, &mentions).await?;
    statuses::replace_tags(pool, &row.id, &hashtags_of(note)).await?;
    statuses::replace_emojis(pool, &row.id, &emojis_of(note)).await?;
    media::replace_remote(
        pool,
        &row.id,
        &remote.id,
        note.sensitive,
        &remote_attachments(note, value),
    )
    .await?;
    // The attachments are ours to judge now that they are stored. This is the check site:
    // `screen_status` looks only at `remote` rows, so an upload by one of our own accounts
    // is never quarantined — it was accepted under this instance's rules and its author can
    // answer for it. A failed check must not fail the ingest: the post is already here, and
    // the alternative to a missed match is a delivery the peer will retry forever.
    //
    // A paused domain is the one exception: the attachments are recorded but never fetched,
    // because the pause says this peer's media is not to be pulled right now. That is
    // distinct from `instance_block`'s `reject_media`, which refuses the rows outright.
    let paused = match remote.domain.as_deref() {
        Some(domain) => nodus_server_store::pauses::in_force(pool, domain)
            .await
            .unwrap_or(false),
        None => false,
    };
    if paused {
        tracing::debug!(status = %row.id, domain = ?remote.domain, "not fetching media from a paused domain");
    } else if let Err(error) = crate::guard::screen_status(pool, &row.id, &remote.id).await {
        tracing::warn!(status = %row.id, %error, "inbound media check could not run");
    }
    // Now the instance's rules read the post. Inbound scope: the author is somebody
    // else's account, so a `local` rule is not about them.
    crate::rulewatch::screen(pool, "inbound", &row.id, &remote.id, &row.content).await;
    Ok(())
}

fn hashtags_of(note: &Note) -> Vec<String> {
    let Some(Value::Array(tags)) = note.extra.get("tag") else {
        return Vec::new();
    };
    let mut names: Vec<String> = tags
        .iter()
        .filter(|tag| tag.get("type").and_then(Value::as_str) == Some("Hashtag"))
        .filter_map(|tag| tag.get("name").and_then(Value::as_str))
        .map(|name| name.trim_start_matches('#').to_lowercase())
        .filter(|name| !name.is_empty())
        .collect();
    names.sort();
    names.dedup();
    names
}

fn emojis_of(note: &Note) -> Vec<statuses::StatusEmoji> {
    let mut seen = std::collections::HashSet::new();
    note.emojis
        .iter()
        .filter(|emoji| validate_remote_url(&emoji.url).is_ok())
        .filter_map(|emoji| {
            let shortcode = emoji.shortcode.trim_matches(':').to_owned();
            (!shortcode.is_empty() && seen.insert(shortcode.clone())).then_some(
                statuses::StatusEmoji {
                    shortcode,
                    url: emoji.url.clone(),
                },
            )
        })
        .collect()
}

/// A peer's `Question`, or a `Note` that carries one as an attachment or inline options.
fn question_document(value: &Value) -> Option<&Value> {
    if matches!(document_type(value), Some("Question"))
        || value.get("oneOf").is_some()
        || value.get("anyOf").is_some()
    {
        return Some(value);
    }
    value
        .get("attachment")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|item| matches!(document_type(item), Some("Question")))
        })
}

struct RemotePoll {
    options: Vec<String>,
    tallies: Vec<i64>,
    multiple: bool,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    voters_count: i64,
}

fn remote_poll_of(value: &Value) -> Option<RemotePoll> {
    let multiple = value.get("anyOf").is_some();
    let options = value
        .get("oneOf")
        .or_else(|| value.get("anyOf"))?
        .as_array()?;
    if options.is_empty() || options.len() > 4 {
        tracing::debug!(
            options = options.len(),
            "ignoring a poll this instance cannot hold"
        );
        return None;
    }
    let titles: Vec<String> = options
        .iter()
        .map(|option| {
            option
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    let tallies: Vec<i64> = options.iter().map(poll_tally).collect();
    let voters_count = value
        .get("votersCount")
        .or_else(|| value.get("voters_count"))
        .and_then(Value::as_i64)
        .filter(|count| *count >= 0)
        .unwrap_or_else(|| tallies.iter().sum());
    let expires_at = value
        .get("endTime")
        .and_then(Value::as_str)
        .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
        .map(|at| at.with_timezone(&chrono::Utc));
    Some(RemotePoll {
        options: titles,
        tallies,
        multiple,
        expires_at,
        voters_count,
    })
}

fn poll_tally(option: &Value) -> i64 {
    option
        .get("replies")
        .and_then(|replies| replies.get("totalItems"))
        .or_else(|| option.get("votes_count"))
        .or_else(|| option.get("votesCount"))
        .and_then(Value::as_i64)
        .unwrap_or(0)
        .max(0)
}

/// Stores a federated poll as the same rows a local poll uses, with the peer's counts.
async fn store_note_poll(state: &AppState, value: &Value, row: &StatusRow) -> ApiResult<()> {
    let poll = question_document(value).and_then(remote_poll_of);
    let Some(poll) = poll else {
        // The note arrives without a `Question` — a peer that withdrew its poll, or an
        // `Update` that never had one. Either way the status has no poll now, so the
        // stored one and its tallies must not outlive the document that brought them.
        polls::delete_for_status(state.store().pool(), &row.id).await?;
        return Ok(());
    };
    polls::upsert_remote(
        state.store().pool(),
        &polls::NewRemotePoll {
            status_id: &row.id,
            options: &poll.options,
            multiple: poll.multiple,
            expires_at: poll.expires_at,
            voters_count: poll.voters_count,
            tallies: &poll.tallies,
        },
    )
    .await?;
    Ok(())
}

/// The `blurhash` a peer put on an attachment.
///
/// The typed `Attachment` does not model the placeholder, so it is read back from the
/// document by URL; a peer that sends none keeps `None` rather than an empty string.
fn raw_blurhash<'a>(value: &'a Value, url: &str) -> Option<&'a str> {
    let attachments = match value.get("attachment") {
        Some(Value::Array(items)) => items.as_slice(),
        Some(item @ Value::Object(_)) => std::slice::from_ref(item),
        _ => return None,
    };
    attachments
        .iter()
        .find(|item| item.get("url").and_then(Value::as_str) == Some(url))
        .and_then(|item| item.get("blurhash"))
        .and_then(Value::as_str)
        .filter(|hash| !hash.is_empty())
}

fn remote_attachments<'a>(note: &'a Note, value: &'a Value) -> Vec<media::RemoteAttachment<'a>> {
    note.attachments
        .iter()
        .filter(|attachment| validate_remote_url(&attachment.url).is_ok())
        .filter_map(|attachment| {
            let content_type = match attachment.kind.as_str() {
                "Image" => "image/jpeg",
                "Video" => "video/mp4",
                "Audio" => "audio/mpeg",
                // A `Document` is a PDF or a plain file; Mastodon has no type of its own
                // for it and reports an unclassified upload as `unknown`, which the DTO
                // derives from this content type.
                "Document" => "application/octet-stream",
                _ => return None,
            };
            Some(media::RemoteAttachment {
                url: &attachment.url,
                content_type,
                description: attachment.description.as_deref().unwrap_or_default(),
                width: attachment.width.and_then(|value| i32::try_from(value).ok()),
                height: attachment
                    .height
                    .and_then(|value| i32::try_from(value).ok()),
                blurhash: raw_blurhash(value, &attachment.url),
            })
        })
        .collect()
}

fn html_to_text(html: &str) -> String {
    let mut text = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => text.push(ch),
            _ => {}
        }
    }
    text.trim().to_owned()
}

/// The text of an HTML fragment with the entities the sanitizer introduced undone.
fn html_to_plain(html: &str) -> String {
    html_to_text(html)
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

pub(crate) async fn status_activity(
    state: &AppState,
    row: &StatusRow,
    account: &AccountRow,
) -> ApiResult<Activity> {
    let (value, note) = status_object(state, row, account).await?;
    Ok(Activity::new(
        ActivityKind::Create,
        actor_url(state, account),
        ActivityObject::Value(value),
    )
    .addressed_to(note.to.clone(), note.cc.clone())
    .with_id(format!("{}/activity", note.id.trim_end_matches('/'))))
}

/// An `Update` carrying the status as it stands now.
///
/// Poll tallies move after publication, and an `Update` is how a peer hears the new
/// counts without a second sender or a second queue.
pub(crate) async fn status_update(
    state: &AppState,
    row: &StatusRow,
    account: &AccountRow,
) -> ApiResult<Activity> {
    let (value, note) = status_object(state, row, account).await?;
    Ok(Activity::new(
        ActivityKind::Update,
        actor_url(state, account),
        ActivityObject::Value(value),
    )
    .addressed_to(note.to.clone(), note.cc.clone())
    .with_id(format!(
        "{}/activity#updates/{}",
        note.id.trim_end_matches('/'),
        nodus_server_core::Id::new()
    )))
}

/// The object a `Create` or `Update` carries: a `Question` when the status has a poll,
/// otherwise the plain note.
async fn status_object(
    state: &AppState,
    row: &StatusRow,
    account: &AccountRow,
) -> ApiResult<(Value, Note)> {
    let note = note_document(state, row, account).await?;
    let Some(poll) = polls::by_status(state.store().pool(), &row.id).await? else {
        return Ok((note.to_json(), note));
    };
    let (counts, voters_count) = crate::polls::counts(state, &poll).await?;
    let mut value = note.to_json();
    let Some(map) = value.as_object_mut() else {
        return Ok((value, note));
    };
    map.insert("type".to_owned(), Value::String("Question".to_owned()));
    let options: Vec<Value> = poll
        .options
        .0
        .iter()
        .enumerate()
        .map(|(index, name)| {
            json!({
                "type": "Note",
                "name": name,
                "replies": {
                    "type": "Collection",
                    "totalItems": counts.get(index).copied().unwrap_or(0),
                },
            })
        })
        .collect();
    map.insert(
        if poll.multiple { "anyOf" } else { "oneOf" }.to_owned(),
        Value::Array(options),
    );
    if let Some(expires_at) = poll.expires_at {
        map.insert(
            "endTime".to_owned(),
            Value::String(expires_at.to_rfc3339_opts(SecondsFormat::Secs, true)),
        );
    }
    map.insert("votersCount".to_owned(), json!(voters_count));
    Ok((value, note))
}

/// Who a note is addressed to.
///
/// A direct post is addressed to the accounts it names and to nobody else; a private one
/// reaches the author's followers. Public and unlisted posts put the public collection at
/// opposite ends of `to`/`cc`, which is how a peer tells them apart.
fn audience(visibility: &str, actor: &str, mentioned: &[String]) -> (Vec<String>, Vec<String>) {
    let public = String::from("https://www.w3.org/ns/activitystreams#Public");
    let followers = format!("{actor}/followers");
    let mentioned = mentioned.to_vec();
    match visibility {
        "public" => (
            vec![public],
            std::iter::once(followers).chain(mentioned).collect(),
        ),
        "unlisted" => (
            std::iter::once(followers)
                .chain(mentioned.clone())
                .collect(),
            vec![public],
        ),
        "private" => (vec![followers], mentioned),
        _ => (mentioned, Vec::new()),
    }
}

/// The actors named by a status, as `ActivityPub` ids.
async fn mentioned_actors(state: &AppState, row: &StatusRow) -> Vec<String> {
    let pool = state.store().pool();
    let mut actors = Vec::new();
    for id in statuses::mentions_of(pool, &row.id)
        .await
        .unwrap_or_default()
    {
        match nodus_server_store::accounts::by_id(pool, &id).await {
            Ok(Some(account)) => actors.push(actor_url(state, &account)),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, mention = %id, "could not read a mentioned account");
            }
        }
    }
    actors
}

async fn note_document(state: &AppState, row: &StatusRow, account: &AccountRow) -> ApiResult<Note> {
    let actor = actor_url(state, account);
    let id = status_url(state, row);
    let parent = match &row.in_reply_to_id {
        Some(parent_id) => statuses::by_id(state.store().pool(), parent_id)
            .await?
            .map(|parent| status_url(state, &parent)),
        None => None,
    };
    let mentioned = mentioned_actors(state, row).await;
    let (to, cc) = audience(row.visibility.as_str(), &actor, &mentioned);
    let media = nodus_server_store::media::by_status(state.store().pool(), &row.id).await?;
    let attachments = media
        .iter()
        .map(|media| {
            let url = media
                .remote_url
                .clone()
                .unwrap_or_else(|| state.instance().url(&format!("/media/{}", media.id)));
            Attachment {
                kind: if media.content_type.starts_with("video/") {
                    "Video".to_owned()
                } else if media.content_type.starts_with("image/") {
                    "Image".to_owned()
                } else {
                    "Document".to_owned()
                },
                url: url.clone(),
                preview_url: Some(url),
                description: (!media.description.is_empty()).then(|| media.description.clone()),
                width: media.width.and_then(|value| u32::try_from(value).ok()),
                height: media.height.and_then(|value| u32::try_from(value).ok()),
            }
        })
        .collect();
    Ok(Note {
        id: id.clone(),
        url: state
            .instance()
            .url(&format!("/@{}/{}", account.username, row.id)),
        content: row.content_html.clone(),
        published: row.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        sensitive: row.sensitive,
        summary: row.spoiler_text.clone(),
        attachments,
        emojis: Vec::new(),
        in_reply_to: parent,
        replies: Some(format!("{id}/replies")),
        replies_count: u64::try_from(row.replies_count).unwrap_or_default(),
        attributed_to: Some(actor),
        to,
        cc,
        mentions: mentioned,
        extra: Map::default(),
    })
}

/// A local account has to be its own actor before it can be fetched. Keys are generated
/// once and written beside the account; a later request reuses them so the key id stays
/// stable for remote caches.
pub(crate) async fn ensure_identity(
    state: &AppState,
    account: AccountRow,
) -> ApiResult<AccountRow> {
    if account.uri.is_some()
        && account.public_key_pem.is_some()
        && account.private_key_pem.is_some()
    {
        return Ok(account);
    }
    let actor = state
        .instance()
        .url(&format!("/users/{}", account.username));
    let keys = ActorKeys::generate()?;
    let inbox = format!("{actor}/inbox");
    let shared = state.instance().url("/inbox");
    accounts::set_actor_identity(
        state.store().pool(),
        &account.id,
        &actor,
        &keys.public_pem,
        &keys.private_pem,
        &inbox,
        Some(&shared),
    )
    .await
    .map_err(Into::into)
}

struct ActorKeys {
    public_pem: String,
    private_pem: String,
}

impl ActorKeys {
    fn generate() -> ApiResult<Self> {
        let private = RsaPrivateKey::new(&mut OsRng, 2048).map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not create actor key",
            )
        })?;
        let public = rsa::RsaPublicKey::from(&private);
        let private_pem = private.to_pkcs8_pem(LineEnding::LF).map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not encode actor key",
            )
        })?;
        let public_pem = public.to_public_key_pem(LineEnding::LF).map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not encode actor key",
            )
        })?;
        Ok(Self {
            public_pem,
            private_pem: private_pem.to_string(),
        })
    }
}

fn actor_document(state: &AppState, account: &AccountRow) -> Actor {
    let actor = actor_url(state, account);
    Actor {
        id: actor.clone(),
        kind: "Person".to_owned(),
        username: account.username.clone(),
        name: account.display_name.clone(),
        summary: account.note.clone(),
        url: state.instance().url(&format!("/@{}", account.username)),
        avatar: account
            .avatar_ref
            .as_ref()
            .map(|name| state.instance().url(&format!("/media/{name}"))),
        header: account
            .header_ref
            .as_ref()
            .map(|name| state.instance().url(&format!("/media/{name}"))),
        followers: Some(format!("{actor}/followers")),
        following: Some(format!("{actor}/following")),
        outbox: Some(format!("{actor}/outbox")),
        inbox: Some(format!("{actor}/inbox")),
        shared_inbox: Some(state.instance().url("/inbox")),
        public_key_id: Some(format!("{actor}#main-key")),
        public_key_pem: account.public_key_pem.clone(),
        published: Some(
            account
                .created_at
                .to_rfc3339_opts(SecondsFormat::Secs, true),
        ),
        discoverable: account.discoverable,
        indexable: account.indexable,
        manually_approves_followers: account.locked,
        extra: Map::default(),
    }
}

pub(crate) fn actor_url(state: &AppState, account: &AccountRow) -> String {
    account.uri.clone().unwrap_or_else(|| {
        state
            .instance()
            .url(&format!("/users/{}", account.username))
    })
}

pub(crate) fn status_url(state: &AppState, row: &StatusRow) -> String {
    row.uri
        .clone()
        .unwrap_or_else(|| state.instance().url(&format!("/statuses/{}", row.id)))
}

/// The handle every pre-4.2 Mastodon, and every peer that reads the actor document,
/// derives for the instance actor. The actor is served at `https://host/actor`.
pub(crate) const INSTANCE_ACTOR_USERNAME: &str = "instance.actor";

/// Whether a resolved local username names the instance actor rather than a stored
/// account. The bare domain is included because Mastodon 4.2+ uses `host@host` for its
/// own instance actor, and a peer may ask for that shape before reading ours.
fn is_instance_actor(username: &str, domain: &str) -> bool {
    username.eq_ignore_ascii_case(INSTANCE_ACTOR_USERNAME) || username.eq_ignore_ascii_case(domain)
}

/// The JRD for the instance actor, in the shape Mastodon's own instance actor answers
/// with: an `acct:` subject, the actor URL as the sole alias, a profile-page link and
/// an `activity+json` self link. Peers follow the self link, and some validate that the
/// subject's handle and the document's `preferredUsername` agree.
fn instance_webfinger(state: &AppState) -> Webfinger {
    let actor = state.instance().url("/actor");
    Webfinger {
        subject: format!("acct:{INSTANCE_ACTOR_USERNAME}@{}", state.instance().domain),
        aliases: vec![actor.clone()],
        links: vec![
            WebfingerLink::profile(&state.instance().url("/")),
            WebfingerLink::activitypub(&actor),
        ],
    }
}

fn local_username(resource: &str, domain: &str) -> Option<String> {
    if let Some(handle) = resource.strip_prefix("acct:") {
        let (username, host) = handle.rsplit_once('@')?;
        if !host.eq_ignore_ascii_case(domain) {
            return None;
        }
        return Some(username.to_owned());
    }
    let rest = resource
        .strip_prefix("https://")
        .or_else(|| resource.strip_prefix("http://"))?;
    let (_, path) = rest.split_once('/')?;
    if path.trim_end_matches('/') == "actor" {
        return Some(INSTANCE_ACTOR_USERNAME.to_owned());
    }
    path.strip_prefix("users/").map(str::to_owned)
}

fn document_response<D: Document>(document: &D) -> Response {
    let mut response = Json(document.document()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(D::CONTENT_TYPE),
    );
    response
}

#[cfg(test)]
mod tests {

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn public_and_unlisted_notes_copy_the_peers_addressing() {
        let public = "https://www.w3.org/ns/activitystreams#Public";
        let followers = "https://social.test/users/ada/followers";
        assert_eq!(
            super::addressed(&strings(&[public]), &strings(&[followers])),
            "public"
        );
        assert_eq!(
            super::addressed(&strings(&[followers]), &strings(&[public])),
            "unlisted"
        );
    }

    #[test]
    fn a_note_without_the_public_collection_stays_as_private_as_it_arrived() {
        let followers = "https://social.test/users/ada/followers";
        let eve = "https://mastodon.test/users/eve";
        assert_eq!(
            super::addressed(&strings(&[followers]), &strings(&[eve])),
            "private"
        );
        assert_eq!(super::addressed(&strings(&[eve]), &[]), "direct");
    }

    #[test]
    fn a_public_note_addresses_the_world_and_its_followers() {
        let actor = "https://social.test/users/ada";
        let (to, cc) = super::audience("public", actor, &[]);
        assert_eq!(to, vec!["https://www.w3.org/ns/activitystreams#Public"]);
        assert_eq!(cc, vec![format!("{actor}/followers")]);
    }

    #[test]
    fn a_direct_note_addresses_only_the_people_it_names() {
        let actor = "https://social.test/users/ada";
        let mentioned = vec!["https://mastodon.test/users/eve".to_owned()];
        let (to, cc) = super::audience("direct", actor, &mentioned);
        assert_eq!(to, mentioned);
        assert_eq!(cc, Vec::<String>::new());
    }

    #[test]
    fn a_private_note_reaches_followers_and_names_its_mentions() {
        let actor = "https://social.test/users/ada";
        let mentioned = vec!["https://mastodon.test/users/eve".to_owned()];
        let (to, cc) = super::audience("private", actor, &mentioned);
        assert_eq!(to, vec![format!("{actor}/followers")]);
        assert_eq!(cc, mentioned);
    }

    #[test]
    fn an_unlisted_note_keeps_the_public_collection_out_of_to() {
        let actor = "https://social.test/users/ada";
        let (to, cc) = super::audience("unlisted", actor, &[]);
        assert_eq!(to, vec![format!("{actor}/followers")]);
        assert_eq!(cc, vec!["https://www.w3.org/ns/activitystreams#Public"]);
    }
    use super::*;
    use nodus_server_core::Id;
    use nodus_server_store::Store;

    async fn with_isolated_state<F, Fut>(body: F)
    where
        F: FnOnce(Store, AppState) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let admin = Store::connect(&url, 1).await.expect("connect to postgres");
        let schema = format!("pgtest_{}", Id::new());
        sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
            .execute(admin.pool())
            .await
            .expect("create isolated test schema");

        let sep = if url.contains('?') { '&' } else { '?' };
        let schema_url = format!("{url}{sep}options=-csearch_path%3D{schema}%2Cpublic");
        let store = Store::connect(&schema_url, 5)
            .await
            .expect("connect isolated store");
        store.migrate().await.expect("run migrations");

        let state = AppState::new(
            store.clone(),
            crate::InstanceConfig {
                domain: "social.test".to_owned(),
                base_url: "https://social.test".to_owned(),
                title: "Nodus test".to_owned(),
                description: "A test instance".to_owned(),
                contact_email: None,
                api_version: "4.3.0".to_owned(),
                version: "0.1.0".to_owned(),
                registrations_open: false,
            },
        );
        body(store, state).await;

        let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
            .execute(admin.pool())
            .await;
    }

    #[tokio::test]
    async fn ingest_note_sanitizes_html_and_escapes_summary() {
        with_isolated_state(|store, state| async move {
            let remote = accounts::upsert_remote(
                store.pool(),
                &accounts::RemoteAccount {
                    uri: "https://remote.test/users/mallory",
                    username: "mallory",
                    domain: "remote.test",
                    display_name: "Mallory",
                    note: "",
                    avatar_url: None,
                    header_url: None,
                    inbox_url: Some("https://remote.test/users/mallory/inbox"),
                    shared_inbox_url: None,
                    public_key_pem: None,
                    locked: false,
                    bot: false,
                },
            )
            .await
            .expect("upsert remote account");

            let note_uri = format!("https://remote.test/notes/{}", Id::new());
            let note_json = serde_json::json!({
                "id": note_uri,
                "type": "Note",
                "published": "2026-01-01T00:00:00Z",
                "summary": "<script>alert('cw')</script> & warning",
                "sensitive": true,
                "content": "<p>Hello <span class=\"h-card\"><a class=\"u-url mention\" href=\"https://social.test/@alice\">@alice</a></span></p><script>alert(1)</script><img src=x onerror=alert(2)><a href=\"javascript:alert(3)\">evil</a>"
            });

            ingest_note(&state, &remote, &note_json)
                .await
                .expect("ingest note");

            let stored = statuses::by_uri(store.pool(), &note_uri)
                .await
                .expect("lookup")
                .expect("stored status");

            assert!(!stored.content_html.contains("<script"));
            assert!(!stored.content_html.contains("alert(1)"));
            assert!(!stored.content_html.contains("<img"));
            assert!(!stored.content_html.contains("onerror"));
            assert!(!stored.content_html.contains("javascript:"));
            assert!(
                stored.content_html.contains(
                    r#"<span class="h-card"><a class="u-url mention" href="https://social.test/@alice" target="_blank" rel="nofollow noopener noreferrer">@alice</a></span>"#
                ),
                "mention formatting lost: {}",
                stored.content_html
            );
            assert!(stored.content_html.contains(">evil</a>"), "unwrapped link text lost");
            assert!(!stored.content.contains("alert(1)"));
            assert!(!stored.spoiler_text.contains('<'));
            assert!(stored.spoiler_text.contains("&lt;script&gt;"));
            assert!(stored.spoiler_text.contains("&amp;"));
        })
        .await;
    }

    #[tokio::test]
    async fn upsert_remote_actor_sanitizes_summary_and_escapes_name() {
        with_isolated_state(|_store, state| async move {
            let actor_url = format!("https://remote.test/users/{}", Id::new());
            let actor = Actor {
                id: actor_url.clone(),
                kind: "Person".to_owned(),
                username: "mallory".to_owned(),
                name: "<script>alert('name')</script> & <b>Mallory</b>".to_owned(),
                summary: "<p>Bio <a href=\"https://remote.test/@mallory\">profile</a></p><script>alert(1)</script><img src=x onerror=alert(2)>".to_owned(),
                url: actor_url.clone(),
                avatar: None,
                header: None,
                followers: None,
                following: None,
                outbox: None,
                inbox: Some(format!("{actor_url}/inbox")),
                shared_inbox: None,
                public_key_pem: None,
                public_key_id: None,
                published: None,
                discoverable: true,
                indexable: true,
                manually_approves_followers: false,
                extra: Map::default(),
            };

            let row = upsert_remote_actor(&state, &actor_url, "remote.test", &actor)
                .await
                .expect("upsert remote actor");

            assert!(!row.display_name.contains('<'));
            assert!(row.display_name.contains("&lt;script&gt;"));
            assert!(row.display_name.contains("&amp;"));
            assert!(!row.note.contains("<script"));
            assert!(!row.note.contains("alert(1)"));
            assert!(!row.note.contains("<img"));
            assert!(!row.note.contains("onerror"));
            assert!(
                row.note.contains(
                    r#"<p>Bio <a href="https://remote.test/@mallory" target="_blank" rel="nofollow noopener noreferrer">profile</a></p>"#
                ),
                "bio was: {}",
                row.note
            );
        })
        .await;
    }

    #[test]
    fn webfinger_accepts_the_local_acct_form() {
        assert_eq!(
            local_username("acct:alice@social.test", "social.test"),
            Some("alice".to_owned())
        );
        assert_eq!(local_username("acct:alice@other.test", "social.test"), None);
    }

    #[test]
    fn webfinger_accepts_the_actor_url_form() {
        assert_eq!(
            local_username("https://social.test/users/alice", "social.test"),
            Some("alice".to_owned())
        );
        assert_eq!(
            local_username("https://social.test/actor", "social.test"),
            Some(INSTANCE_ACTOR_USERNAME.to_owned())
        );
    }

    #[test]
    fn the_instance_actor_answers_to_the_legacy_and_domain_handles() {
        assert!(is_instance_actor("instance.actor", "social.test"));
        assert!(is_instance_actor("SOCIAL.TEST", "social.test"));
        assert!(!is_instance_actor("alice", "social.test"));
    }

    async fn seed_remote(store: &Store, uri: &str) -> AccountRow {
        let domain = uri
            .split("://")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .unwrap_or("remote.test");
        let username = uri.rsplit('/').next().unwrap_or("remote");
        let inbox = format!("{uri}/inbox");
        accounts::upsert_remote(
            store.pool(),
            &accounts::RemoteAccount {
                uri,
                username,
                domain,
                display_name: username,
                note: "",
                avatar_url: None,
                header_url: None,
                inbox_url: Some(inbox.as_str()),
                shared_inbox_url: None,
                public_key_pem: None,
                locked: false,
                bot: false,
            },
        )
        .await
        .expect("seed remote account")
    }

    fn move_activity(actor: &str, target: &str) -> Activity {
        let mut extra = Map::new();
        extra.insert("target".to_owned(), serde_json::json!(target));
        Activity {
            id: Some(format!("{actor}#moves/{}", Id::new())),
            kind: ActivityKind::Move,
            actor: actor.to_owned(),
            object: ActivityObject::Id(actor.to_owned()),
            to: Vec::new(),
            cc: Vec::new(),
            extra,
        }
    }

    #[tokio::test]
    async fn an_unverified_move_changes_nothing() {
        with_isolated_state(|store, state| async move {
            let mover_uri = "https://old.test/users/a";
            let target_uri = "https://new.test/users/a";
            seed_remote(&store, mover_uri).await;
            seed_remote(&store, target_uri).await;
            let stranger = "https://stranger.test/users/b".to_owned();
            accounts::set_also_known_as(store.pool(), target_uri, &[stranger.clone()])
                .await
                .expect("seed target aliases");

            ingest_activity(&state, &move_activity(mover_uri, target_uri))
                .await
                .expect("ingest move");

            let stored = accounts::by_uri(store.pool(), mover_uri)
                .await
                .expect("read mover")
                .expect("mover row");
            assert!(stored.moved_to.is_none());
            let target = accounts::by_uri(store.pool(), target_uri)
                .await
                .expect("read target")
                .expect("target row");
            assert_eq!(target.also_known_as, vec![stranger]);
        })
        .await;
    }

    #[tokio::test]
    async fn a_move_the_target_acknowledges_is_recorded_without_deleting_anything() {
        with_isolated_state(|store, state| async move {
            let mover_uri = "https://old.test/users/a";
            let target_uri = "https://new.test/users/a";
            let mover = seed_remote(&store, mover_uri).await;
            seed_remote(&store, target_uri).await;
            accounts::set_also_known_as(store.pool(), target_uri, &[mover_uri.to_owned()])
                .await
                .expect("seed target aliases");
            let status_uri = format!("https://old.test/notes/{}", Id::new());
            statuses::upsert_remote(
                store.pool(),
                &statuses::NewRemoteStatus {
                    id: &Id::new().to_string(),
                    account_id: &mover.id,
                    uri: &status_uri,
                    content: "before the move",
                    content_html: "<p>before the move</p>",
                    spoiler_text: "",
                    sensitive: false,
                    visibility: "public",
                    in_reply_to_id: None,
                    in_reply_to_account_id: None,
                    created_at: chrono::Utc::now(),
                },
            )
            .await
            .expect("seed status");

            ingest_activity(&state, &move_activity(mover_uri, target_uri))
                .await
                .expect("ingest move");

            let stored = accounts::by_uri(store.pool(), mover_uri)
                .await
                .expect("read mover")
                .expect("mover row");
            assert_eq!(stored.moved_to.as_deref(), Some(target_uri));
            assert!(statuses::by_uri(store.pool(), &status_uri)
                .await
                .expect("read status")
                .is_some());
        })
        .await;
    }

    #[tokio::test]
    async fn a_move_to_an_uncached_actor_is_ignored() {
        with_isolated_state(|store, state| async move {
            let mover_uri = "https://old.test/users/a";
            seed_remote(&store, mover_uri).await;
            ingest_activity(
                &state,
                &move_activity(mover_uri, "https://missing.invalid/users/a"),
            )
            .await
            .expect("an unverifiable move is ignored");

            let stored = accounts::by_uri(store.pool(), mover_uri)
                .await
                .expect("read mover")
                .expect("mover row");
            assert!(stored.moved_to.is_none());
        })
        .await;
    }

    #[tokio::test]
    async fn a_move_from_an_uncached_actor_is_rejected() {
        with_isolated_state(|_store, state| async move {
            let error = ingest_activity(
                &state,
                &move_activity(
                    "https://missing.invalid/users/a",
                    "https://new.test/users/a",
                ),
            )
            .await
            .expect_err("an actor we cannot fetch cannot move");
            assert!(!error.message().is_empty());
        })
        .await;
    }

    #[test]
    fn a_flag_with_an_array_object_is_parsed_with_its_targets() {
        let value = serde_json::json!({
            "id": "https://remote.test/reports/1",
            "type": "Flag",
            "actor": "https://remote.test/users/mallory",
            "content": "spam",
            "object": [
                "https://remote.test/users/spammer",
                {"id": "https://remote.test/notes/9"}
            ]
        });
        let activity = super::flag_activity(&value).expect("flag parsed");
        assert_eq!(activity.kind, ActivityKind::Flag);
        assert_eq!(activity.actor, "https://remote.test/users/mallory");
        assert_eq!(
            super::flag_targets(&activity),
            vec![
                "https://remote.test/users/spammer".to_owned(),
                "https://remote.test/notes/9".to_owned()
            ]
        );
    }

    #[test]
    fn the_flag_fallback_only_handles_array_objects() {
        assert!(super::flag_activity(&serde_json::json!({
            "type": "Flag",
            "actor": "https://remote.test/users/mallory",
            "object": "https://remote.test/users/spammer"
        }))
        .is_none());
        assert!(super::flag_activity(&serde_json::json!({
            "type": "Create",
            "actor": "https://remote.test/users/mallory",
            "object": []
        }))
        .is_none());
    }

    #[test]
    fn hashtags_are_lowercased_deduplicated_and_ignore_mentions() {
        let note = Note::from_json(&serde_json::json!({
            "id": "https://remote.test/notes/1",
            "type": "Note",
            "content": "<p>hi</p>",
            "tag": [
                {"type": "Hashtag", "name": "#Rust"},
                {"type": "Hashtag", "name": "#rust"},
                {"type": "Mention", "href": "https://remote.test/users/eve"},
                {"type": "Hashtag", "name": "#"}
            ]
        }))
        .expect("note parses");
        assert_eq!(super::hashtags_of(&note), vec!["rust".to_owned()]);
    }

    #[tokio::test]
    async fn an_ingested_note_keeps_mentions_tags_and_media() {
        with_isolated_state(|store, state| async move {
            let author = seed_remote(&store, "https://remote.test/users/mallory").await;
            let mentioned = seed_remote(&store, "https://remote.test/users/eve").await;
            let note_uri = format!("https://remote.test/notes/{}", Id::new());
            let note = serde_json::json!({
                "id": note_uri,
                "type": "Note",
                "published": "2026-01-01T00:00:00Z",
                "content": "<p>look</p>",
                "tag": [
                    {"type": "Mention", "href": mentioned.uri.clone().unwrap()},
                    {"type": "Hashtag", "name": "#Rust"}
                ],
                "attachment": [{
                    "type": "Image",
                    "url": "https://remote.test/media/1.png",
                    "name": "alt text",
                    "width": 640,
                    "height": 480
                }]
            });

            ingest_note(&state, &author, &note)
                .await
                .expect("ingest note");

            let row = statuses::by_uri(store.pool(), &note_uri)
                .await
                .expect("lookup")
                .expect("stored status");
            assert_eq!(
                statuses::mentions_of(store.pool(), &row.id)
                    .await
                    .expect("read mentions"),
                vec![mentioned.id.clone()]
            );
            assert_eq!(
                statuses::tags_of(store.pool(), &row.id)
                    .await
                    .expect("read tags"),
                vec!["rust".to_owned()]
            );
            let stored = media::by_status(store.pool(), &row.id)
                .await
                .expect("read media");
            assert_eq!(stored.len(), 1);
            assert_eq!(
                stored[0].remote_url.as_deref(),
                Some("https://remote.test/media/1.png")
            );
            assert_eq!(stored[0].description, "alt text");
        })
        .await;
    }

    #[tokio::test]
    async fn an_ingested_note_serves_tags_emoji_and_media_in_its_dto() {
        with_isolated_state(|store, state| async move {
            let author = seed_remote(&store, "https://remote.test/users/mallory").await;
            let mentioned = seed_remote(&store, "https://remote.test/users/eve").await;
            let note_uri = format!("https://remote.test/notes/{}", Id::new());
            let note = serde_json::json!({
                "id": note_uri,
                "type": "Note",
                "published": "2026-01-01T00:00:00Z",
                "content": "<p>:ferris: look #Rust</p>",
                "tag": [
                    {"type": "Mention", "href": mentioned.uri.clone().unwrap()},
                    {"type": "Hashtag", "name": "#Rust"},
                    {"type": "Hashtag", "name": "#fedi"},
                    {"type": "Emoji", "name": ":ferris:", "icon": {"type": "Image", "url": "https://remote.test/emoji/ferris.png"}}
                ],
                "attachment": [{
                    "type": "Image",
                    "url": "https://remote.test/media/1.png",
                    "name": "alt text",
                    "width": 640,
                    "height": 480
                }]
            });

            ingest_note(&state, &author, &note)
                .await
                .expect("ingest note");
            let row = statuses::by_uri(store.pool(), &note_uri)
                .await
                .expect("lookup")
                .expect("stored status");
            let dto = crate::statuses::dto(&state, &row, None)
                .await
                .expect("build status dto");
            let body = serde_json::to_value(dto).expect("serialize status dto");

            assert_eq!(body["tags"][0]["name"], "fedi");
            assert_eq!(body["tags"][1]["name"], "rust");
            assert_eq!(body["mentions"][0]["username"], "eve");
            assert_eq!(
                body["mentions"][0]["url"], "https://remote.test/@eve",
                "a remote mention links to the profile the peer holds"
            );
            assert_eq!(body["emojis"][0]["shortcode"], "ferris");
            assert_eq!(
                body["emojis"][0]["url"],
                "https://remote.test/emoji/ferris.png"
            );
            assert_eq!(
                body["media_attachments"][0]["url"],
                "https://remote.test/media/1.png"
            );
            assert_eq!(body["media_attachments"][0]["type"], "image");
        })
        .await;
    }

    #[tokio::test]
    async fn a_document_attachment_ingests_as_an_unknown_file() {
        with_isolated_state(|store, state| async move {
            let author = seed_remote(&store, "https://remote.test/users/mallory").await;
            let note_uri = format!("https://remote.test/notes/{}", Id::new());
            let note = serde_json::json!({
                "id": note_uri,
                "type": "Note",
                "published": "2026-01-01T00:00:00Z",
                "content": "<p>a paper</p>",
                "attachment": [{
                    "type": "Document",
                    "url": "https://remote.test/media/paper.pdf",
                    "name": "the paper",
                    "width": 612,
                    "height": 792,
                    "blurhash": "LEHV6nWB2yk8pyo0adR*.7kCMdnj"
                }]
            });

            ingest_note(&state, &author, &note)
                .await
                .expect("ingest note");
            let row = statuses::by_uri(store.pool(), &note_uri)
                .await
                .expect("lookup")
                .expect("stored status");
            let dto = crate::statuses::dto(&state, &row, None)
                .await
                .expect("build status dto");
            let body = serde_json::to_value(dto).expect("serialize status dto");

            assert_eq!(body["media_attachments"][0]["type"], "unknown");
            assert_eq!(
                body["media_attachments"][0]["url"],
                "https://remote.test/media/paper.pdf"
            );
            assert_eq!(body["media_attachments"][0]["description"], "the paper");
            assert_eq!(
                body["media_attachments"][0]["blurhash"],
                "LEHV6nWB2yk8pyo0adR*.7kCMdnj"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn an_update_without_a_question_clears_the_stored_poll() {
        with_isolated_state(|store, state| async move {
            let author = seed_remote(&store, "https://remote.test/users/mallory").await;
            let question_uri = format!("https://remote.test/questions/{}", Id::new());
            let question = serde_json::json!({
                "id": question_uri,
                "type": "Question",
                "published": "2026-01-01T00:00:00Z",
                "content": "<p>which?</p>",
                "to": ["https://www.w3.org/ns/activitystreams#Public"],
                "oneOf": [
                    {"type": "Note", "name": "yes", "replies": {"type": "Collection", "totalItems": 3}},
                    {"type": "Note", "name": "no", "replies": {"type": "Collection", "totalItems": 2}}
                ],
                "votersCount": 5
            });
            ingest_note(&state, &author, &question)
                .await
                .expect("ingest question");
            let row = statuses::by_uri(store.pool(), &question_uri)
                .await
                .expect("lookup")
                .expect("stored status");
            let poll = polls::by_status(store.pool(), &row.id)
                .await
                .expect("read poll")
                .expect("question became a poll");

            let activity = Activity::new(
                ActivityKind::Update,
                author.uri.clone().unwrap(),
                serde_json::json!({
                    "id": question_uri,
                    "type": "Note",
                    "content": "<p>never mind</p>",
                    "to": ["https://www.w3.org/ns/activitystreams#Public"]
                }),
            );
            ingest_activity(&state, &activity)
                .await
                .expect("ingest poll-less update");

            assert!(
                polls::by_status(store.pool(), &row.id)
                    .await
                    .expect("read poll")
                    .is_none(),
                "a note that no longer asks a question has no poll"
            );
            assert!(
                polls::tally_counts(store.pool(), &poll.id)
                    .await
                    .expect("read tallies")
                    .is_empty(),
                "the withdrawn poll's tallies go with it"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn an_ingested_question_becomes_a_read_only_poll_with_the_peers_counts() {
        with_isolated_state(|store, state| async move {
            let author = seed_remote(&store, "https://remote.test/users/mallory").await;
            let question_uri = format!("https://remote.test/questions/{}", Id::new());
            let question = serde_json::json!({
                "id": question_uri,
                "type": "Question",
                "published": "2026-01-01T00:00:00Z",
                "content": "<p>which?</p>",
                "to": ["https://www.w3.org/ns/activitystreams#Public"],
                "oneOf": [
                    {"type": "Note", "name": "yes", "replies": {"type": "Collection", "totalItems": 3}},
                    {"type": "Note", "name": "no", "replies": {"type": "Collection", "totalItems": 2}}
                ],
                "endTime": "2030-01-01T00:00:00Z",
                "votersCount": 5
            });

            ingest_note(&state, &author, &question)
                .await
                .expect("ingest question");
            let row = statuses::by_uri(store.pool(), &question_uri)
                .await
                .expect("lookup")
                .expect("stored status");
            let poll = polls::by_status(store.pool(), &row.id)
                .await
                .expect("read poll")
                .expect("question became a poll");
            assert!(!poll.local);
            assert!(!poll.multiple);
            assert_eq!(poll.options.0, vec!["yes".to_owned(), "no".to_owned()]);
            assert_eq!(poll.voters_count, 5);
            let counts = polls::tally_counts(store.pool(), &poll.id)
                .await
                .expect("read tallies");
            assert_eq!(counts.len(), 2);
            assert_eq!((counts[0].option_index, counts[0].votes), (0, 3));
            assert_eq!((counts[1].option_index, counts[1].votes), (1, 2));

            let updated = serde_json::json!({
                "id": question_uri,
                "type": "Question",
                "content": "<p>still which?</p>",
                "to": ["https://www.w3.org/ns/activitystreams#Public"],
                "oneOf": [
                    {"type": "Note", "name": "yes", "replies": {"type": "Collection", "totalItems": 1}},
                    {"type": "Note", "name": "no", "replies": {"type": "Collection", "totalItems": 4}}
                ],
                "endTime": "2030-01-01T00:00:00Z",
                "votersCount": 5
            });
            let activity = Activity::new(
                ActivityKind::Update,
                author.uri.clone().unwrap(),
                updated,
            );
            ingest_activity(&state, &activity)
                .await
                .expect("ingest poll update");

            let counts = polls::tally_counts(store.pool(), &poll.id)
                .await
                .expect("read tallies");
            assert_eq!(counts.len(), 2);
            assert_eq!((counts[0].option_index, counts[0].votes), (0, 1));
            assert_eq!((counts[1].option_index, counts[1].votes), (1, 4));
        })
        .await;
    }

    #[tokio::test]
    async fn an_update_refreshes_a_remote_note_and_stamps_the_edit() {
        with_isolated_state(|store, state| async move {
            let author = seed_remote(&store, "https://remote.test/users/mallory").await;
            let note_uri = format!("https://remote.test/notes/{}", Id::new());
            let original = serde_json::json!({
                "id": note_uri,
                "type": "Note",
                "to": ["https://www.w3.org/ns/activitystreams#Public"],
                "content": "<p>before</p>"
            });
            ingest_note(&state, &author, &original)
                .await
                .expect("ingest note");

            let edited = serde_json::json!({
                "id": note_uri,
                "type": "Note",
                "summary": "cw",
                "sensitive": true,
                "content": "<p>after</p>"
            });
            let activity = Activity::new(ActivityKind::Update, author.uri.clone().unwrap(), edited);
            ingest_activity(&state, &activity)
                .await
                .expect("ingest update");

            let row = statuses::by_uri(store.pool(), &note_uri)
                .await
                .expect("lookup")
                .expect("stored status");
            assert_eq!(row.content, "after");
            assert!(row.content_html.contains("<p>after</p>"));
            assert!(row.sensitive);
            assert_eq!(row.spoiler_text, "cw");
            assert!(row.edited_at.is_some());
            assert_eq!(row.visibility, "public");
        })
        .await;
    }

    #[tokio::test]
    async fn an_update_refreshes_a_remote_profile() {
        with_isolated_state(|store, state| async move {
            let author = seed_remote(&store, "https://remote.test/users/mallory").await;
            let uri = author.uri.clone().unwrap();
            let document = serde_json::json!({
                "id": uri,
                "type": "Person",
                "preferredUsername": "mallory",
                "name": "New Name",
                "summary": "<p>new bio</p>",
                "icon": {"type": "Image", "url": "https://remote.test/avatar.png"},
                "image": {"type": "Image", "url": "https://remote.test/header.png"},
                "inbox": "https://remote.test/users/mallory/inbox"
            });
            let activity = Activity::new(ActivityKind::Update, uri, document);

            ingest_activity(&state, &activity)
                .await
                .expect("ingest update");

            let row = accounts::by_uri(store.pool(), author.uri.as_deref().unwrap())
                .await
                .expect("lookup")
                .expect("stored account");
            assert_eq!(row.display_name, "New Name");
            assert!(row.note.contains("new bio"));
            assert_eq!(
                row.avatar_url.as_deref(),
                Some("https://remote.test/avatar.png")
            );
            assert_eq!(
                row.header_url.as_deref(),
                Some("https://remote.test/header.png")
            );
        })
        .await;
    }

    #[tokio::test]
    async fn deleting_a_remote_actor_soft_deletes_its_statuses_but_keeps_the_account() {
        with_isolated_state(|store, state| async move {
            let author = seed_remote(&store, "https://remote.test/users/mallory").await;
            let uri = author.uri.clone().unwrap();
            let first = format!("https://remote.test/notes/{}", Id::new());
            let second = format!("https://remote.test/notes/{}", Id::new());
            for note_uri in [&first, &second] {
                ingest_note(
                    &state,
                    &author,
                    &serde_json::json!({
                        "id": note_uri,
                        "type": "Note",
                        "content": "<p>gone soon</p>"
                    }),
                )
                .await
                .expect("ingest note");
            }

            let activity = Activity::new(ActivityKind::Delete, uri.clone(), uri.clone());
            ingest_activity(&state, &activity)
                .await
                .expect("ingest delete");

            assert!(statuses::by_uri(store.pool(), &first)
                .await
                .expect("lookup")
                .is_none());
            assert!(statuses::by_uri(store.pool(), &second)
                .await
                .expect("lookup")
                .is_none());
            assert!(accounts::by_uri(store.pool(), &uri)
                .await
                .expect("lookup")
                .is_some());
        })
        .await;
    }

    #[tokio::test]
    async fn deleting_a_remote_note_spares_its_siblings() {
        with_isolated_state(|store, state| async move {
            let author = seed_remote(&store, "https://remote.test/users/mallory").await;
            let gone = format!("https://remote.test/notes/{}", Id::new());
            let kept = format!("https://remote.test/notes/{}", Id::new());
            for note_uri in [&gone, &kept] {
                ingest_note(
                    &state,
                    &author,
                    &serde_json::json!({
                        "id": note_uri,
                        "type": "Note",
                        "content": "<p>x</p>"
                    }),
                )
                .await
                .expect("ingest note");
            }

            let activity = Activity::new(
                ActivityKind::Delete,
                author.uri.clone().unwrap(),
                gone.clone(),
            );
            ingest_activity(&state, &activity)
                .await
                .expect("ingest delete");

            assert!(statuses::by_uri(store.pool(), &gone)
                .await
                .expect("lookup")
                .is_none());
            assert!(statuses::by_uri(store.pool(), &kept)
                .await
                .expect("lookup")
                .is_some());
        })
        .await;
    }

    #[tokio::test]
    async fn an_inbound_block_stops_delivery_to_the_blocking_host() {
        with_isolated_state(|store, state| async move {
            let blocker = seed_remote(&store, "https://blocked.test/users/mallory").await;
            let local = accounts::insert(
                store.pool(),
                &accounts::NewAccount {
                    username: "alice",
                    display_name: "Alice",
                    note: "",
                    bot: false,
                    locked: false,
                },
            )
            .await
            .expect("insert local account");
            let activity = Activity::new(
                ActivityKind::Block,
                blocker.uri.clone().unwrap(),
                "https://social.test/users/alice",
            );

            ingest_activity(&state, &activity)
                .await
                .expect("ingest block");

            let document = serde_json::json!({
                "id": format!("https://social.test/users/alice/statuses/{}", Id::new()),
                "type": "Create",
                "actor": "https://social.test/users/alice",
                "object": {"id": "https://social.test/users/alice/statuses/1"}
            });
            let inboxes = vec![
                "https://blocked.test/users/mallory/inbox".to_owned(),
                "https://open.test/inbox".to_owned(),
            ];
            assert_eq!(
                nodus_server_store::delivery::enqueue(store.pool(), &local.id, &document, &inboxes)
                    .await
                    .expect("enqueue"),
                1
            );
            let pending = nodus_server_store::delivery::pending(store.pool(), 10)
                .await
                .expect("pending");
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].inbox_url, "https://open.test/inbox");
        })
        .await;
    }

    #[tokio::test]
    async fn a_flag_opens_a_federation_report() {
        with_isolated_state(|store, state| async move {
            let reporter = seed_remote(&store, "https://remote.test/users/mallory").await;
            let target = seed_remote(&store, "https://remote.test/users/spammer").await;
            let value = serde_json::json!({
                "id": "https://remote.test/reports/1",
                "type": "Flag",
                "actor": reporter.uri.clone().unwrap(),
                "content": "spam &amp; abuse",
                "object": [target.uri.clone().unwrap()]
            });
            let activity = super::flag_activity(&value).expect("flag parsed");

            ingest_activity(&state, &activity)
                .await
                .expect("ingest flag");
            ingest_activity(&state, &activity)
                .await
                .expect("ingest replayed flag");

            let reports = nodus_server_store::moderation::reports(
                store.pool(),
                &nodus_server_store::moderation::ReportFilter {
                    category: Some("federation"),
                    limit: 10,
                    ..Default::default()
                },
            )
            .await
            .expect("read reports");
            assert_eq!(
                reports.len(),
                1,
                "a replayed flag must not open a second report"
            );
            assert_eq!(reports[0].account_id.as_deref(), Some(reporter.id.as_str()));
            assert_eq!(reports[0].target_account_id, target.id);
            assert_eq!(reports[0].comment, "spam & abuse");
        })
        .await;
    }

    async fn seed_local_poll(
        store: &Store,
        options: &[&str],
        multiple: bool,
        hide_totals: bool,
    ) -> (AccountRow, StatusRow, String) {
        let username = format!("ada_{}", Id::new());
        let account = accounts::insert(
            store.pool(),
            &accounts::NewAccount {
                username: &username,
                display_name: &username,
                note: "",
                bot: false,
                locked: false,
            },
        )
        .await
        .expect("insert local account");
        let status_id = Id::new().to_string();
        let options: Vec<String> = options.iter().map(|option| (*option).to_owned()).collect();
        let poll_id = format!("{status_id}:poll");
        let row = statuses::create_with_poll(
            store.pool(),
            &statuses::NewStatus {
                id: &status_id,
                account_id: &account.id,
                content: "which one",
                content_html: "<p>which one</p>",
                content_source: Some("which one"),
                content_format: "html",
                spoiler_text: "",
                visibility: "public",
                sensitive: false,
                in_reply_to_id: None,
                in_reply_to_account_id: None,
                reblog_of_id: None,
                language: Some("en"),
            },
            &[],
            &[],
            &[],
            Some(&polls::NewPoll {
                id: &poll_id,
                status_id: &status_id,
                options: &options,
                multiple,
                hide_totals,
                expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            }),
        )
        .await
        .expect("insert status and poll");
        (account, row, poll_id)
    }

    #[tokio::test]
    async fn a_single_choice_poll_is_a_question_with_one_of() {
        with_isolated_state(|store, state| async move {
            let (account, row, _) = seed_local_poll(&store, &["tea", "coffee"], false, false).await;
            let activity = status_activity(&state, &row, &account)
                .await
                .expect("build create");
            let value = activity.to_json();
            assert_eq!(value["type"], "Create");
            let object = &value["object"];
            assert_eq!(object["type"], "Question");
            assert!(object.get("oneOf").is_some(), "single uses oneOf");
            assert!(object.get("anyOf").is_none(), "single does not use anyOf");
            assert_eq!(
                object["oneOf"][0],
                json!({
                    "type": "Note",
                    "name": "tea",
                    "replies": {"type": "Collection", "totalItems": 0},
                })
            );
            assert_eq!(object["votersCount"], 0);
            assert!(object["endTime"]
                .as_str()
                .is_some_and(|end| end.ends_with('Z')));
            assert_eq!(
                object["to"],
                json!(["https://www.w3.org/ns/activitystreams#Public"])
            );
            assert_eq!(
                object["cc"],
                json!([format!(
                    "https://social.test/users/{}/followers",
                    account.username
                )])
            );
        })
        .await;
    }

    #[tokio::test]
    async fn a_multiple_choice_poll_uses_any_of_and_updates_carry_tallies() {
        with_isolated_state(|store, state| async move {
            let (account, row, poll) =
                seed_local_poll(&store, &["tea", "coffee"], true, false).await;
            let create = status_activity(&state, &row, &account)
                .await
                .expect("build create");
            let value = create.to_json();
            let object = &value["object"];
            assert!(object.get("anyOf").is_some(), "multiple uses anyOf");
            assert!(object.get("oneOf").is_none(), "multiple does not use oneOf");

            let voter = accounts::insert(
                store.pool(),
                &accounts::NewAccount {
                    username: &format!("voter_{}", Id::new()),
                    display_name: "voter",
                    note: "",
                    bot: false,
                    locked: false,
                },
            )
            .await
            .expect("insert voter");
            assert!(polls::vote(store.pool(), &poll, &voter.id, &[1])
                .await
                .expect("vote"));

            let update = status_update(&state, &row, &account)
                .await
                .expect("build update");
            let value = update.to_json();
            assert_eq!(value["type"], "Update");
            let object = &value["object"];
            assert_eq!(object["anyOf"][1]["replies"]["totalItems"], 1);
            assert_eq!(object["anyOf"][0]["replies"]["totalItems"], 0);
            assert_eq!(object["votersCount"], 1);
        })
        .await;
    }

    #[tokio::test]
    async fn an_echoed_question_cannot_take_over_a_local_poll() {
        with_isolated_state(|store, state| async move {
            let (_account, row, _) = seed_local_poll(&store, &["tea", "coffee"], false, false).await;
            let remote = seed_remote(&store, "https://remote.test/users/mallory").await;
            let echoed = json!({
                "id": status_url(&state, &row),
                "type": "Question",
                "attributedTo": "https://remote.test/users/mallory",
                "content": "<p>stolen</p>",
                "published": "2026-01-01T00:00:00Z",
                "oneOf": [
                    {"type": "Note", "name": "stolen", "replies": {"type": "Collection", "totalItems": 9}},
                    {"type": "Note", "name": "also stolen", "replies": {"type": "Collection", "totalItems": 1}},
                ],
            });
            assert!(
                ingest_note(&state, &remote, &echoed).await.is_err(),
                "a remote account cannot own a local status URI"
            );

            let poll = polls::by_status(store.pool(), &row.id)
                .await
                .expect("read poll")
                .expect("poll remains");
            assert!(poll.local, "the poll is still local");
            assert_eq!(poll.options.0, vec!["tea", "coffee"]);
            let status = statuses::by_id(store.pool(), &row.id)
                .await
                .expect("read status")
                .expect("status remains");
            assert_eq!(status.content, "which one");
        })
        .await;
    }
}
