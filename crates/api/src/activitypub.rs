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
use serde_json::{Map, Value};

use nodus_server_core::PageParams;
use nodus_server_federation::{prepare, verify_prepared};
use nodus_server_sdk::activitypub::ActivityPub;
use nodus_server_sdk::activitypub::{
    Activity, ActivityKind, ActivityObject, Actor, Attachment, Collection, CollectionPage, Note,
    Webfinger,
};
use nodus_server_store::accounts::{self, AccountRow};
use nodus_server_store::media;
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

/// Builds the routes an ActivityPub peer calls. They live at the domain root, not under
/// `/api`, because a peer discovers them from WebFinger and the actor document.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/.well-known/webfinger", get(webfinger))
        .route("/inbox", post(shared_inbox))
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
    Ok(document_response(
        &note_document(&state, &row, &account).await?,
    ))
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
    let actor = ActivityPub::new()
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
        Some("Note") => {
            let note = Note::from_json(value)
                .map_err(|error| ApiError::unprocessable(error.to_string()))?;
            update_remote_note(state, remote, activity, &note).await
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
    store_note_extras(state, remote, note, &row).await
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
    }
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
            account_id: &remote.id,
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
    let actor = ActivityPub::new()
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
    Ok(accounts::upsert_remote(
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
    .await?)
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
    store_note_extras(state, remote, &note, &row).await
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
/// its hashtags and its media.
async fn store_note_extras(
    state: &AppState,
    remote: &AccountRow,
    note: &Note,
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
    media::replace_remote(
        pool,
        &row.id,
        &remote.id,
        note.sensitive,
        &remote_attachments(note),
    )
    .await?;
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

fn remote_attachments(note: &Note) -> Vec<media::RemoteAttachment<'_>> {
    note.attachments
        .iter()
        .filter(|attachment| validate_remote_url(&attachment.url).is_ok())
        .filter_map(|attachment| {
            let content_type = match attachment.kind.as_str() {
                "Image" => "image/jpeg",
                "Video" => "video/mp4",
                "Audio" => "audio/mpeg",
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
    let note = note_document(state, row, account).await?;
    Ok(Activity::create(actor_url(state, account), &note))
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
async fn ensure_identity(state: &AppState, account: AccountRow) -> ApiResult<AccountRow> {
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
            assert_eq!(reports[0].account_id, reporter.id);
            assert_eq!(reports[0].target_account_id, target.id);
            assert_eq!(reports[0].comment, "spam & abuse");
        })
        .await;
    }
}
