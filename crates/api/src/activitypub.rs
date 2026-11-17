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
    let activity =
        Activity::from_json(&value).map_err(|error| ApiError::unprocessable(error.to_string()))?;

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
                follow_local(state, &remote, target).await?;
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
        ActivityKind::Create => {
            if let ActivityObject::Value(value) = &activity.object {
                ingest_note(state, &remote, value).await?;
            }
        }
        ActivityKind::Delete => {
            if let Some(id) = delete_target_id(activity) {
                if validate_remote_url(id).is_err() || !same_origin(id, &activity.actor) {
                    return Err(ApiError::forbidden(
                        "cannot delete object from another origin",
                    ));
                }
                statuses::delete_remote(state.store().pool(), id, &remote.id).await?;
            }
        }
        _ => {}
    }
    Ok(())
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

fn is_disallowed_ipv4(v4: Ipv4Addr) -> bool {
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

fn is_disallowed_ipv6(v6: Ipv6Addr) -> bool {
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
            avatar: actor.avatar.as_deref(),
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

async fn follow_local(state: &AppState, remote: &AccountRow, target: &str) -> ApiResult<()> {
    let Some(local) = local_target(state, target).await? else {
        return Ok(());
    };
    nodus_server_store::social::follow(state.store().pool(), &remote.id, &local.id, true, false)
        .await?;
    nodus_server_store::social::notify(state.store().pool(), &local.id, "follow", &remote.id, None)
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
    statuses::upsert_remote(
        state.store().pool(),
        &statuses::NewRemoteStatus {
            id: &nodus_server_core::Id::new().to_string(),
            account_id: &remote.id,
            uri: &note.id,
            content: &content,
            content_html: &content_html,
            spoiler_text: &spoiler_text,
            sensitive: note.sensitive,
            in_reply_to_id: parent.as_ref().map(|row| row.id.as_str()),
            in_reply_to_account_id: parent.as_ref().map(|row| row.account_id.as_str()),
            created_at,
        },
    )
    .await?;
    Ok(())
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

async fn status_activity(
    state: &AppState,
    row: &StatusRow,
    account: &AccountRow,
) -> ApiResult<Activity> {
    let note = note_document(state, row, account).await?;
    Ok(Activity::create(actor_url(state, account), &note))
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
    let (to, cc) = match row.visibility.as_str() {
        "public" => (
            vec![String::from("https://www.w3.org/ns/activitystreams#Public")],
            vec![format!("{actor}/followers")],
        ),
        "unlisted" => (
            vec![format!("{actor}/followers")],
            vec![String::from("https://www.w3.org/ns/activitystreams#Public")],
        ),
        _ => return Err(ApiError::not_found("Record not found")),
    };
    let media = nodus_server_store::media::by_status(state.store().pool(), &row.id).await?;
    let attachments = media
        .iter()
        .map(|media| Attachment {
            kind: if media.content_type.starts_with("video/") {
                "Video".to_owned()
            } else if media.content_type.starts_with("image/") {
                "Image".to_owned()
            } else {
                "Document".to_owned()
            },
            url: state.instance().url(&format!("/media/{}", media.id)),
            preview_url: Some(state.instance().url(&format!("/media/{}", media.id))),
            description: (!media.description.is_empty()).then(|| media.description.clone()),
            width: media.width.and_then(|value| u32::try_from(value).ok()),
            height: media.height.and_then(|value| u32::try_from(value).ok()),
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
        mentions: Vec::new(),
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

fn actor_url(state: &AppState, account: &AccountRow) -> String {
    account.uri.clone().unwrap_or_else(|| {
        state
            .instance()
            .url(&format!("/users/{}", account.username))
    })
}

fn status_url(state: &AppState, row: &StatusRow) -> String {
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
                    avatar: None,
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
}
