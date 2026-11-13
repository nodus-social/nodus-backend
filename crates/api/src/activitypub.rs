//! The server side of ActivityPub: actors, notes, collections, WebFinger and inbox.
//!
//! Handlers build the same `nodus-activitypub-sdk` documents a reader parses, so a
//! server response and a remote parse cannot drift into two shapes. Storage and
//! policy stay in `nodus-server-store`; this module only maps rows to protocol
//! documents and protocol requests to store calls.

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
use nodus_server_sdk::activitypub::ActivityPub;
use nodus_server_sdk::activitypub::{
    Activity, ActivityKind, ActivityObject, Actor, Attachment, Collection, CollectionPage, Note,
    Webfinger,
};
use nodus_server_sdk::federation::signature::crypto::{body_digest, RsaVerifier};
use nodus_server_sdk::federation::signature::{HttpSignature, Verifier};
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

    let page = statuses::account_page(
        state.store().pool(),
        &account.id,
        PageParams::new().with_limit(Some(20)),
    )
    .await?;
    let mut items = Vec::with_capacity(page.items.len());
    for row in &page.items {
        items.push(status_activity(&state, row, &account).await?.to_json());
    }
    let next = page
        .next_max_id
        .map(|id| format!("{collection_url}?page=true&max_id={id}"));
    Ok(document_response(&OutboxPage {
        value: CollectionPage {
            items,
            next,
            total_items: u64::try_from(account.statuses_count).unwrap_or_default(),
        }
        .to_json(&format!("{collection_url}?page=true"), &collection_url),
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
    verify_signature(state, headers, uri, body).await?;
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| ApiError::unprocessable("The activity is not JSON"))?;
    let activity =
        Activity::from_json(&value).map_err(|error| ApiError::unprocessable(error.to_string()))?;
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
) -> ApiResult<()> {
    let raw = headers
        .get("signature")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("Missing HTTP signature"))?;
    let signature =
        HttpSignature::parse(raw).map_err(|error| ApiError::unauthorized(error.to_string()))?;
    if let Some(digest) = headers.get("digest").and_then(|value| value.to_str().ok()) {
        if digest != body_digest(body) {
            return Err(ApiError::unauthorized("Body digest does not match"));
        }
    }
    if let Some(date) = headers.get("date").and_then(|value| value.to_str().ok()) {
        let parsed = chrono::DateTime::parse_from_rfc2822(date)
            .map_err(|_| ApiError::unauthorized("Invalid Date header"))?;
        if (chrono::Utc::now() - parsed.with_timezone(&chrono::Utc))
            .num_minutes()
            .abs()
            > 5
        {
            return Err(ApiError::unauthorized("Signature is stale"));
        }
    }
    let key_actor = signature
        .key_id
        .split('#')
        .next()
        .unwrap_or(&signature.key_id);
    let actor = ActivityPub::new()
        .actor_url(key_actor)
        .await
        .map_err(|error| ApiError::unauthorized(error.to_string()))?;
    let pem = actor
        .public_key_pem
        .ok_or_else(|| ApiError::unauthorized("Actor has no public key"))?;
    let signing = signature
        .signing_string(|name| {
            if name == "(request-target)" {
                Some(format!("post {}", uri.path()))
            } else {
                headers
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            }
        })
        .map_err(|error| ApiError::unauthorized(error.to_string()))?;
    RsaVerifier::from_public_key_pem(&pem)
        .and_then(|verifier| {
            verifier.verify(
                &signature.key_id,
                &signature.algorithm,
                signing.as_bytes(),
                &signature.signature,
            )
        })
        .map_err(|error| ApiError::unauthorized(error.to_string()))?;
    let _ = state;
    Ok(())
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
            if let Some(id) = activity_target_id(activity) {
                statuses::delete_remote(state.store().pool(), id).await?;
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

pub(crate) async fn ensure_remote_actor(
    state: &AppState,
    actor_url: &str,
) -> ApiResult<AccountRow> {
    let domain = url::Url::parse(actor_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_default();
    if domain.is_empty()
        || nodus_server_store::moderation::blocked_domain(state.store().pool(), &domain)
            .await?
            .is_some()
    {
        return Err(ApiError::forbidden("domain is blocked"));
    }
    if let Some(row) = accounts::by_uri(state.store().pool(), actor_url).await? {
        return Ok(row);
    }
    let actor = ActivityPub::new()
        .actor_url(actor_url)
        .await
        .map_err(|error| ApiError::unprocessable(error.to_string()))?;
    let host = domain;
    Ok(accounts::upsert_remote(
        state.store().pool(),
        &accounts::RemoteAccount {
            uri: actor_url,
            username: &actor.username,
            domain: &host,
            display_name: &actor.name,
            note: &actor.summary,
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
    let parent = match &note.in_reply_to {
        Some(uri) => statuses::by_uri(state.store().pool(), uri).await?,
        None => None,
    };
    let created_at = chrono::DateTime::parse_from_rfc3339(&note.published).map_or_else(
        |_| chrono::Utc::now(),
        |date| date.with_timezone(&chrono::Utc),
    );
    statuses::upsert_remote(
        state.store().pool(),
        &statuses::NewRemoteStatus {
            id: &nodus_server_core::Id::new().to_string(),
            account_id: &remote.id,
            uri: &note.id,
            content: &html_to_text(&note.content),
            content_html: &note.content,
            spoiler_text: &note.summary,
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
