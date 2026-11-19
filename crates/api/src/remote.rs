//! Finding a remote account from a handle or a link.
//!
//! A reader who pastes `@alice@remote.test` into search expects the instance to go and
//! look. That is one WebFinger request and one actor fetch, done only when the client
//! explicitly asks with `resolve=true`, and cached in `account` afterwards so the second
//! lookup is a row read.
//!
//! Both requests are made by [`client_for`], which resolves the host itself and then
//! pins the connection to the address it checked. Checking a name and then letting the
//! system resolve it again would leave a rebinding window; connecting to the address we
//! validated closes it.

use std::net::IpAddr;
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::Value;

use crate::activitypub::{is_disallowed_ipv4, is_disallowed_ipv6};
use crate::error::{ApiError, ApiResult};

const USER_AGENT: &str = concat!("nodus/", env!("CARGO_PKG_VERSION"));
const TIMEOUT: Duration = Duration::from_secs(8);
/// Actor types we accept. A `Group` is a group account; `Application` is a bot.
const ACTOR_KINDS: [&str; 5] = ["Person", "Application", "Service", "Group", "Organization"];

/// One of our own actors, used to sign outgoing reads.
#[derive(Debug, Clone)]
pub struct Signer {
    key_id: String,
    private_key_pem: String,
}

impl Signer {
    /// Builds the `#main-key` id the way our own actor document publishes it: the stored
    /// actor `uri` when the account has one, otherwise the path this instance serves.
    #[must_use]
    pub fn new(
        instance: &crate::state::InstanceConfig,
        username: &str,
        uri: Option<&str>,
        private_key_pem: &str,
    ) -> Self {
        let actor = uri.map_or_else(
            || {
                format!(
                    "{}/users/{username}",
                    instance.base_url.trim_end_matches('/')
                )
            },
            str::to_owned,
        );
        Self {
            key_id: format!("{actor}#main-key"),
            private_key_pem: private_key_pem.to_owned(),
        }
    }
}

fn federation_sign(
    signer: &Signer,
    method: &str,
    path: &str,
    host: &str,
) -> Option<nodus_server_federation::SignedHeaders> {
    nodus_server_federation::sign(
        method,
        path,
        host,
        chrono::Utc::now(),
        b"",
        &signer.key_id,
        &signer.private_key_pem,
    )
    .map_err(|error| tracing::warn!(%error, "signing failed"))
    .ok()
}

/// A remote account, ready to be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteActor {
    pub uri: String,
    pub username: String,
    pub domain: String,
    pub display_name: String,
    pub note: String,
    pub avatar_url: Option<String>,
    pub header_url: Option<String>,
    pub inbox_url: Option<String>,
    pub shared_inbox_url: Option<String>,
    pub public_key_pem: Option<String>,
    pub locked: bool,
    pub bot: bool,
}

/// What a reader actually typed: a handle or a link to a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Handle { user: String, host: String },
    Link { url: String, host: String },
}

/// Reads a handle (`@user@host`, `user@host`) or a profile link (`https://host/@user`).
#[must_use]
pub fn parse_target(raw: &str) -> Option<Target> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains("://") {
        let url = url::Url::parse(trimmed).ok()?;
        if url.scheme() != "https" {
            return None;
        }
        let host = url.host_str()?.to_ascii_lowercase();
        if !valid_host(&host) {
            return None;
        }
        return Some(Target::Link {
            url: url.to_string(),
            host,
        });
    }
    let without_prefix = trimmed.trim_start_matches('@');
    let (user, host) = without_prefix.rsplit_once('@')?;
    let host = host.to_ascii_lowercase();
    if !valid_user(user) || !valid_host(&host) {
        return None;
    }
    Some(Target::Handle {
        user: user.to_owned(),
        host,
    })
}

/// A host we are willing to connect to: a name, never an address literal.
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.contains('.')
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host.parse::<IpAddr>().is_err()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn valid_user(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 64
        && user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// Hosts the operator has vouched for, which may resolve to a private address.
///
/// The guard below exists so a stranger cannot point us at `127.0.0.1` or the LAN. An
/// operator running several instances on one network is not a stranger: on a Proxmox host
/// `/etc/hosts` pins every service name to the bridge address, so `mastodon.example`
/// resolves to `10.0.1.x` from inside the container and a strict guard makes the whole
/// federation path unreachable. `NODUS_ALLOW_PRIVATE_HOSTS` names those hosts explicitly
/// (comma separated); nothing is trusted that is not named.
fn trusted_private_hosts() -> &'static [String] {
    static HOSTS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    HOSTS.get_or_init(|| {
        std::env::var("NODUS_ALLOW_PRIVATE_HOSTS")
            .unwrap_or_default()
            .split(',')
            .map(|host| {
                host.trim()
                    .trim_start_matches("https://")
                    .trim_end_matches('/')
            })
            .filter(|host| !host.is_empty())
            .map(str::to_ascii_lowercase)
            .collect()
    })
}

/// Anything about the target itself that cannot succeed, without touching the network.
async fn client_for(host: &str) -> ApiResult<reqwest::Client> {
    client_for_with(host, TIMEOUT).await
}

/// The same guard, with a budget of the caller's choosing.
///
/// A peer block list is a download, not a probe: the default eight seconds is right for
/// asking an actor's inbox to accept a delivery, and too little to read a few thousand
/// lines from a list host over a slow link. The address check is identical either way —
/// only how long we are willing to wait for the body changes.
async fn client_for_with(host: &str, timeout: Duration) -> ApiResult<reqwest::Client> {
    let addrs: Vec<_> = tokio::net::lookup_host((host, 443))
        .await
        .map_err(|_| unreachable(host))?
        .collect();
    let trusted = trusted_private_hosts()
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(host));
    let address = addrs
        .iter()
        .find(|addr| {
            trusted
                || match addr.ip() {
                    IpAddr::V4(v4) => !is_disallowed_ipv4(v4),
                    IpAddr::V6(v6) => !is_disallowed_ipv6(v6),
                }
        })
        .copied()
        .ok_or_else(|| unreachable(host))?;
    reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::none())
        .resolve(host, address)
        .build()
        .map_err(|error| {
            tracing::warn!(%host, %error, "could not build the outbound client");
            unavailable()
        })
}

/// The client for an `https` URL an administrator supplied, built by the same guard.
///
/// The scheme check lives here rather than in the handler because it is the same decision
/// either way: what this instance is willing to talk to. `client_for_with` then resolves the
/// host once, refuses a private answer, and pins the connection to the address it checked,
/// so a host that answers differently on the second lookup gains nothing.
pub(crate) async fn outbound_client(url: &str, timeout: Duration) -> ApiResult<reqwest::Client> {
    let parsed =
        url::Url::parse(url).map_err(|_| ApiError::unprocessable("that URL is not a URL"))?;
    if parsed.scheme() != "https" {
        return Err(ApiError::unprocessable("only https URLs can be fetched"));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| ApiError::unprocessable("that URL has no host"))?
        .to_ascii_lowercase();
    client_for_with(&host, timeout).await
}

fn unreachable(host: &str) -> ApiError {
    tracing::debug!(%host, "refused to reach a remote host");
    ApiError::unprocessable("That account's instance is not reachable from here.")
}

fn unavailable() -> ApiError {
    ApiError::new(StatusCode::BAD_GATEWAY, "That instance did not answer.")
}

/// The largest media file the content-set check will pull into memory.
///
/// The bytes are hashed and dropped, so this is a work budget rather than storage: eight
/// megabytes covers a photo at any sane size and refuses a video that would spend the whole
/// ingest window on a check nobody asked for.
const MEDIA_FETCH_MAX: usize = 8 * 1024 * 1024;

/// A media host that has not answered in this long is not going to answer usefully.
const MEDIA_FETCH_TIMEOUT: Duration = Duration::from_secs(4);

/// Reads a remote attachment, so the content-set check can hash it.
///
/// The same client as every other outbound read: the host is resolved here, checked against
/// the private-address guard, and the connection pinned to the address that was checked.
/// Only `https`, only names (`client_for` refuses an address literal), and no redirects —
/// the target of a redirect was never checked. Every failure is `None`, because a media
/// host that is down is not a reason to refuse a post; it only means we cannot look.
pub(crate) async fn fetch_media_bytes(url: &str) -> Option<Vec<u8>> {
    let parsed = url::Url::parse(url).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    let host = parsed.host_str()?.to_ascii_lowercase();
    let client = match client_for(&host).await {
        Ok(client) => client,
        Err(error) => {
            tracing::debug!(%host, message = error.message(), "refused a media fetch");
            return None;
        }
    };
    let request = client
        .get(url)
        .header(reqwest::header::ACCEPT, "image/*, video/*, */*;q=0.1");
    let mut response = match tokio::time::timeout(MEDIA_FETCH_TIMEOUT, request.send()).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            tracing::debug!(%url, %error, "media fetch failed");
            return None;
        }
        Err(_) => {
            tracing::debug!(%url, "media fetch timed out");
            return None;
        }
    };
    if !response.status().is_success() {
        tracing::debug!(%url, status = %response.status(), "media host refused the read");
        return None;
    }
    if response.content_length().unwrap_or(0) > MEDIA_FETCH_MAX as u64 {
        tracing::debug!(%url, "media is larger than the check will read");
        return None;
    }
    let mut bytes: Vec<u8> = Vec::new();
    loop {
        let chunk = match tokio::time::timeout(MEDIA_FETCH_TIMEOUT, response.chunk()).await {
            Ok(Ok(Some(chunk))) => chunk,
            Ok(Ok(None)) => break,
            Ok(Err(error)) => {
                tracing::debug!(%url, %error, "media read failed midway");
                return None;
            }
            Err(_) => {
                tracing::debug!(%url, "media read timed out midway");
                return None;
            }
        };
        if bytes.len() + chunk.len() > MEDIA_FETCH_MAX {
            tracing::debug!(%url, "media grew past the size the check will read");
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    Some(bytes)
}

/// Finds the actor document for `@user@host` through WebFinger.
async fn webfinger(user: &str, host: &str, signer: Option<&Signer>) -> ApiResult<String> {
    let resource = url::form_urlencoded::byte_serialize(format!("acct:{user}@{host}").as_bytes())
        .collect::<String>();
    let url = format!("https://{host}/.well-known/webfinger?resource={resource}");
    let body = get(&url, host, "application/jrd+json, application/json", signer).await?;
    let href = body
        .get("links")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|link| {
            link.get("rel").and_then(Value::as_str) == Some("self")
                && link
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| kind.contains("activity+json") || kind.contains("ld+json"))
        })
        .and_then(|link| link.get("href"))
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::not_found("That account was not found on its instance."))?;
    if !href.starts_with("https://") {
        return Err(ApiError::unprocessable(
            "That instance pointed at a link we will not follow.",
        ));
    }
    Ok(href.to_owned())
}

/// Fetches an actor document. `expected` is the host the reader named: a document that
/// claims to live somewhere else is not the account they asked about.
async fn actor_document(url: &str, expected: &str, signer: Option<&Signer>) -> ApiResult<Value> {
    let parsed = url::Url::parse(url)
        .map_err(|_| ApiError::unprocessable("That is not a link to an account."))?;
    if parsed.scheme() != "https" || parsed.host_str() != Some(expected) {
        return Err(ApiError::unprocessable(
            "That link does not belong to the account's instance.",
        ));
    }
    get(
        url,
        expected,
        "application/activity+json, application/ld+json",
        signer,
    )
    .await
}

async fn get(url: &str, host: &str, accept: &str, signer: Option<&Signer>) -> ApiResult<Value> {
    let client = client_for(host).await?;
    let mut request = client.get(url).header(reqwest::header::ACCEPT, accept);
    if let Some(signer) = signer {
        let path = match url::Url::parse(url) {
            Ok(parsed) => parsed.query().map_or_else(
                || parsed.path().to_owned(),
                |query| format!("{}?{query}", parsed.path()),
            ),
            Err(_) => "/".to_owned(),
        };
        if let Some(headers) = federation_sign(signer, "GET", &path, host) {
            for (name, value) in headers.pairs() {
                request = request.header(name, value);
            }
        } else {
            tracing::warn!(%host, "could not sign the outgoing request");
        }
    }
    let response = request.send().await.map_err(|error| {
        tracing::debug!(%url, %error, "remote fetch failed");
        unavailable()
    })?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(ApiError::not_found(
            "That account was not found on its instance.",
        ));
    }
    if !response.status().is_success() {
        return Err(unavailable());
    }
    response.json::<Value>().await.map_err(|error| {
        tracing::debug!(%url, %error, "remote answer was not JSON");
        unavailable()
    })
}

/// Resolves a handle or profile link into an account we can store.
pub async fn resolve(term: &str, signer: Option<&Signer>) -> ApiResult<RemoteActor> {
    let target = parse_target(term)
        .ok_or_else(|| ApiError::unprocessable("That is not a handle or a link to an account."))?;
    let (document_url, user, host) = match target {
        Target::Handle { user, host } => (webfinger(&user, &host, signer).await?, user, host),
        Target::Link { url, host } => (url, String::new(), host),
    };
    let document = actor_document(&document_url, &host, signer).await?;
    actor_from_document(&document, &user, &host)
}

/// Reads the fields we keep out of an actor document.
pub fn actor_from_document(
    document: &Value,
    fallback_user: &str,
    host: &str,
) -> ApiResult<RemoteActor> {
    let kind = document
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(not_an_actor)?;
    if !ACTOR_KINDS.contains(&kind) {
        return Err(not_an_actor());
    }
    let uri = document
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| id.starts_with("https://"))
        .ok_or_else(not_an_actor)?
        .to_owned();
    let username = document
        .get("preferredUsername")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .unwrap_or(fallback_user);
    if username.is_empty() {
        return Err(not_an_actor());
    }
    let display_name = crate::html::escape_text(
        document
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    );
    let note = crate::html::sanitize_html(
        document
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    );
    let picture = |field: &str| {
        document
            .get(field)
            .and_then(|image| match image {
                Value::String(url) => Some(url.clone()),
                other => other.get("url").and_then(Value::as_str).map(str::to_owned),
            })
            .filter(|url| url.starts_with("https://"))
    };
    let endpoints = document.get("endpoints");
    Ok(RemoteActor {
        uri,
        username: username.to_owned(),
        domain: host.to_owned(),
        display_name,
        note,
        avatar_url: picture("icon"),
        header_url: picture("image"),
        inbox_url: document
            .get("inbox")
            .and_then(Value::as_str)
            .map(str::to_owned),
        shared_inbox_url: endpoints
            .and_then(|value| value.get("sharedInbox"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        public_key_pem: document
            .get("publicKey")
            .and_then(|key| key.get("publicKeyPem"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        locked: document
            .get("manuallyApprovesFollowers")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        bot: matches!(kind, "Application" | "Service"),
    })
}

fn not_an_actor() -> ApiError {
    ApiError::unprocessable("That instance did not describe an account.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_and_links_are_recognised() {
        assert_eq!(
            parse_target("@alice@remote.test"),
            Some(Target::Handle {
                user: "alice".to_owned(),
                host: "remote.test".to_owned()
            })
        );
        assert_eq!(
            parse_target(" alice@Remote.Test "),
            Some(Target::Handle {
                user: "alice".to_owned(),
                host: "remote.test".to_owned()
            })
        );
        assert_eq!(
            parse_target("https://baraag.net/@Tomostrawberry"),
            Some(Target::Link {
                url: "https://baraag.net/@Tomostrawberry".to_owned(),
                host: "baraag.net".to_owned()
            })
        );
    }

    #[test]
    fn nonsense_and_private_targets_are_refused() {
        for raw in [
            "",
            "alice",
            "@alice",
            "alice@localhost",
            "alice@127.0.0.1",
            "alice@[::1]",
            "alice@remote.test/@bob",
            "http://remote.test/@alice",
            "javascript:alert(1)",
            "https://127.0.0.1/@alice",
            "https://remote.test./@alice",
            "bob@-remote.test",
            "b ob@remote.test",
        ] {
            assert!(parse_target(raw).is_none(), "{raw} should not parse");
        }
    }

    #[test]
    fn an_actor_document_becomes_a_remote_account() {
        let document = serde_json::json!({
            "id": "https://remote.test/users/alice",
            "type": "Person",
            "preferredUsername": "alice",
            "name": "<b>Alice</b>",
            "summary": "<p>Hi <script>alert(1)</script></p>",
            "icon": { "type": "Image", "url": "https://remote.test/alice.png" },
            "image": "https://remote.test/alice-header.png",
            "inbox": "https://remote.test/users/alice/inbox",
            "endpoints": { "sharedInbox": "https://remote.test/inbox" },
            "publicKey": { "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n" },
            "manuallyApprovesFollowers": true
        });
        let actor = actor_from_document(&document, "alice", "remote.test").expect("actor");
        assert_eq!(actor.uri, "https://remote.test/users/alice");
        assert_eq!(actor.username, "alice");
        assert_eq!(actor.domain, "remote.test");
        assert_eq!(actor.display_name, "&lt;b&gt;Alice&lt;/b&gt;");
        assert!(!actor.note.contains("<script"));
        assert_eq!(
            actor.avatar_url.as_deref(),
            Some("https://remote.test/alice.png")
        );
        assert_eq!(
            actor.header_url.as_deref(),
            Some("https://remote.test/alice-header.png")
        );
        assert_eq!(
            actor.shared_inbox_url.as_deref(),
            Some("https://remote.test/inbox")
        );
        assert!(actor.locked);
        assert!(!actor.bot);
    }

    #[test]
    fn a_document_that_is_not_an_account_is_refused() {
        let page = serde_json::json!({ "id": "https://remote.test/notes/1", "type": "Note" });
        assert!(actor_from_document(&page, "alice", "remote.test").is_err());
        let anonymous = serde_json::json!({ "type": "Person" });
        assert!(actor_from_document(&anonymous, "alice", "remote.test").is_err());
        let plain = serde_json::json!({ "id": "http://remote.test/users/a", "type": "Person" });
        assert!(actor_from_document(&plain, "alice", "remote.test").is_err());
    }
}
