//! Secure mode: who is allowed to read an ActivityPub document.
//!
//! Off by default (`NODUS_AUTHORIZED_FETCH`), and off is exactly the behaviour every
//! previous release had. On, a read of an ActivityPub surface has to be signed by the
//! instance that asks, which is what stops a hostile instance from scraping every post
//! on this one by pretending to be a browser — the setting Mastodon calls
//! `AUTHORIZED_FETCH`.
//!
//! The pieces are all existing ones: `nodus_server_federation` parses the header and
//! verifies RSA, and the signing client already used for outbound reads supplies the
//! identities. Nothing new is signed or hashed here.

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use nodus_server_federation::{
    parse_header, signing_string, verify_digest, verify_prepared, PreparedRequest,
};

use crate::activitypub::{ensure_domain_allowed, validate_remote_url};
use crate::error::ApiError;
use crate::state::AppState;
use nodus_server_store::accounts;

/// How far a signed `Date` may be from now, in seconds.
///
/// One hour, because an ActivityPub read is cheap and re-signing is cheaper: a replay
/// window wider than this buys a replayer a signed request long after it was captured.
const MAX_DATE_SKEW_SECONDS: i64 = 3600;

/// Media types that ask for an ActivityPub representation of a resource.
const ACTIVITY_JSON_TYPES: [&str; 2] = ["application/activity+json", "application/ld+json"];

/// The middleware the root router installs. A no-op unless the switch is on, the
/// request is a read, and the request targets an ActivityPub surface.
pub async fn require_signature(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if !state.authorized_fetch() || !needs_signature(&request) {
        return next.run(request).await;
    }

    // A session of this instance is not a scrape. The browser and the app carry a
    // bearer token we issued, so they are asked for identity the way every other route
    // asks for it; requiring an HTTP signature from them would lock our own users out
    // of their own instance. This is the whole reason secure mode is safe to turn on:
    // it narrows anonymous reads to signed peers, it does not narrow authenticated
    // reads to anybody.
    if is_local_session(&state, request.headers()).await {
        return next.run(request).await;
    }

    // Owned copies, not borrows of the request: the verification future has to be
    // `Send` for the layer, and the body type is not shared across threads.
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let target = request
        .uri()
        .path_and_query()
        .map_or_else(|| path.clone(), |pq| pq.as_str().to_owned());
    let mut headers = Vec::with_capacity(request.headers().len());
    for (name, value) in request.headers() {
        let Ok(value) = value.to_str() else {
            return ApiError::unauthorized("a request header is not text").into_response();
        };
        headers.push((name.as_str().to_owned(), value.to_owned()));
    }

    if let Err(error) = verify(&state, &method, &target, &headers).await {
        tracing::info!(
            %method,
            %path,
            reason = %error.message(),
            "refused an unsigned secure-mode read"
        );
        return error.into_response();
    }
    next.run(request).await
}

/// Whether this request has to prove who it is with the switch on.
///
/// Reads only: inbox delivery is a POST that already requires a signature and keeps its
/// own path. WebFinger stays public because it is discovery, not content, and a peer
/// cannot sign a lookup it does not yet know the key for.
fn needs_signature(request: &Request) -> bool {
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        return false;
    }
    let path = request.uri().path();
    // Discovery stays public in both spellings: WebFinger because a peer cannot sign a
    // lookup it does not yet know the key for, and NodeInfo because a directory reads it
    // before it has any relationship with this instance. Neither is content.
    if path.starts_with("/.well-known/")
        || path.starts_with("/nodeinfo/")
        || path.starts_with("/api/")
        || path.starts_with("/media/")
    {
        return false;
    }
    if path == "/actor"
        || path.starts_with("/users/")
        || path.starts_with("/objects/")
        || path.starts_with("/statuses/")
    {
        return true;
    }
    wants_activity_json(request.headers())
}

fn wants_activity_json(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value.split(',').any(|part| {
                let media = part.split(';').next().unwrap_or_default().trim();
                ACTIVITY_JSON_TYPES
                    .iter()
                    .any(|activity| media.eq_ignore_ascii_case(activity))
            })
        })
}

/// True when the request carries a bearer token this instance issued and that resolves.
///
/// Any failure (no header, malformed, unknown, revoked) is `false`: this is a bypass for
/// our own sessions, not an authentication error to report.
async fn is_local_session(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(raw) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Some(token) = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .filter(|token| !token.is_empty())
    else {
        return false;
    };
    let digest = crate::auth::token_digest(token);
    matches!(
        accounts::verify_token(state.store().pool(), &digest).await,
        Ok(Some(_))
    )
}

/// Parses the `Signature` header, the date window and the digest, resolves the signer's
/// key, and verifies the signature over exactly the headers it names.
///
/// `headers` is the request's header pairs in wire order; `method` and `target` (path
/// and query) are what `(request-target)` covers.
async fn verify(
    state: &AppState,
    method: &Method,
    target: &str,
    headers: &[(String, String)],
) -> Result<(), ApiError> {
    let raw = single(headers, "signature")?.ok_or_else(|| ApiError::unauthorized(UNSIGNED))?;
    let params = parse_header(&raw).map_err(|error| ApiError::unauthorized(error.to_string()))?;
    if params.algorithm != "rsa-sha256" {
        return Err(ApiError::unauthorized(format!(
            "signed fetch requires rsa-sha256, not {}",
            params.algorithm
        )));
    }
    let signed_headers: Vec<&str> = params.headers.iter().map(String::as_str).collect();
    for required in ["(request-target)", "date"] {
        if !signed_headers.contains(&required) {
            return Err(ApiError::unauthorized(format!(
                "the signature must cover {required}"
            )));
        }
    }

    let date = single(headers, "date")?
        .ok_or_else(|| ApiError::unauthorized("signed fetch requires a Date header"))?;
    let signed_at = chrono::DateTime::parse_from_rfc2822(&date)
        .map_err(|_| ApiError::unauthorized("the Date header is not RFC 2822"))?
        .with_timezone(&Utc);
    if (Utc::now() - signed_at).num_seconds().abs() > MAX_DATE_SKEW_SECONDS {
        return Err(ApiError::unauthorized(
            "the signed Date is more than an hour from now",
        ));
    }

    // Read surfaces carry no body, so the only body a signature can cover here is the
    // empty one; a Digest header that disagrees means the signature was made for a
    // different payload.
    if let Some(digest) = single(headers, "digest")? {
        verify_digest(b"", &digest)
            .map_err(|error| ApiError::unauthorized(format!("digest mismatch: {error}")))?;
    }

    let (actor, key_id) = key_actor(&params.key_id)?;
    ensure_signer_allowed(state, &actor).await?;
    let pem = key_for(state, &actor, key_id).await?;

    let signing = signing_string(&params, method.as_str(), target, |name| {
        single(headers, name).ok().flatten()
    })
    .map_err(|error| ApiError::unauthorized(error.to_string()))?;
    verify_prepared(
        &PreparedRequest {
            params,
            signing_string: signing,
        },
        &pem,
    )
    .map_err(|error| ApiError::unauthorized(format!("signature does not verify: {error}")))
}

const UNSIGNED: &str =
    "this instance requires an HTTP signature for ActivityPub reads (secure mode is on)";

/// One header value by name (case-insensitive); a repeated header is refused, not guessed.
fn single(headers: &[(String, String)], name: &str) -> Result<Option<String>, ApiError> {
    let mut values = headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value);
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ApiError::unauthorized(format!(
            "the {name} header appears more than once"
        )));
    }
    Ok(Some(first.clone()))
}

/// The actor URL named by `keyId`, and the full key id to compare against the document.
fn key_actor(key_id: &str) -> Result<(String, &str), ApiError> {
    let actor = key_id.split('#').next().unwrap_or(key_id);
    if actor.is_empty() {
        return Err(ApiError::unauthorized("the signature names no keyId"));
    }
    validate_remote_url(actor)
        .map_err(|_| ApiError::unauthorized("the signing keyId is not a public HTTPS URL"))?;
    Ok((actor.to_owned(), key_id))
}

/// The origin rule: our own origin always, a peer only when it is not a blocked domain —
/// the same gate the inbox applies before it parses a signature.
async fn ensure_signer_allowed(state: &AppState, actor: &str) -> Result<(), ApiError> {
    let host = url::Url::parse(actor)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .ok_or_else(|| ApiError::unauthorized("the signing keyId has no host"))?;
    if host == state.instance().domain {
        return Ok(());
    }
    ensure_domain_allowed(state, &host)
        .await
        .map_err(|_| ApiError::unauthorized("the signing domain is blocked"))
}

/// Resolves a signing key that belongs to this instance without issuing a request.
///
/// Fetching our own actor over HTTP is a loop that secure mode itself closes: the fetch
/// is unsigned, so this instance answers it with the same 401 it gives any unsigned
/// reader — and the signature most likely to be made by an operator or a debugging tool
/// is the one that then fails. So a `keyId` on our own domain is answered from memory
/// (`FederationKey` for `/actor`, the account row for `/users/<name>`).
///
/// `Ok(None)` means the actor is a peer and the caller may resolve it over the network;
/// `Ok(Some(pem))` means it is ours and no request was made. `Err` means it claims to be
/// ours but is not a key we publish, which is never a reason to go to the network.
pub(crate) async fn local_actor_key(
    state: &AppState,
    actor: &str,
    key_id: &str,
) -> Result<Option<String>, ApiError> {
    let Ok(url) = url::Url::parse(actor) else {
        return Ok(None);
    };
    let ours = url
        .host_str()
        .is_some_and(|host| host.eq_ignore_ascii_case(&state.instance().domain));
    if !ours {
        return Ok(None);
    }
    if url.path() == "/actor" {
        let Some(key) = state.federation() else {
            return Err(ApiError::unauthorized(
                "this instance has no signing key configured",
            ));
        };
        if key_id != key.key_id() {
            return Err(ApiError::unauthorized(
                "the signature keyId is not this actor's public key",
            ));
        }
        let pem = key.public_pem().to_owned();
        state.cache_actor_key(actor, pem.clone());
        return Ok(Some(pem));
    }
    let username = url
        .path()
        .strip_prefix("/users/")
        .filter(|name| !name.is_empty() && !name.contains('/'));
    let Some(username) = username else {
        return Err(ApiError::unauthorized(
            "the signing keyId does not name one of this instance's actors",
        ));
    };
    let Some(account) = accounts::local_by_username(state.store().pool(), username).await? else {
        return Err(ApiError::unauthorized(
            "the signing keyId names no local account",
        ));
    };
    let Some(pem) = account.public_key_pem else {
        return Err(ApiError::unauthorized(
            "the local account has published no public key",
        ));
    };
    if key_id != format!("{actor}#main-key") {
        return Err(ApiError::unauthorized(
            "the signature keyId is not this actor's public key",
        ));
    }
    state.cache_actor_key(actor, pem.clone());
    Ok(Some(pem))
}

/// A signing key we already hold for `actor`: the memory cache, then the account row.
///
/// No network. This is the whole reason inbox delivery does not dial the sender: the
/// peer that signs a request is a peer we have a row for — we ingested its earlier
/// activity, or it addressed us from a key it published — and asking its host again to
/// learn what we store locally turns every delivery into a request to a host that may
/// not even resolve. The document fetch stays as the refresh path, so a rotated key
/// still converges rather than locking the peer out.
///
/// The gate is taken around the store lookup so concurrent misses for one actor share a
/// single query instead of stampeding the pool.
pub(crate) async fn known_actor_key(
    state: &AppState,
    actor: &str,
) -> Result<Option<String>, ApiError> {
    if let Some(pem) = state.cached_actor_key(actor) {
        return Ok(Some(pem));
    }
    let gate = state.key_fetch_gate(actor);
    let _cold = gate.lock().await;
    if let Some(pem) = state.cached_actor_key(actor) {
        return Ok(Some(pem));
    }
    let stored = accounts::by_uri(state.store().pool(), actor)
        .await?
        .and_then(|account| account.public_key_pem);
    if let Some(pem) = &stored {
        state.cache_actor_key(actor, pem.clone());
    }
    Ok(stored)
}

/// The signer's public key: our own data when the actor is local, then a key we already
/// hold, then its actor document.
///
/// Reaching the document costs one fetch, guarded per actor so concurrent requests wait
/// for it rather than each starting one. The fetch goes through the signing client
/// (`fediverse_client`), so a peer that also enforces secure mode accepts it. A fetch
/// that fails is an error and is never cached.
async fn key_for(state: &AppState, actor: &str, key_id: &str) -> Result<String, ApiError> {
    if let Some(pem) = local_actor_key(state, actor, key_id).await? {
        return Ok(pem);
    }
    if let Some(pem) = known_actor_key(state, actor).await? {
        return Ok(pem);
    }
    let document = state
        .fediverse_client()
        .actor_url(actor)
        .await
        .map_err(|error| {
            ApiError::unauthorized(format!("cannot fetch the signing actor's key: {error}"))
        })?;
    if document.id != actor {
        return Err(ApiError::unauthorized(
            "the fetched actor document names a different id",
        ));
    }
    if let Some(public_key_id) = document.public_key_id.as_deref() {
        if public_key_id != key_id {
            return Err(ApiError::unauthorized(
                "the signature keyId is not this actor's public key",
            ));
        }
    }
    let pem = document.public_key_pem.ok_or_else(|| {
        ApiError::unauthorized("the signing actor document carries no public key")
    })?;
    state.cache_actor_key(actor, pem.clone());
    Ok(pem)
}

/// Unit tests for the surface decision, which needs no database and no network.
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn read(uri: &str, accept: Option<&str>) -> Request {
        let mut builder = Request::builder().method("GET").uri(uri);
        if let Some(accept) = accept {
            builder = builder.header(header::ACCEPT, accept);
        }
        builder.body(Body::empty()).expect("request")
    }

    #[test]
    fn reads_of_activitypub_surfaces_need_a_signature() {
        assert!(needs_signature(&read("/actor", None)));
        assert!(needs_signature(&read("/users/alice", None)));
        assert!(needs_signature(&read(
            "/users/alice/outbox?page=true",
            None
        )));
        assert!(needs_signature(&read("/objects/1", None)));
        assert!(needs_signature(&read("/statuses/1", None)));
        assert!(needs_signature(&read(
            "/@alice/1",
            Some("application/activity+json")
        )));
    }

    #[test]
    fn discovery_delivery_and_the_client_api_keep_their_own_rules() {
        assert!(!needs_signature(&read(
            "/.well-known/webfinger?resource=acct:a@b",
            None
        )));
        assert!(!needs_signature(&read(
            "/api/v1/statuses/1",
            Some("application/json")
        )));
        assert!(!needs_signature(&read("/nodeinfo/2.0", None)));
        assert!(!needs_signature(&read("/@alice/1", Some("text/html"))));
        let post = Request::builder()
            .method("POST")
            .uri("/inbox")
            .body(Body::empty())
            .expect("request");
        assert!(!needs_signature(&post));
    }

    #[test]
    fn a_key_id_naming_a_fragment_is_resolved_to_its_actor() {
        let (actor, key_id) = key_actor("https://peer.test/users/bob#main-key").expect("actor");
        assert_eq!(actor, "https://peer.test/users/bob");
        assert_eq!(key_id, "https://peer.test/users/bob#main-key");
        assert!(key_actor("http://peer.test/users/bob#main-key").is_err());
        assert!(key_actor("https://127.0.0.1/users/bob#main-key").is_err());
    }
}
