//! What `NODUS_ALLOW_INSECURE_PEERS` changes, and what it does not.
//!
//! A lab peer runs in development mode: plain http, a port of its own choosing, no
//! certificate. The escape hatch is a host allowlist, so the tests here prove three
//! things: a named host is actually dialled at the scheme and port its target names (a
//! real listener on this machine answers, and the `Host` header it sees carries the
//! port); the first such request warns once and the second does not; and an unlisted
//! host is still refused before any lookup happens.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex, Once, OnceLock, PoisonError};

use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use tokio::net::TcpListener;
use tracing_subscriber::layer::SubscriberExt;

use nodus_server_api::remote::{parse_target, resolve, Target};

/// The peer name the escaping tests allow.
///
/// `parse_target` accepts names only, never address literals, and requires a dot, so
/// `localhost` will not do. `localhost.localdomain` is the conventional `/etc/hosts`
/// alias for this machine; binding the listener by the same name means the address
/// family the test listens on is the one the resolver hands the client.
const PEER: &str = "localhost.localdomain";

/// Warnings recorded for the whole test binary.
static WARNINGS: OnceLock<Arc<Mutex<Vec<String>>>> = OnceLock::new();

fn allow_peer() {
    static ALLOW: Once = Once::new();
    ALLOW.call_once(|| {
        std::env::set_var("NODUS_ALLOW_INSECURE_PEERS", PEER);
        // The listener is on loopback, which the private-address guard refuses unless
        // the host is named. Listing it is a separate decision from allowing http.
        std::env::set_var("NODUS_ALLOW_PRIVATE_HOSTS", PEER);
    });
}

fn capture_warnings() -> &'static Arc<Mutex<Vec<String>>> {
    WARNINGS.get_or_init(|| {
        let warnings = Arc::new(Mutex::new(Vec::new()));
        let subscriber =
            tracing_subscriber::registry().with(CaptureWarnings(Arc::clone(&warnings)));
        tracing::subscriber::set_global_default(subscriber)
            .expect("install the warning capture once per test binary");
        warnings
    })
}

struct CaptureWarnings(Arc<Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureWarnings {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        let mut message = String::new();
        event.record(&mut Message(&mut message));
        if !message.is_empty() {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(message);
        }
    }
}

struct Message<'a>(&'a mut String);

impl tracing::field::Visit for Message<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        }
    }
}

fn warning_count(warnings: &Mutex<Vec<String>>, needle: &str) -> usize {
    warnings
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter(|warning| warning.contains(needle))
        .count()
}

#[derive(Clone)]
struct Peer {
    hosts: Arc<Mutex<Vec<String>>>,
}

/// Answers as `alice`, deriving every URL from the `Host` the request carried so the
/// document is only acceptable if the scheme and port reached this listener intact.
async fn actor(State(peer): State<Peer>, headers: HeaderMap) -> impl IntoResponse {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    peer.hosts
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(host.clone());
    let base = format!("http://{host}");
    Json(json!({
        "id": format!("{base}/users/alice"),
        "type": "Person",
        "preferredUsername": "alice",
        "inbox": format!("{base}/users/alice/inbox"),
        "publicKey": { "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n" }
    }))
}

async fn start_peer() -> (String, u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind((PEER, 0))
        .await
        .expect("bind the peer listener");
    let port = listener.local_addr().expect("peer address").port();
    let hosts = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/users/alice", get(actor))
        .with_state(Peer {
            hosts: Arc::clone(&hosts),
        });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{PEER}:{port}/users/alice"), port, hosts)
}

/// (b) and (d): the named peer is reached over http on its own port, and the operator
/// sees one warning for it, not one per request.
#[tokio::test]
async fn a_named_http_peer_is_dialled_at_its_own_scheme_and_port() {
    allow_peer();
    let warnings = Arc::clone(capture_warnings());
    let (url, port, hosts) = start_peer().await;

    let actor = resolve(&url, None)
        .await
        .expect("the peer answers in clear");
    assert_eq!(actor.username, "alice");
    assert_eq!(actor.domain, PEER);
    assert_eq!(
        actor.uri,
        format!("http://{PEER}:{port}/users/alice"),
        "the document was built from the port the request reached"
    );
    let seen = hosts.lock().unwrap_or_else(PoisonError::into_inner).clone();
    assert_eq!(seen.len(), 1, "one request for one resolution");
    assert!(
        seen[0].ends_with(&format!(":{port}")),
        "the Host header should carry the non-default port, saw {:?}",
        seen[0]
    );

    resolve(&url, None).await.expect("the peer answers twice");
    assert_eq!(
        warning_count(&warnings, "plain http"),
        1,
        "a second request to the same host must not warn again"
    );
}

/// (c): the allowlist is a list, not a switch.
#[tokio::test]
async fn an_unlisted_host_over_http_is_still_refused() {
    allow_peer();
    assert!(parse_target("http://unlisted.test/users/alice").is_none());
    assert!(
        resolve("http://unlisted.test/users/alice", None)
            .await
            .is_err(),
        "an unlisted host must not reach the network"
    );
}

/// (c) again, from the other side: naming one host does not disturb `https`.
#[tokio::test]
async fn an_https_target_is_a_link_as_before() {
    allow_peer();
    assert_eq!(
        parse_target("https://remote.test/@alice"),
        Some(Target::Link {
            url: "https://remote.test/@alice".to_owned(),
            host: "remote.test".to_owned(),
        })
    );
    let actor = serde_json::json!({
        "id": "https://remote.test/users/alice",
        "type": "Person",
        "preferredUsername": "alice",
    });
    assert!(nodus_server_api::remote::actor_from_document(&actor, "alice", "remote.test").is_ok());
    let plain = serde_json::json!({
        "id": "http://remote.test/users/alice",
        "type": "Person",
        "preferredUsername": "alice",
    });
    assert!(
        nodus_server_api::remote::actor_from_document(&plain, "alice", "remote.test").is_err(),
        "a document cannot smuggle in a plain-http id for an unlisted host"
    );
}
