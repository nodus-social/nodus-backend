//! The routes this API retired stay retired, and answer what was promised.
//!
//! Two decisions are pinned here, because an audit that removed a surface is only finished
//! if nothing quietly puts it back:
//!
//! 1. `GET /api/v1/nodus/events` answers `410 Gone` naming `/api/v1/streaming`. It is kept
//!    as a tombstone rather than deleted because an SSE client cannot tell a `404` from a
//!    dropped connection and reconnects on both.
//! 2. `GET /api/v1/nodus/sync/snapshot` and both `/api/v1/hydrate/*` routes are gone, and
//!    must fall through to the router's `404` — a handler that assembled its own copy of a
//!    status page, and a second remote-ingest path nothing called, are dead weight.
//!
//! The last test is the other half of a retirement: the surface clients do use — the stream,
//! the sync root, the capability document and the handshake — still answers.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use nodus_server_api::{router, AppState, InstanceConfig};
use nodus_server_store::Store;

/// A state that never reaches a database.
///
/// Every route asserted here answers before a row is touched — a tombstone, the fallback, a
/// grant refusal or a public document — so a lazy pool is enough. `tests/capabilities.rs`
/// explains the same choice at length.
fn state() -> AppState {
    let store = Store::connect_lazy("postgres://nodus:nodus@127.0.0.1:1/nodus", 1);
    AppState::new(
        store,
        InstanceConfig {
            domain: "social.test".to_owned(),
            base_url: "https://social.test".to_owned(),
            title: "Nodus test".to_owned(),
            description: "A test instance".to_owned(),
            contact_email: None,
            api_version: "4.3.0".to_owned(),
            version: "0.1.0".to_owned(),
            registrations_open: false,
        },
    )
}

async fn get(path: &str) -> (StatusCode, String) {
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        router(state()).oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("request"),
        ),
    )
    .await
    .unwrap_or_else(|_| panic!("{path} reached a handler that needed a database"))
    .expect("response");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn the_retired_event_stream_says_where_it_went() {
    // No token and a collection the caller would not own: the tombstone is answered before
    // any grant is consulted, which is the point — the old client never sees a 401 and
    // concludes it should re-authenticate instead of move.
    let (status, body) = get("/api/v1/nodus/events?collection=timeline:local").await;
    assert_eq!(status, StatusCode::GONE, "answered {status}: {body}");
    assert_eq!(
        body,
        r#"{"error":"this endpoint was replaced by /api/v1/streaming"}"#
    );
}

#[tokio::test]
async fn the_deleted_surface_falls_through_to_no_route() {
    for path in [
        "/api/v1/nodus/sync/snapshot?collection=timeline:local",
        "/api/v1/hydrate/account?acct=alice@remote.test",
        "/api/v1/hydrate/status?url=https://remote.test/notes/1",
    ] {
        let (status, body) = get(path).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{path} is retired but answered {status}: {body}"
        );
        assert!(
            body.contains("no route for"),
            "{path} reached a handler instead of the fallback: {body}"
        );
    }
}

#[tokio::test]
async fn the_surface_that_stayed_still_answers() {
    assert_eq!(
        get("/api/v1/streaming").await.0,
        StatusCode::UNAUTHORIZED,
        "the replacement must still be there, behind its grant"
    );
    assert_eq!(
        get("/api/v1/nodus/sync/root?collection=timeline:local")
            .await
            .0,
        StatusCode::UNAUTHORIZED,
        "sync/root is the collection probe a diff client still needs"
    );
    assert_eq!(get("/api/v1/nodus/capabilities").await.0, StatusCode::OK);
    assert_eq!(get("/api/v1/meta").await.0, StatusCode::OK);
}
