//! The handshake and the protocol screen must tell the same story.
//!
//! A client gates its doors on `/api/v1/meta` and its Protocol screen reads
//! `/api/v1/nodus/capabilities`. Two lists that drift apart hide a service the instance
//! does serve, or advertise one it does not, and either way nobody notices until a
//! production console is empty.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use nodus_server_api::{meta, AppState, InstanceConfig};
use nodus_server_store::Store;

fn state() -> AppState {
    // A lazy pool: these tests assert routing and serialization, never a query.
    // Every capability switch is on, so this state is the whole vocabulary: the conditional
    // half (`drive_share` without NODUS_DRIVE_SHARE_SECRET) is asserted in
    // `tests/capabilities.rs`, where both states are built side by side.
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
    .with_drive_share(true)
}

async fn get(path: &str) -> (StatusCode, Option<String>, Value) {
    let response = nodus_server_api::root_router(state())
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let cache = response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body = serde_json::from_slice(&body).expect("json body");
    (status, cache, body)
}

fn names(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("features array")
        .iter()
        .map(|name| name.as_str().expect("feature name").to_owned())
        .collect()
}

#[tokio::test]
async fn the_handshake_names_a_recommender_flag_and_a_console_flag() {
    let (status, cache, body) = get("/api/v1/meta").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache.as_deref(), Some("public, max-age=60"));

    assert_eq!(body["api"], "1");
    assert_eq!(body["contract"], nodus_shared::CONTRACT_VERSION);
    assert_eq!(body["min_contract"], nodus_shared::MIN_CONTRACT_VERSION);

    let published = names(&body["features"]);
    // The recommender's three are served by this instance too, so they are named here.
    assert!(published.iter().any(|name| name == "feed_accounts"));
    // And the console doors this API itself answers for.
    assert!(published.iter().any(|name| name == "admin"));
    assert_eq!(published, meta::FEATURES.map(str::to_owned));
}

#[tokio::test]
async fn the_protocol_screen_cannot_contradict_the_gate() {
    let (_, _, handshake) = get("/api/v1/meta").await;
    let (status, _, capabilities) = get("/api/v1/nodus/capabilities").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(capabilities["contract"], "nodus-1");
    assert_eq!(capabilities["features"], handshake["features"]);
}
