//! `POST /api/v1/apps`: the client registration a browser makes before it can subscribe
//! to Web Push.
//!
//! A browser needs the VAPID public key *before* it calls `pushManager.subscribe`, and it
//! has no subscription yet, so `GET /api/v1/push/subscription` answers 404. Mastodon
//! publishes the key on the app document for exactly this reason; these tests pin that
//! the same key is there, and that an instance without a key fabricates nothing.

mod support;

use serde_json::json;

use support::{json_of, run_db_test, run_db_test_without_vapid, send, send_anon, test_vapid};

async fn register(app: &axum::Router) -> serde_json::Value {
    let (status, body) = send(
        app,
        "",
        "POST",
        "/api/v1/apps",
        Some(json!({
            "client_name": "WebClient",
            "redirect_uris": "https://client.test/cb",
            "scopes": "read write push"
        })),
    )
    .await;
    assert_eq!(status, 200, "app register failed: {body}");
    json_of(&body)
}

#[tokio::test]
async fn registration_publishes_the_configured_vapid_key() {
    run_db_test(|_store, app| async move {
        let registered = register(&app).await;
        assert_eq!(
            registered["vapid_key"],
            test_vapid().public_key(),
            "the browser subscribes with this exact key: {registered}"
        );

        let (status, body) = send_anon(&app, "GET", "/api/v2/instance").await;
        assert_eq!(status, 200, "instance v2: {body}");
        assert_eq!(
            json_of(&body)["configuration"]["vapid"]["public_key"],
            test_vapid().public_key()
        );

        let (status, body) = send_anon(&app, "GET", "/api/v1/instance").await;
        assert_eq!(status, 200, "instance v1: {body}");
        assert_eq!(
            json_of(&body)["configuration"]["vapid"]["public_key"],
            test_vapid().public_key()
        );
    })
    .await;
}

#[tokio::test]
async fn registration_without_a_vapid_key_reports_null() {
    run_db_test_without_vapid(|_store, app| async move {
        let registered = register(&app).await;
        assert_eq!(
            registered.get("vapid_key"),
            Some(&serde_json::Value::Null),
            "an instance with no key must not invent one: {registered}"
        );

        let (status, body) = send_anon(&app, "GET", "/api/v2/instance").await;
        assert_eq!(status, 200, "instance v2: {body}");
        assert!(
            json_of(&body)["configuration"].get("vapid").is_none(),
            "the configuration omits vapid rather than nulling it: {body}"
        );
    })
    .await;
}
