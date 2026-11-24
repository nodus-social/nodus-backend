//! Relay subscriptions: the console's `Follow`, the relay's answer, and the `Undo`.
//!
//! The assertions are on stored state and on the delivery queue rather than on a live peer:
//! a subscription's whole lifecycle is a row, a queued activity and the row's state after
//! the relay answers, and none of that needs a relay process to be running.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::Utc;
use http_body_util::BodyExt;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{EncodePublicKey as _, LineEnding};
use rsa::rand_core::OsRng;
use rsa::signature::{SignatureEncoding as _, Signer as _};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

use nodus_server_store::accounts;

mod support;

use support::{create_account, create_token, json_of, run_db_test, send, send_form};

const RELAY: &str = "https://relay.test/inbox";
const RELAY_ACTOR: &str = "https://relay.test/actor";

async fn staff(pool: &PgPool, label: &str) -> String {
    let id = create_account(pool, label).await;
    accounts::set_staff_role(pool, &id, "admin")
        .await
        .expect("grant role");
    create_token(pool, &id, &["admin:read", "admin:write"]).await
}

/// The queued activities, oldest first.
async fn queued(pool: &PgPool) -> Vec<Value> {
    let rows: Vec<(Value,)> =
        sqlx::query_as("SELECT activity FROM federation_delivery ORDER BY created_at, id")
            .fetch_all(pool)
            .await
            .expect("delivery rows");
    rows.into_iter().map(|(activity,)| activity).collect()
}

async fn subscribe(app: &Router, token: &str, inbox_url: &str) -> Value {
    let (status, body) = send(
        app,
        token,
        "POST",
        "/api/v1/admin/relays",
        Some(json!({ "inbox_url": inbox_url })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "subscribe refused: {body}");
    json_of(&body)
}

async fn state_of(app: &Router, token: &str, id: &str) -> String {
    let (status, body) = send(app, token, "GET", "/api/v1/admin/relays", None).await;
    assert_eq!(status, StatusCode::OK, "list refused: {body}");
    json_of(&body)
        .as_array()
        .expect("relay list")
        .iter()
        .find(|relay| relay["id"] == json!(id))
        .unwrap_or_else(|| panic!("relay {id} vanished: {body}"))["state"]
        .as_str()
        .expect("state")
        .to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn subscribing_refuses_a_bad_url_and_a_duplicate() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let token = staff(pool, "relay-admin").await;

        for bad in ["http://relay.test/inbox", "not a url"] {
            let (status, body) = send(
                &app,
                &token,
                "POST",
                "/api/v1/admin/relays",
                Some(json!({ "inbox_url": bad })),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
        }
        assert!(
            queued(pool).await.is_empty(),
            "a refused URL queued a Follow"
        );

        let relay = subscribe(&app, &token, RELAY).await;
        assert_eq!(relay["inbox_url"], json!(RELAY));
        assert_eq!(relay["state"], json!("pending"));
        let follow_id = relay["follow_activity_id"].as_str().expect("follow id");

        let follow = queued(pool)
            .await
            .into_iter()
            .find(|activity| activity["type"] == json!("Follow"))
            .expect("queued Follow");
        assert_eq!(follow["id"], json!(follow_id));
        assert_eq!(follow["object"], json!(RELAY));

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/admin/relays",
            Some(json!({ "inbox_url": RELAY })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
        assert!(body.contains("already subscribed"), "body: {body}");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_form_body_subscribes_too() {
    run_db_test(|store, app| async move {
        let token = staff(store.pool(), "relay-form-admin").await;
        let (status, body) = send_form(
            &app,
            &token,
            "POST",
            "/api/v1/admin/relays",
            &[("inbox_url", RELAY)],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "form subscribe refused: {body}");
        assert_eq!(json_of(&body)["state"], json!("pending"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unsubscribing_deletes_the_row_and_queues_an_undo() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let token = staff(pool, "relay-admin").await;
        let relay = subscribe(&app, &token, RELAY).await;
        let id = relay["id"].as_str().expect("id");
        let follow_id = relay["follow_activity_id"]
            .as_str()
            .expect("follow id")
            .to_owned();

        let (status, body) = send(
            &app,
            &token,
            "DELETE",
            &format!("/api/v1/admin/relays/{id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unsubscribe refused: {body}");
        assert_eq!(json_of(&body)["inbox_url"], json!(RELAY));

        let (status, body) = send(&app, &token, "GET", "/api/v1/admin/relays", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json_of(&body), json!([]), "row survived: {body}");

        let undo = queued(pool)
            .await
            .into_iter()
            .find(|activity| activity["type"] == json!("Undo"))
            .expect("queued Undo");
        assert_eq!(undo["object"]["id"], json!(follow_id));
        assert_eq!(undo["object"]["type"], json!("Follow"));
        assert_eq!(undo["object"]["object"], json!(RELAY));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn accept_and_reject_move_the_subscription_out_of_pending() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let token = staff(pool, "relay-admin").await;
        let (private, pem) = generate_keypair();
        seed_signer(pool, RELAY_ACTOR, &pem).await;
        let actor = "https://social.test/users/relay-follower";

        let relay = subscribe(&app, &token, RELAY).await;
        let id = relay["id"].as_str().expect("id").to_owned();
        let follow_id = relay["follow_activity_id"]
            .as_str()
            .expect("follow id")
            .to_owned();

        let (status, body) = post_signed(
            &app,
            &private,
            RELAY_ACTOR,
            &json!({
                "id": format!("{RELAY_ACTOR}#accepts/1"),
                "type": "Accept",
                "actor": RELAY_ACTOR,
                "object": { "id": follow_id, "type": "Follow", "actor": actor, "object": RELAY },
            }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "accept answered: {body}");
        assert_eq!(state_of(&app, &token, &id).await, "accepted");

        let second = "https://relay-two.test/inbox";
        let relay = subscribe(&app, &token, second).await;
        let id = relay["id"].as_str().expect("id").to_owned();
        let follow_id = relay["follow_activity_id"]
            .as_str()
            .expect("follow id")
            .to_owned();
        let (status, body) = post_signed(
            &app,
            &private,
            RELAY_ACTOR,
            &json!({
                "id": format!("{RELAY_ACTOR}#rejects/1"),
                "type": "Reject",
                "actor": RELAY_ACTOR,
                "object": { "id": follow_id, "type": "Follow", "actor": actor, "object": second },
            }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "reject answered: {body}");
        assert_eq!(state_of(&app, &token, &id).await, "rejected");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_announce_from_an_unknown_relay_is_acknowledged() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (private, pem) = generate_keypair();
        let actor = "https://unknown-relay.test/actor";
        seed_signer(pool, actor, &pem).await;

        let (status, body) = post_signed(
            &app,
            &private,
            actor,
            &json!({
                "id": format!("{actor}#announces/1"),
                "type": "Announce",
                "actor": actor,
                "object": "https://elsewhere.test/users/someone/statuses/1",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "announce answered: {body}");
        assert!(
            queued(pool).await.is_empty(),
            "an Announce must not become a delivery"
        );
    })
    .await;
}

fn generate_keypair() -> (RsaPrivateKey, String) {
    let private = RsaPrivateKey::new(&mut OsRng, 1024).expect("rsa key");
    let pem = RsaPublicKey::from(&private)
        .to_public_key_pem(LineEnding::LF)
        .expect("public key pem");
    (private, pem)
}

/// Seeds the signer's published key, so verification costs no outbound fetch.
async fn seed_signer(pool: &PgPool, uri: &str, pem: &str) {
    let parsed = url::Url::parse(uri).expect("signer url");
    let username = parsed.path().rsplit('/').next().unwrap_or_default();
    accounts::upsert_remote(
        pool,
        &accounts::RemoteAccount {
            uri,
            username,
            domain: parsed.host_str().expect("signer host"),
            display_name: username,
            note: "",
            avatar_url: None,
            header_url: None,
            inbox_url: Some(&format!("{uri}/inbox")),
            shared_inbox_url: None,
            public_key_pem: Some(pem),
            locked: false,
            bot: false,
        },
    )
    .await
    .expect("upsert remote signer");
}

/// Signs and posts one activity into the shared inbox, the way a peer delivers it.
async fn post_signed(
    app: &Router,
    private: &RsaPrivateKey,
    actor: &str,
    activity: &Value,
) -> (StatusCode, String) {
    let body_bytes = serde_json::to_vec(activity).expect("json bytes");
    let digest = format!("SHA-256={}", BASE64.encode(Sha256::digest(&body_bytes)));
    let date = Utc::now().to_rfc2822();
    let signing_input = [
        "(request-target): post /inbox".to_owned(),
        "host: social.test".to_owned(),
        format!("date: {date}"),
        format!("digest: {digest}"),
    ]
    .join("\n");
    let signature = SigningKey::<Sha256>::new(private.clone()).sign(signing_input.as_bytes());
    let header = format!(
        "keyId=\"{actor}#main-key\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date digest\",signature=\"{}\"",
        BASE64.encode(signature.to_bytes())
    );
    let request = Request::builder()
        .method("POST")
        .uri("/inbox")
        .header("host", "social.test")
        .header("date", date)
        .header("digest", digest)
        .header("signature", header)
        .body(Body::from(body_bytes))
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("router response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}
