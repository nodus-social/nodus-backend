//! Web Push delivery: the payload a browser can actually read, the alert filter, and the
//! two ways a dead endpoint leaves the table.
//!
//! The payload assertion decrypts with the subscription's own key pair. Checking the JSON
//! shape of the encrypted body would pass on a body no browser can open, which is the one
//! failure that matters here.

mod support;

use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use base64::Engine;
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use p256::{EncodedPoint, PublicKey, SecretKey};
use serde_json::{json, Value};
use sha2::Sha256;

use nodus_server_api::webpush;
use nodus_server_store::{push, social};

use support::{create_account, run_db_test, test_vapid};

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn alerts(mention: bool, follow: bool) -> Value {
    json!({
        "mention": mention,
        "reblog": false,
        "follow": follow,
        "follow_request": false,
        "favourite": false,
        "poll": false,
        "status": false,
        "update": false,
        "admin.sign_up": false,
        "admin.report": false,
    })
}

/// A browser's own key pair, as `PushManager.subscribe` would produce it.
fn browser_keys() -> (SecretKey, String, String) {
    let secret = SecretKey::random(&mut OsRng);
    let public = EncodedPoint::from(secret.public_key()).as_bytes().to_vec();
    let mut auth = [0u8; 16];
    OsRng.fill_bytes(&mut auth);
    (secret, b64(&public), b64(&auth))
}

/// An HTTP endpoint that records every body it receives and always answers `status`.
async fn stub(status: StatusCode) -> (String, Arc<Mutex<Vec<Vec<u8>>>>) {
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let recorded = bodies.clone();
    let app = Router::new().route(
        "/push",
        post(move |body: Bytes| {
            let recorded = recorded.clone();
            async move {
                recorded.lock().expect("bodies").push(body.to_vec());
                (status, "")
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub");
    let address = listener.local_addr().expect("stub address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{address}/push"), bodies)
}

/// RFC 8291's decryption, written independently of [`webpush::encrypt`] so the test cannot
/// pass by sharing a mistake with the sender.
fn decrypt(secret: &SecretKey, auth: &str, body: &[u8]) -> Vec<u8> {
    let salt = &body[..16];
    let id_length = body[20] as usize;
    let sender_public = &body[21..21 + id_length];
    let header = &body[..21 + id_length];
    let ciphertext = &body[21 + id_length..];

    let ua_public = EncodedPoint::from(secret.public_key()).as_bytes().to_vec();
    let sender = PublicKey::from_sec1_bytes(sender_public).expect("sender key");
    let shared = diffie_hellman(secret.to_nonzero_scalar(), sender.as_affine());

    let mut info = b"WebPush: info\x00".to_vec();
    info.extend_from_slice(&ua_public);
    info.extend_from_slice(sender_public);
    let auth = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(auth)
        .expect("auth base64");
    let ikm_hkdf = Hkdf::<Sha256>::new(Some(&auth), shared.raw_secret_bytes());
    let mut ikm = [0u8; 32];
    ikm_hkdf.expand(&info, &mut ikm).expect("ikm");

    let hkdf = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut cek = [0u8; 16];
    hkdf.expand(b"Content-Encoding: aes128gcm\x00", &mut cek)
        .expect("cek");
    let mut nonce = [0u8; 12];
    hkdf.expand(b"Content-Encoding: nonce\x00", &mut nonce)
        .expect("nonce");

    let cipher = Aes128Gcm::new_from_slice(&cek).expect("cipher");
    let mut plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .expect("decrypt");
    // The last-record delimiter ends the data; there is no padding after it.
    if let Some(position) = plaintext.iter().rposition(|byte| *byte == 0x02) {
        plaintext.truncate(position);
    }
    plaintext
}

#[tokio::test]
async fn a_mention_payload_decrypts_and_a_follow_only_subscriber_is_skipped() {
    run_db_test(|store, _app| async move {
        let recipient = create_account(store.pool(), "push-delivery-mention").await;
        let actor = create_account(store.pool(), "push-delivery-actor").await;
        social::notify_with_note(
            store.pool(),
            &recipient,
            "mention",
            &actor,
            None,
            Some("A very particular sentence"),
        )
        .await
        .expect("notification");

        let (secret, p256dh, auth) = browser_keys();
        let (live, live_bodies) = stub(StatusCode::CREATED).await;
        let (dead, _dead_bodies) = stub(StatusCode::INTERNAL_SERVER_ERROR).await;
        let (quiet, quiet_bodies) = stub(StatusCode::CREATED).await;

        push::upsert(
            store.pool(),
            &recipient,
            &live,
            &p256dh,
            &auth,
            &alerts(true, false),
            None,
        )
        .await
        .expect("live subscription");
        push::upsert(
            store.pool(),
            &recipient,
            &dead,
            &p256dh,
            &auth,
            &alerts(true, false),
            None,
        )
        .await
        .expect("dead subscription");
        push::upsert(
            store.pool(),
            &recipient,
            &quiet,
            &p256dh,
            &auth,
            &alerts(false, true),
            None,
        )
        .await
        .expect("follow-only subscription");

        let report = webpush::deliver_due(store.pool(), &test_vapid(), 100)
            .await
            .expect("deliver");
        assert_eq!(report.sent, 1, "one live endpoint was reached");
        assert_eq!(report.failed, 1, "the 500 endpoint was counted, not fatal");

        let bodies = live_bodies.lock().expect("live bodies").clone();
        assert_eq!(bodies.len(), 1, "the live endpoint got exactly one push");
        assert!(
            quiet_bodies.lock().expect("quiet bodies").is_empty(),
            "a follow-only subscriber must not receive a mention"
        );

        let plaintext = decrypt(&secret, &auth, &bodies[0]);
        let payload: Value = serde_json::from_slice(&plaintext).expect("payload JSON");
        assert!(
            payload["body"]
                .as_str()
                .unwrap_or_default()
                .contains("A very particular sentence"),
            "payload: {payload}"
        );

        let subscriptions = push::list(store.pool(), &recipient).await.expect("list");
        assert_eq!(subscriptions.len(), 3, "one failure must not remove a row");
    })
    .await;
}

#[tokio::test]
async fn a_410_from_the_push_service_removes_the_subscription() {
    run_db_test(|store, _app| async move {
        let recipient = create_account(store.pool(), "push-delivery-gone").await;
        let actor = create_account(store.pool(), "push-delivery-gone-actor").await;
        social::notify_with_note(store.pool(), &recipient, "follow", &actor, None, None)
            .await
            .expect("notification");

        let (_, p256dh, auth) = browser_keys();
        let (gone, _bodies) = stub(StatusCode::GONE).await;
        push::upsert(
            store.pool(),
            &recipient,
            &gone,
            &p256dh,
            &auth,
            &alerts(false, true),
            None,
        )
        .await
        .expect("subscription");

        let report = webpush::deliver_due(store.pool(), &test_vapid(), 100)
            .await
            .expect("deliver");
        assert_eq!(report.removed, 1);
        assert!(
            push::list(store.pool(), &recipient)
                .await
                .expect("list")
                .is_empty(),
            "a 410 means the browser is gone and the row goes with it"
        );
    })
    .await;
}

#[tokio::test]
async fn ten_failures_retire_the_subscription() {
    run_db_test(|store, _app| async move {
        let recipient = create_account(store.pool(), "push-delivery-cap").await;
        let actor = create_account(store.pool(), "push-delivery-cap-actor").await;
        let (_, p256dh, auth) = browser_keys();
        let (dead, _bodies) = stub(StatusCode::INTERNAL_SERVER_ERROR).await;
        push::upsert(
            store.pool(),
            &recipient,
            &dead,
            &p256dh,
            &auth,
            &alerts(true, true),
            None,
        )
        .await
        .expect("subscription");

        for attempt in 1..=webpush::MAX_FAILURES {
            social::notify_with_note(
                store.pool(),
                &recipient,
                "mention",
                &actor,
                None,
                Some("retry"),
            )
            .await
            .expect("notification");
            webpush::deliver_due(store.pool(), &test_vapid(), 100)
                .await
                .expect("deliver");
            if attempt < webpush::MAX_FAILURES {
                let rows = push::list(store.pool(), &recipient).await.expect("list");
                assert_eq!(
                    rows.len(),
                    1,
                    "the row survives until the tenth failure (attempt {attempt})"
                );
            }
        }
        assert!(
            push::list(store.pool(), &recipient)
                .await
                .expect("list")
                .is_empty(),
            "the tenth failure drops the row"
        );
    })
    .await;
}
