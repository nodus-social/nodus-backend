//! What `NODUS_ALLOW_INSECURE_PEERS` changes on the inbound side.
//!
//! A lab peer in development mode signs its deliveries and names its actors over plain
//! http. The escape hatch is the same host allowlist the outbound client uses, so these
//! tests prove a real signature from a named `http` actor verifies, that an unlisted one
//! is still refused with the same error, and that `https` is undisturbed. Each binary gets
//! one list because `insecure_peer_hosts` caches it in a `OnceLock`; the empty-list case is
//! therefore its own file, `inbound_http_refused_by_default.rs`.

mod support;

use std::sync::Once;

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

use nodus_server_store::accounts::{self, RemoteAccount};

/// The peer name this test binary allows.
const PEER: &str = "peer.test";

fn allow_peer() {
    static ALLOW: Once = Once::new();
    ALLOW.call_once(|| std::env::set_var("NODUS_ALLOW_INSECURE_PEERS", PEER));
}

fn generate_keypair() -> (RsaPrivateKey, String) {
    let private = RsaPrivateKey::new(&mut OsRng, 1024).expect("rsa key");
    let pem = RsaPublicKey::from(&private)
        .to_public_key_pem(LineEnding::LF)
        .expect("public key pem");
    (private, pem)
}

/// Seeds the signer's published key so verification costs no outbound fetch, the way
/// `issue_11.rs` seeds the peers it signs as.
async fn seed_signer(pool: &PgPool, uri: &str, pem: &str) {
    let parsed = url::Url::parse(uri).expect("signer url");
    let username = parsed.path().rsplit('/').next().unwrap_or_default();
    accounts::upsert_remote(
        pool,
        &RemoteAccount {
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

/// The activity a peer sends about itself: one real RSA signature over the same header set
/// the server requires, which is only accepted after the signer's URL passes the guard.
fn delete_self(signer: &str) -> Value {
    json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{signer}/deletes/1"),
        "type": "Delete",
        "actor": signer,
        "object": { "id": signer, "type": "Person" },
    })
}

async fn post_signed_inbox(
    app: &Router,
    private: &RsaPrivateKey,
    key_id: &str,
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
        "keyId=\"{key_id}\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date digest\",signature=\"{}\"",
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

/// (b): a real signature from a named `http` actor verifies and is ingested.
#[tokio::test]
async fn a_named_plain_http_signer_verifies_a_delivery() {
    allow_peer();
    support::run_db_test(|store, app| async move {
        let (key, pem) = generate_keypair();
        let signer = "http://peer.test:3000/users/alice";
        seed_signer(store.pool(), signer, &pem).await;
        let (status, body) = post_signed_inbox(
            &app,
            &key,
            &format!("{signer}#main-key"),
            &delete_self(signer),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "a signed delivery from a named plain-http peer must verify: {body}"
        );
    })
    .await;
}

/// (c): the allowlist is a list, not a mode — in one run, an unlisted `http` signer is
/// refused at verification and a listed one is accepted.
#[tokio::test]
async fn an_unlisted_http_signer_is_refused_while_a_listed_one_is_accepted() {
    allow_peer();
    support::run_db_test(|store, app| async move {
        let pool = store.pool();
        let (unlisted_key, unlisted_pem) = generate_keypair();
        let unlisted = "http://unlisted.test/users/bob";
        seed_signer(pool, unlisted, &unlisted_pem).await;
        let (status, body) = post_signed_inbox(
            &app,
            &unlisted_key,
            &format!("{unlisted}#main-key"),
            &delete_self(unlisted),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "an unlisted plain-http signer must be refused: {body}"
        );
        assert!(
            body.contains("signing key actor URL is invalid"),
            "the refusal must stay at the scheme check, saw {body}"
        );

        let (listed_key, listed_pem) = generate_keypair();
        let listed = "http://peer.test:3000/users/carol";
        seed_signer(pool, listed, &listed_pem).await;
        let (status, body) = post_signed_inbox(
            &app,
            &listed_key,
            &format!("{listed}#main-key"),
            &delete_self(listed),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "naming the host must accept exactly that host: {body}"
        );
    })
    .await;
}

/// (d): an `https` signer keeps verifying while the escape hatch is configured.
#[tokio::test]
async fn an_https_signer_still_verifies() {
    allow_peer();
    support::run_db_test(|store, app| async move {
        let (key, pem) = generate_keypair();
        let signer = "https://remote.test/users/dave";
        seed_signer(store.pool(), signer, &pem).await;
        let (status, body) = post_signed_inbox(
            &app,
            &key,
            &format!("{signer}#main-key"),
            &delete_self(signer),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "an https signer is unaffected by the allowlist: {body}"
        );
    })
    .await;
}
