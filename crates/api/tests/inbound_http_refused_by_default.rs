//! The default is unchanged: with no peer named, an `http` signer is refused at
//! verification, before any key lookup, with the same error as before.
//!
//! This lives in its own binary because `insecure_peer_hosts` caches
//! `NODUS_ALLOW_INSECURE_PEERS` in a `OnceLock`; the allowlisted cases are in
//! `inbound_insecure_peers.rs`, a separate process with the variable set.

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::Utc;
use http_body_util::BodyExt;
use rsa::pkcs1v15::SigningKey;
use rsa::rand_core::OsRng;
use rsa::signature::{SignatureEncoding as _, Signer as _};
use rsa::RsaPrivateKey;
use serde_json::json;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

/// (a): with the list empty, a signed delivery from an `http` actor is refused with the
/// same message the lab saw, so nothing about the default moved.
#[tokio::test]
async fn a_plain_http_signer_is_refused_when_no_peer_is_named() {
    support::run_db_test(|_store, app| async move {
        assert!(
            std::env::var("NODUS_ALLOW_INSECURE_PEERS").map_or(true, |list| list.trim().is_empty()),
            "this test binary must not run with the escape hatch configured"
        );

        let private = RsaPrivateKey::new(&mut OsRng, 1024).expect("rsa key");
        let signer = "http://peer.test:3000/users/alice";
        let activity = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "http://peer.test:3000/follows/1",
            "type": "Follow",
            "actor": signer,
            "object": "https://social.test/users/nobody",
        });
        let body_bytes = serde_json::to_vec(&activity).expect("json bytes");
        let digest = format!("SHA-256={}", BASE64.encode(Sha256::digest(&body_bytes)));
        let date = Utc::now().to_rfc2822();
        let signing_input = [
            "(request-target): post /inbox".to_owned(),
            "host: social.test".to_owned(),
            format!("date: {date}"),
            format!("digest: {digest}"),
        ]
        .join("\n");
        let signature = SigningKey::<Sha256>::new(private).sign(signing_input.as_bytes());
        let header = format!(
            "keyId=\"{signer}#main-key\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date digest\",signature=\"{}\"",
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
        let body = String::from_utf8_lossy(&bytes);
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "an unlisted plain-http signer must still be refused: {body}"
        );
        assert!(
            body.contains("signing key actor URL is invalid"),
            "the refusal must keep its text, saw {body}"
        );
    })
    .await;
}
