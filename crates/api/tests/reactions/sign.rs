//! Signing a delivery into our inbox the way a peer does.
//!
//! The signature has to cover the body it signs, so the activity is serialised once and
//! both the digest and the POST body are built from those same bytes.

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
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

use nodus_server_store::accounts::{self, RemoteAccount};

pub const SIGNER: &str = "https://remote.test/users/reactor";

pub fn generate_keypair() -> (RsaPrivateKey, String) {
    let private = RsaPrivateKey::new(&mut OsRng, 1024).expect("rsa key");
    let pem = RsaPublicKey::from(&private)
        .to_public_key_pem(LineEnding::LF)
        .expect("public key pem");
    (private, pem)
}

/// Seeds the signer's published key, so verification costs no outbound fetch.
pub async fn seed_signer(pool: &PgPool, uri: &str, pem: &str) {
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

pub async fn post_signed_inbox(
    app: &Router,
    private: &RsaPrivateKey,
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
        "keyId=\"{SIGNER}#main-key\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date digest\",signature=\"{}\"",
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
