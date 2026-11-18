//! The instance actor document and the key it publishes.
//!
//! A peer resolves the `keyId` on our signed fetches to this document, so the two have to
//! name the same key. Nothing else exercises that pairing: our own signature verifies even
//! when the published id is wrong.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::rand_core::OsRng;
use serde_json::Value;
use tower::ServiceExt;

use nodus_server_api::{root_router, AppState, FederationKey};

mod support;

use support::{instance_config, run_db_test};

fn key() -> (FederationKey, String) {
    let private = rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("key");
    let pem = private.to_pkcs8_pem(LineEnding::LF).expect("pem").to_string();
    let key = FederationKey::from_pem(&instance_config(), &pem).expect("federation key");
    (key, pem)
}

async fn get(app: &axum::Router, uri: &str) -> (StatusCode, String, String) {
    let request = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, content_type, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn the_instance_actor_publishes_the_key_the_signer_names() {
    run_db_test(|store, _app| async move {
        let (key, _pem) = key();
        let state = AppState::with_federation(store.clone(), instance_config(), Some(key));
        let app = root_router(state.clone());

        let (status, content_type, body) = get(&app, "/actor").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(content_type, "application/activity+json");
        assert!(
            !body.contains("PRIVATE"),
            "the actor document must never carry the private key: {body}"
        );

        let document: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(document["id"], "https://social.test/actor");
        assert_eq!(document["type"], "Application");
        assert_eq!(document["preferredUsername"], "instance.actor");
        assert_eq!(document["url"], "https://social.test/actor");
        assert_eq!(document["inbox"], "https://social.test/inbox");
        assert_eq!(
            document["endpoints"]["sharedInbox"],
            "https://social.test/inbox"
        );
        assert_eq!(document["publicKey"]["owner"], "https://social.test/actor");
        assert!(
            document["publicKey"]["publicKeyPem"]
                .as_str()
                .is_some_and(|pem| pem.starts_with("-----BEGIN PUBLIC KEY-----")),
            "the document has to publish a public key: {document}"
        );

        let key_id = document["publicKey"]["id"]
            .as_str()
            .expect("publicKey.id")
            .to_owned();
        assert_eq!(key_id, "https://social.test/actor#main-key");
        assert_eq!(key_id, state.federation().expect("key").key_id());

        let signed = state
            .federation()
            .expect("key")
            .signer()
            .sign(
                "GET",
                &url::Url::parse("https://remote.test/users/eve").expect("url"),
                None,
                chrono::Utc::now(),
            )
            .expect("sign");
        assert!(
            signed.signature.contains(&format!("keyId=\"{key_id}\"")),
            "the signature has to name the published key: {}",
            signed.signature
        );
        assert!(signed.digest.is_none(), "a GET carries no digest");

        let request = signed
            .apply(reqwest::Client::new().get("https://remote.test/users/eve"))
            .build()
            .expect("request");
        assert!(request.headers().contains_key("signature"));
        assert!(request.headers().contains_key("date"));
        assert!(!request.headers().contains_key("digest"));
    })
    .await;
}

#[tokio::test]
async fn an_instance_without_a_key_serves_an_actor_without_a_public_key() {
    run_db_test(|store, _app| async move {
        let state = AppState::new(store.clone(), instance_config());
        let app = root_router(state.clone());

        let (status, _content_type, body) = get(&app, "/actor").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let document: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(document["id"], "https://social.test/actor");
        assert!(state.federation().is_none());
        assert!(
            document.get("publicKey").is_none(),
            "no key is configured, so none is published: {document}"
        );
        let _unsigned = state.fediverse_client();
    })
    .await;
}
