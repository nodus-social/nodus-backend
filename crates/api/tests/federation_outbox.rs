//! What we owe other instances: the queue and the worker that drains it.
//!
//! These tests hold the two halves apart on purpose. One checks that an action taken here
//! writes the activity down for the right inboxes; the other points a queued delivery at a
//! stub server and checks that what arrives is signed, addressed and then marked done.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use serde_json::{json, Value};
use sqlx::PgPool;

use nodus_server_api::state::AppState;
use nodus_server_store::accounts::{self, RemoteAccount};

mod support;

use support::{create_account, create_token, instance_config, run_db_test, send};

/// A throwaway keypair for the delivery test: signing only needs a real key, and a test
/// that shipped its own would still be signing with something no peer ever trusted.
const TEST_PRIVATE_KEY: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCSI2vMOd4jjzdv\n\
OqnyqNI0mDuWtbI8FQMUnkjrchOqeGJwym94955BGCA/Tlu1jDIVfO40Rfx1Iere\n\
jGB3d8+Myt+db/dOHXEOkDN6DnM7v54vIKcT1CUQ77mNEueMeMWRQsyEiGqdliqZ\n\
sO4QFJUsSC6Jbx17qrdOSkYOmP/JVtaPBBobEV/1w/rNqlhWgwdB0DNWx1RuOKUb\n\
zpTSay0BfBOus4XF98syMWLkqci3n86tTG7mehc/y2/dTLnjmVpbR675TRp7CXjy\n\
SkWuXqW3ADbU+KQHGfpOuCH25TP1SZAjPs175le0PXxsF+K2Uo95I/QNmW6lf5Ww\n\
e/isyn99AgMBAAECggEAFcGJi4Pp8D1NXBUjC+naMX5LEMAdYsMgtvHBmrEHAHqf\n\
nSRmErTlLdJbqqZjEioRorql88j03Aif9gshVBKAJvkPmq6lO084GkTu2khLG3qx\n\
dVlVG6dE8A/gUyzx+oBYWVcqf2iXsWeTvAG9JKO2eZCIF78fvTNzIAgABK2pFt4f\n\
EU/eunCSDX1wPj0uVvIcf0XdS9bwt3VsQsdgAH6OBP8mM0kPCAsm1sT/Pc9L8WZY\n\
J45zpePfVDMdmQzsXWW1uPy7lxG2nd9x54JsT3RPO5blSQaKXR8wrVNnpL15ukvO\n\
Q7Bulv06gA7SZm35lt1ieOkM6PeqU9hmn5ptik87+QKBgQDJWMPt9X6pS+L+fxPo\n\
UyeXykxPSzLPvlBFBBIUICYC12C1gXAmZd9yuNN+xDDVWJEHhrIwfHwTN81x8EuU\n\
Upa8Jymrt9qrxWDRxBJppfyew0+bLp8YpBqNb/W/fJ7Vi/CRTD4rM4ZXVoV14MAm\n\
u3UlXhaqGjepYbFDyX/8p2mVlwKBgQC5zlJdB5eZNHdfveOLxSSGMCMXRT8AVG/O\n\
5rcGTltiSqWc+vUNGPvqONwCqiziEhWBtXs3QC5DNikCxE2+UYLcFzDETlbxWmHe\n\
FNQJHRhU3YYUKArYWCEV9G4dw5c9sHvO1jJx2B02MPBWuzEcW6jHrorIj0IgwzNp\n\
x3h2+P2+CwKBgClvggrDfch7XICBSGiETF6ZfDDJSfCkusIpP0sy/n+RMU7JD3pn\n\
dp+WV7f7ygztyBLjbmI6DBKsZjQvfm5MvMaFzLaRBIha+zzP+/YP+bf2e7h01Lru\n\
cqRuyQUaMVnDDcPpC9Y6KUhp/tcuZHzUERyai1GASboq558KpbMqBLmLAoGBAKGF\n\
LO44Kl4BUQCGpuca8pw//lE9Xf4gaK24vEQcG66/a2aidiHzpRJAaWlbm/bOd6mx\n\
JLKr9UtyKoaANYELhLFk63zLCSN4SXlwK77cbwlfJS4ifQMC4YgfWxY+sBvtbkMo\n\
yuNSVlqEgnky8wdO2tLy9SxR9M9cQTZkM2FhI9tvAoGAPP0iUPwESK6xNJxhrdEy\n\
1Xqp25TxWYcvTpnZ3UNZyIDrXqXRmx9OgTUmkPV4beIRQ3kG1m2d28GZFTeiMZ21\n\
m4EnFoyE8MFXyjHeuoWo05BewL0DayNAhzjQbbFW4gilW7ivHJ7lwlyMt79Ko3FX\n\
1/Lbpa+LJdioyMZEswXoDMA=\n\
-----END PRIVATE KEY-----";
const TEST_PUBLIC_KEY: &str = "\
-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkiNrzDneI483bzqp8qjS\n\
NJg7lrWyPBUDFJ5I63ITqnhicMpvePeeQRggP05btYwyFXzuNEX8dSHq3oxgd3fP\n\
jMrfnW/3Th1xDpAzeg5zO7+eLyCnE9QlEO+5jRLnjHjFkULMhIhqnZYqmbDuEBSV\n\
LEguiW8de6q3TkpGDpj/yVbWjwQaGxFf9cP6zapYVoMHQdAzVsdUbjilG86U0mst\n\
AXwTrrOFxffLMjFi5KnIt5/OrUxu5noXP8tv3Uy545laW0eu+U0aewl48kpFrl6l\n\
twA21PikBxn6Trgh9uUz9UmQIz7Ne+ZXtD18bBfitlKPeSP0DZlupX+VsHv4rMp/\n\
fQIDAQAB\n\
-----END PUBLIC KEY-----";

/// The name an account was created with, for actor URLs.
async fn username_of(pool: &PgPool, id: &str) -> String {
    let username: String = sqlx::query_scalar("SELECT username FROM account WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("username");
    username
}

/// A local account that can sign: peers need an actor id and a private key.
async fn signing_account(pool: &PgPool, label: &str) -> String {
    let id = create_account(pool, label).await;
    let username = username_of(pool, &id).await;
    accounts::set_actor_identity(
        pool,
        &id,
        &format!("https://social.test/users/{username}"),
        TEST_PUBLIC_KEY,
        TEST_PRIVATE_KEY,
        "https://social.test/inbox",
        None,
    )
    .await
    .expect("actor identity");
    id
}

/// A follower on another instance, with a shared inbox of its own.
async fn remote_follower(pool: &PgPool, label: &str, shared_inbox: &str) -> String {
    let account = accounts::upsert_remote(
        pool,
        &RemoteAccount {
            uri: &format!("https://remote.test/users/{label}"),
            username: label,
            domain: "remote.test",
            display_name: label,
            note: "",
            avatar_url: None,
            header_url: None,
            inbox_url: Some(&format!("https://remote.test/users/{label}/inbox")),
            shared_inbox_url: Some(shared_inbox),
            public_key_pem: None,
            locked: false,
            bot: false,
        },
    )
    .await
    .expect("remote account");
    account.id
}

#[tokio::test]
async fn a_post_is_queued_once_per_follower_inbox() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let author = signing_account(&pool, "author").await;
        let token = create_token(&pool, &author, &["read", "write"]).await;
        // Two followers on the same instance: one shared inbox, so one delivery.
        let first = remote_follower(&pool, "first", "https://remote.test/inbox").await;
        let second = remote_follower(&pool, "second", "https://remote.test/inbox").await;
        support::follow(&pool, &first, &author).await;
        support::follow(&pool, &second, &author).await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/statuses",
            Some(json!({ "status": "hello peers", "visibility": "public" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let queued: Vec<(String, Value)> = sqlx::query_as(
            "SELECT inbox_url, activity FROM federation_delivery ORDER BY inbox_url",
        )
        .fetch_all(&pool)
        .await
        .expect("queued deliveries");
        assert_eq!(queued.len(), 1, "one inbox, one delivery: {queued:?}");
        let (inbox, activity) = &queued[0];
        assert_eq!(inbox, "https://remote.test/inbox");
        assert_eq!(activity["type"], "Create");
        assert_eq!(activity["object"]["type"], "Note");
        assert!(activity["id"].as_str().is_some_and(|id| !id.is_empty()));
        assert_eq!(
            activity["actor"],
            format!(
                "https://social.test/users/{}",
                username_of(&pool, &author).await
            )
        );
    })
    .await;
}

#[tokio::test]
async fn a_private_post_reaches_followers_and_is_not_addressed_to_the_public() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let author = signing_account(&pool, "author").await;
        let username = username_of(&pool, &author).await;
        let token = create_token(&pool, &author, &["read", "write"]).await;
        let follower = remote_follower(&pool, "follower", "https://remote.test/inbox").await;
        support::follow(&pool, &follower, &author).await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/statuses",
            Some(json!({ "status": "not for everyone", "visibility": "private" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let queued: Vec<(String, Value)> =
            sqlx::query_as("SELECT inbox_url, activity FROM federation_delivery")
                .fetch_all(&pool)
                .await
                .expect("queued deliveries");
        assert_eq!(queued.len(), 1, "a private post goes to followers only");
        let (inbox, activity) = &queued[0];
        assert_eq!(inbox, "https://remote.test/inbox");
        assert_eq!(
            activity["object"]["to"],
            json!([format!("https://social.test/users/{username}/followers")])
        );
        assert_eq!(activity["object"]["cc"], json!([]));
        assert!(
            !activity
                .to_string()
                .contains("https://www.w3.org/ns/activitystreams#Public"),
            "a private post must not advertise the public collection: {activity}"
        );
    })
    .await;
}

#[derive(Clone)]
struct Stub {
    seen: Arc<Mutex<Vec<(HeaderMap, String)>>>,
}

async fn record(State(stub): State<Stub>, headers: HeaderMap, body: String) -> impl IntoResponse {
    stub.seen.lock().expect("lock").push((headers, body));
    StatusCode::ACCEPTED
}

#[tokio::test]
async fn a_queued_activity_arrives_signed_and_is_marked_delivered() {
    run_db_test(|store, _app| async move {
        let pool = store.pool().clone();
        let author = signing_account(&pool, "author").await;
        let username = username_of(&pool, &author).await;

        let stub = Stub {
            seen: Arc::new(Mutex::new(Vec::new())),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let router = Router::new()
            .route("/inbox", post(record))
            .with_state(stub.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        let activity = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://social.test/users/x#follows/1",
            "type": "Follow",
            "actor": format!("https://social.test/users/{username}"),
            "object": "https://remote.test/users/first",
        });
        let inbox = format!("http://{address}/inbox");
        let queued = nodus_server_store::delivery::enqueue(
            &pool,
            &author,
            &activity,
            std::slice::from_ref(&inbox),
        )
        .await
        .expect("enqueue");
        assert_eq!(queued, 1);

        let state = AppState::new(store.clone(), instance_config());
        assert!(
            nodus_server_api::outbox::deliver_once(&state)
                .await
                .expect("delivery"),
            "there was work to do"
        );

        let seen = stub.seen.lock().expect("lock").clone();
        assert_eq!(seen.len(), 1, "the stub should have been posted to once");
        let (headers, body) = &seen[0];
        let signature = headers
            .get("signature")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert!(
            signature.contains(&format!(
                "keyId=\"https://social.test/users/{username}#main-key\""
            )),
            "the signature has to name the key that signed it: {signature}"
        );
        assert!(
            signature.contains("algorithm=\"rsa-sha256\""),
            "{signature}"
        );
        assert!(
            signature.contains("headers=\"(request-target) host date digest\""),
            "{signature}"
        );
        assert!(
            headers.get("digest").is_some(),
            "the body is pinned by a digest"
        );
        let received: Value = serde_json::from_str(body).expect("json body");
        assert_eq!(received["type"], "Follow");

        let pending = nodus_server_store::delivery::pending(&pool, 10)
            .await
            .expect("pending");
        assert!(pending.is_empty(), "a delivered activity is no longer owed");
    })
    .await;
}

#[tokio::test]
async fn a_failed_delivery_keeps_its_error_and_waits() {
    run_db_test(|store, _app| async move {
        let pool = store.pool().clone();
        let author = signing_account(&pool, "author").await;
        let activity = json!({
            "id": "https://social.test/users/x#follows/2",
            "type": "Follow",
            "actor": "x",
            "object": "y",
        });
        // Nothing listens on this port, so the attempt fails the way a peer that is down
        // fails ours.
        let inbox = "http://127.0.0.1:9/inbox".to_owned();
        nodus_server_store::delivery::enqueue(&pool, &author, &activity, &[inbox])
            .await
            .expect("enqueue");

        let state = AppState::new(store.clone(), instance_config());
        assert!(nodus_server_api::outbox::deliver_once(&state)
            .await
            .expect("delivery"));

        let pending = nodus_server_store::delivery::pending(&pool, 10)
            .await
            .expect("pending");
        assert_eq!(pending.len(), 1, "a failed delivery stays owed");
        assert_eq!(pending[0].attempts, 1);
        assert!(
            pending[0].last_error.is_some(),
            "the reason has to be readable later"
        );
    })
    .await;
}
