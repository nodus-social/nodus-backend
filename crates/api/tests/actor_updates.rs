//! A profile edit is only real to the rest of the network once it is announced.
//!
//! Peers cache the actor document they fetched, so a change to its name, summary, avatar or
//! header is invisible until this instance sends an `Update` whose object is that document.
//! These tests hold the queue to the promise: one activity per follower inbox, one per burst
//! of saves, and nothing at all to a host this instance blocked or paused.

use rsa::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _, LineEnding};
use rsa::rand_core::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use sqlx::PgPool;

use nodus_server_store::accounts::{self, RemoteAccount};
use nodus_server_store::{moderation, pauses};

mod support;

use support::{create_account, create_token, follow, run_db_test, send};

fn keypair() -> (String, String) {
    let private = RsaPrivateKey::new(&mut OsRng, 1024).expect("rsa key");
    let public = RsaPublicKey::from(&private)
        .to_public_key_pem(LineEnding::LF)
        .expect("public key pem");
    let secret = private
        .to_pkcs8_pem(LineEnding::LF)
        .expect("private key pem")
        .to_string();
    (public, secret)
}

/// A local account with the actor identity its queued activity will be signed with.
async fn profile_account(pool: &PgPool, label: &str) -> String {
    let id = create_account(pool, label).await;
    let username: String = sqlx::query_scalar("SELECT username FROM account WHERE id = $1")
        .bind(&id)
        .fetch_one(pool)
        .await
        .expect("username");
    let (public, secret) = keypair();
    accounts::set_actor_identity(
        pool,
        &id,
        &format!("https://social.test/users/{username}"),
        &public,
        &secret,
        "https://social.test/inbox",
        None,
    )
    .await
    .expect("actor identity");
    id
}

async fn remote_follower(pool: &PgPool, label: &str, domain: &str, shared_inbox: &str) -> String {
    let account = accounts::upsert_remote(
        pool,
        &RemoteAccount {
            uri: &format!("https://{domain}/users/{label}"),
            username: label,
            domain,
            display_name: label,
            note: "",
            avatar_url: None,
            header_url: None,
            inbox_url: Some(&format!("https://{domain}/users/{label}/inbox")),
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

async fn edit(app: &axum::Router, token: &str, body: Value) {
    let (status, text) = send(
        app,
        token,
        "PATCH",
        "/api/v1/accounts/update_credentials",
        Some(body),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{text}");
}

async fn queued_actor_updates(pool: &PgPool) -> Vec<(String, Value)> {
    sqlx::query_as(
        "SELECT inbox_url, activity FROM federation_delivery \
          WHERE activity_kind = 'Update' AND activity->'object'->>'type' = 'Person' \
          ORDER BY inbox_url",
    )
    .fetch_all(pool)
    .await
    .expect("queued actor updates")
}

#[tokio::test]
async fn an_edit_queues_one_update_for_the_follower_inbox() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let author = profile_account(&pool, "author").await;
        let token = create_token(&pool, &author, &["read", "write"]).await;
        let first =
            remote_follower(&pool, "first", "remote.test", "https://remote.test/inbox").await;
        let second =
            remote_follower(&pool, "second", "remote.test", "https://remote.test/inbox").await;
        follow(&pool, &first, &author).await;
        follow(&pool, &second, &author).await;

        edit(&app, &token, json!({ "display_name": "Lux" })).await;

        let queued = queued_actor_updates(&pool).await;
        assert_eq!(
            queued.len(),
            1,
            "two followers, one shared inbox: {queued:?}"
        );
        let (inbox, activity) = &queued[0];
        assert_eq!(inbox, "https://remote.test/inbox");
        assert_eq!(activity["type"], "Update");
        assert_eq!(activity["object"]["type"], "Person");
    })
    .await;
}

#[tokio::test]
async fn a_second_edit_inside_the_window_reuses_the_queued_update() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let author = profile_account(&pool, "author").await;
        let token = create_token(&pool, &author, &["read", "write"]).await;
        let follower = remote_follower(
            &pool,
            "follower",
            "remote.test",
            "https://remote.test/inbox",
        )
        .await;
        follow(&pool, &follower, &author).await;

        edit(&app, &token, json!({ "display_name": "First name" })).await;
        edit(
            &app,
            &token,
            json!({ "display_name": "Second name", "note": "new bio" }),
        )
        .await;

        let queued = queued_actor_updates(&pool).await;
        assert_eq!(queued.len(), 1, "a burst is one activity: {queued:?}");
        assert_eq!(queued[0].1["object"]["name"], "Second name");
        assert_eq!(queued[0].1["object"]["summary"], "new bio");

        // The queued row is the thing the window measures: an edit after it has aged out is
        // a new activity, not a rewrite of the one followers already have.
        sqlx::query(
            "UPDATE federation_delivery SET created_at = now() - interval '61 seconds' \
              WHERE activity_kind = 'Update'",
        )
        .execute(&pool)
        .await
        .expect("age the queued update");

        edit(&app, &token, json!({ "display_name": "Third name" })).await;
        let queued = queued_actor_updates(&pool).await;
        assert_eq!(
            queued.len(),
            2,
            "outside the window is a new update: {queued:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_blocked_or_paused_follower_domain_gets_nothing() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let author = profile_account(&pool, "author").await;
        let token = create_token(&pool, &author, &["read", "write"]).await;
        let blocked = remote_follower(
            &pool,
            "blocked",
            "blocked.test",
            "https://blocked.test/inbox",
        )
        .await;
        let paused =
            remote_follower(&pool, "paused", "paused.test", "https://paused.test/inbox").await;
        follow(&pool, &blocked, &author).await;
        follow(&pool, &paused, &author).await;

        moderation::create_block(
            &pool,
            &moderation::NewDomainBlock {
                domain: "blocked.test",
                severity: "suspend",
                reject_media: true,
                reject_reports: true,
                obfuscate: false,
                public_comment: "blocked",
            },
        )
        .await
        .expect("block the domain");
        pauses::upsert(
            &pool,
            &pauses::NewDomainPause {
                domain: "paused.test",
                reason: "under review",
                expires_at: None,
                created_by: None,
            },
        )
        .await
        .expect("pause the domain");

        edit(&app, &token, json!({ "display_name": "Changed" })).await;

        let queued = queued_actor_updates(&pool).await;
        assert!(
            queued.is_empty(),
            "nothing is announced to a closed host: {queued:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn the_object_is_the_actor_document_and_carries_the_changed_field() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let author = profile_account(&pool, "author").await;
        let token = create_token(&pool, &author, &["read", "write"]).await;
        let follower = remote_follower(
            &pool,
            "follower",
            "remote.test",
            "https://remote.test/inbox",
        )
        .await;
        follow(&pool, &follower, &author).await;

        edit(
            &app,
            &token,
            json!({ "display_name": "A new name", "note": "<p>A new bio</p>" }),
        )
        .await;

        let queued = queued_actor_updates(&pool).await;
        assert_eq!(queued.len(), 1, "{queued:?}");
        let activity = &queued[0].1;
        let object = &activity["object"];
        assert_eq!(object["type"], "Person");
        assert_eq!(object["name"], "A new name");
        assert_eq!(object["summary"], "<p>A new bio</p>");
        assert!(
            object["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("https://social.test/users/")),
            "the object is the actor, not a patch: {object}"
        );
        assert_eq!(
            activity["cc"],
            json!([format!(
                "{}/followers",
                object["id"].as_str().unwrap_or_default()
            )])
        );
    })
    .await;
}
