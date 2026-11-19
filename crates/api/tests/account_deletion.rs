//! Leaving: a deletion request hides the account at once, tells the peers that know it,
//! and erases the profile only after the grace window has passed.
//!
//! The distinction these tests hold is the whole feature. "Deleted" is two states: the
//! tombstone that exists now (tokens dead, writing hidden) and the erasure that happens at
//! `purge_at`. A test that only checked the row disappeared would miss both.

use chrono::{Duration, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;

use nodus_server_store::accounts::{self, RemoteAccount};

mod support;

use support::{create_account, create_status, create_token, follow, run_db_test, send, send_anon};

/// A remote account with an inbox, the shape a follower has after an accepted follow.
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

async fn username_of(pool: &PgPool, id: &str) -> String {
    sqlx::query_scalar("SELECT username FROM account WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("username")
}

async fn identify(pool: &PgPool, id: &str, username: &str) -> String {
    let uri = format!("https://social.test/users/{username}");
    accounts::set_actor_identity(
        pool,
        id,
        &uri,
        "public-key",
        "private-key",
        &format!("{uri}/inbox"),
        Some("https://social.test/inbox"),
    )
    .await
    .expect("actor identity");
    uri
}

async fn row_state(
    pool: &PgPool,
    id: &str,
) -> (
    Option<chrono::DateTime<Utc>>,
    Option<chrono::DateTime<Utc>>,
    String,
    Option<String>,
    Option<String>,
) {
    sqlx::query_as(
        "SELECT deleted_at, purge_at, display_name, avatar_ref, uri \
           FROM account WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("account row")
}

#[tokio::test]
async fn a_delete_disables_tokens_and_hides_posts_while_the_row_waits_for_purge() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let author = create_account(&pool, "leaver").await;
        let token = create_token(&pool, &author, &["read", "write"]).await;
        let status = create_status(&pool, &author, "still here?", "public", &[], &[]).await;
        let username = username_of(&pool, &author).await;
        identify(&pool, &author, &username).await;

        let (before, _) = send_anon(&app, "GET", &format!("/api/v1/statuses/{status}")).await;
        assert_eq!(before, axum::http::StatusCode::OK);

        let (deleted, body) = send(
            &app,
            &token,
            "DELETE",
            &format!("/api/v1/accounts/{author}"),
            None,
        )
        .await;
        assert_eq!(deleted, axum::http::StatusCode::ACCEPTED, "{body}");
        let answer: Value = serde_json::from_str(&body).expect("deletion json");
        assert!(answer["deleted_at"].is_string(), "{answer}");
        assert!(answer["purge_at"].is_string(), "{answer}");

        // The token is dead and the writing is no longer served, both immediately.
        let (verify, _) = send(
            &app,
            &token,
            "GET",
            "/api/v1/accounts/verify_credentials",
            None,
        )
        .await;
        assert_eq!(verify, axum::http::StatusCode::UNAUTHORIZED);
        let (after, _) = send_anon(&app, "GET", &format!("/api/v1/statuses/{status}")).await;
        assert_eq!(after, axum::http::StatusCode::NOT_FOUND);

        // The row is a tombstone, not gone: it survives until purge_at.
        let (deleted_at, purge_at, display_name, _, uri) = row_state(&pool, &author).await;
        assert!(deleted_at.is_some());
        assert!(purge_at.is_some_and(|at| at > Utc::now()));
        assert!(
            !display_name.is_empty(),
            "the profile is erased at purge, not now"
        );
        assert!(uri.is_some(), "the tombstone keeps its actor URI");
    })
    .await;
}

#[tokio::test]
async fn a_delete_queues_one_activity_for_followers_and_every_peer_already_reached() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let author = create_account(&pool, "leaver").await;
        let token = create_token(&pool, &author, &["read", "write"]).await;
        let username = username_of(&pool, &author).await;
        let actor = format!("https://social.test/users/{username}");

        let follower = remote_follower(
            &pool,
            "follower",
            "remote.test",
            "https://remote.test/inbox",
        )
        .await;
        follow(&pool, &follower, &author).await;

        // A peer that received an earlier post but no longer follows: the delivery ledger,
        // not the follow table, is the only place that remembers it.
        sqlx::query(
            "INSERT INTO federation_delivery \
                 (id, account_id, activity_id, inbox_url, activity, host, activity_kind, delivered_at) \
             VALUES ('prior-delivery', $1, 'prior-activity', 'https://old.test/inbox', \
                     '{\"type\":\"Create\"}'::jsonb, 'old.test', 'Create', now())",
        )
        .bind(&author)
        .execute(&pool)
        .await
        .expect("prior delivery");

        let (status, body) = send(
            &app,
            &token,
            "DELETE",
            &format!("/api/v1/accounts/{author}"),
            None,
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::ACCEPTED, "{body}");

        let queued: Vec<(String, Value)> = sqlx::query_as(
            "SELECT inbox_url, activity FROM federation_delivery \
              WHERE activity_kind = 'Delete' ORDER BY inbox_url",
        )
        .fetch_all(&pool)
        .await
        .expect("queued deletes");
        assert_eq!(queued.len(), 2, "{queued:?}");
        assert_eq!(queued[0].0, "https://old.test/inbox");
        assert_eq!(queued[1].0, "https://remote.test/inbox");

        let first = &queued[0].1;
        let second = &queued[1].1;
        assert_eq!(first["type"], "Delete");
        assert_eq!(first["object"], actor);
        assert_eq!(second["type"], "Delete");
        assert_eq!(second["object"], actor);
        assert_eq!(
            first["id"], second["id"],
            "one deletion is one activity, whatever the inbox"
        );
        let id = first["id"].as_str().expect("activity id");
        assert!(id.starts_with(&format!("{actor}#activities/")), "{id}");
    })
    .await;
}

#[tokio::test]
async fn purge_erases_once_and_leaves_a_tombstone_a_stale_follow_cannot_recreate() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let author = create_account(&pool, "leaver").await;
        let username = username_of(&pool, &author).await;
        let uri = identify(&pool, &author, &username).await;
        let token = create_token(&pool, &author, &["read", "write"]).await;
        sqlx::query(
            "UPDATE account SET display_name = 'Name', note = 'bio', avatar_ref = 'avatar' \
              WHERE id = $1",
        )
        .bind(&author)
        .execute(&pool)
        .await
        .expect("profile fields");

        accounts::request_deletion(&pool, &author, Utc::now() - Duration::seconds(1))
            .await
            .expect("delete request")
            .expect("account");

        let erased = accounts::purge_due(&pool, 100).await.expect("first purge");
        assert_eq!(erased, 1);

        let (deleted_at, purge_at, display_name, avatar_ref, stored_uri) =
            row_state(&pool, &author).await;
        assert!(deleted_at.is_some());
        assert!(purge_at.is_some());
        assert_eq!(display_name, "");
        assert_eq!(avatar_ref, None);
        assert_eq!(stored_uri.as_deref(), Some(uri.as_str()));
        let credential: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM account_credential WHERE account_id = $1)",
        )
        .bind(&author)
        .fetch_one(&pool)
        .await
        .expect("credential");
        let token_left: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM oauth_token WHERE account_id = $1)")
                .bind(&author)
                .fetch_one(&pool)
                .await
                .expect("token");
        assert!(!credential && !token_left);
        drop(token);

        // Running it again has nothing left to erase, and the tombstone is still one row.
        let again = accounts::purge_due(&pool, 100).await.expect("second purge");
        assert_eq!(again, 0, "purge must be idempotent");
        assert!(accounts::by_uri(&pool, &uri)
            .await
            .expect("by uri")
            .is_some());
        assert!(accounts::local_by_username(&pool, &username)
            .await
            .expect("by name")
            .is_none());

        // A stale Follow or Undo aimed at the old actor cannot reach ingest: the inbox
        // refuses the username before a signature is even checked, and no account appears.
        let (follow_status, _) = send(
            &app,
            "no-token",
            "POST",
            &format!("/users/{username}/inbox"),
            Some(json!({
                "id": "https://remote.test/follows/stale",
                "type": "Follow",
                "actor": "https://remote.test/users/remote",
                "object": uri,
            })),
        )
        .await;
        assert_eq!(follow_status, axum::http::StatusCode::NOT_FOUND);
        let (undo_status, _) = send(
            &app,
            "no-token",
            "POST",
            &format!("/users/{username}/inbox"),
            Some(json!({
                "id": "https://remote.test/undos/stale",
                "type": "Undo",
                "actor": "https://remote.test/users/remote",
                "object": "https://remote.test/follows/stale",
            })),
        )
        .await;
        assert_eq!(undo_status, axum::http::StatusCode::NOT_FOUND);
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM account WHERE uri = $1")
            .bind(&uri)
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(rows, 1, "a stale activity must not mint a second account");
    })
    .await;
}

#[tokio::test]
async fn undelete_inside_the_window_restores_visibility_but_not_the_old_token() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let author = create_account(&pool, "leaver").await;
        let old_token = create_token(&pool, &author, &["read", "write"]).await;
        let status = create_status(&pool, &author, "back soon", "public", &[], &[]).await;

        let (deleted, body) = send(
            &app,
            &old_token,
            "DELETE",
            &format!("/api/v1/accounts/{author}"),
            None,
        )
        .await;
        assert_eq!(deleted, axum::http::StatusCode::ACCEPTED, "{body}");

        let (old_verify, _) = send(
            &app,
            &old_token,
            "GET",
            "/api/v1/accounts/verify_credentials",
            None,
        )
        .await;
        assert_eq!(old_verify, axum::http::StatusCode::UNAUTHORIZED);

        // A token minted after the deletion stands in for proving the account again:
        // the revoked bearer cannot undo what a thief used it to do.
        let new_token = create_token(&pool, &author, &["read", "write"]).await;
        let (restored, body) = send(
            &app,
            &new_token,
            "POST",
            &format!("/api/v1/accounts/{author}/undelete"),
            None,
        )
        .await;
        assert_eq!(restored, axum::http::StatusCode::OK, "{body}");

        let (after_undelete, _) =
            send_anon(&app, "GET", &format!("/api/v1/statuses/{status}")).await;
        assert_eq!(after_undelete, axum::http::StatusCode::OK);
        let (still_dead, _) = send(
            &app,
            &old_token,
            "GET",
            "/api/v1/accounts/verify_credentials",
            None,
        )
        .await;
        assert_eq!(still_dead, axum::http::StatusCode::UNAUTHORIZED);
        let (new_works, _) = send(
            &app,
            &new_token,
            "GET",
            "/api/v1/accounts/verify_credentials",
            None,
        )
        .await;
        assert_eq!(new_works, axum::http::StatusCode::OK);
    })
    .await;
}
