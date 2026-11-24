//! Account migration: aliases, the Move redirect, and the consent that gates it.
//!
//! A Move is a redirect, not a deletion: the old profile keeps answering, now with
//! `movedTo`, and only a target that already lists the mover in `alsoKnownAs` may be
//! moved to. These tests pin the four refusals, the redirect on both the account document
//! and a status's author, and both directions of that consent rule.

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{create_account, create_status, create_token, json_of, run_db_test, send, send_anon};

const MOVE: &str = "/api/v1/accounts/move";
const ALIASES: &str = "/api/v1/accounts/aliases";

async fn username(store: &nodus_server_store::Store, id: &str) -> String {
    store
        .account(id)
        .await
        .expect("read account")
        .expect("account exists")
        .username
}

fn refusal(body: &str) -> String {
    json_of(body)["error"]
        .as_str()
        .unwrap_or_else(|| panic!("no error sentence in {body}"))
        .to_owned()
}

#[tokio::test]
async fn moving_to_yourself_is_refused() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "selfmove").await;
        let name = username(&store, &account).await;
        let token = create_token(&pool, &account, &["write:accounts"]).await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            MOVE,
            Some(json!({ "acct": format!("@{name}@social.test") })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body was {body}");
        assert_eq!(refusal(&body), "You cannot move to the same account");
    })
    .await;
}

#[tokio::test]
async fn an_unknown_target_is_refused() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "stranger").await;
        let token = create_token(&pool, &account, &["write:accounts"]).await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            MOVE,
            Some(json!({ "acct": "@nobody@elsewhere.test" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body was {body}");
        assert_eq!(refusal(&body), "This instance does not know that account");
    })
    .await;
}

#[tokio::test]
async fn a_target_that_has_not_listed_you_refuses_the_move() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let source = create_account(&pool, "unlisted").await;
        let target = create_account(&pool, "target").await;
        let target_name = username(&store, &target).await;
        let token = create_token(&pool, &source, &["write:accounts"]).await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            MOVE,
            Some(json!({ "acct": format!("@{target_name}@social.test") })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body was {body}");
        assert!(
            refusal(&body).contains("has not listed you in also_known_as"),
            "body was {body}"
        );
        // The refusal must not half-apply: the source still points nowhere.
        let row = store
            .account(&source)
            .await
            .expect("read source")
            .expect("source");
        assert_eq!(row.moved_to, None);
    })
    .await;
}

#[tokio::test]
async fn a_target_that_lists_you_accepts_the_move() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let source = create_account(&pool, "mover").await;
        let target = create_account(&pool, "heir").await;
        let source_name = username(&store, &source).await;
        let target_name = username(&store, &target).await;
        let source_token = create_token(&pool, &source, &["write:accounts", "read:accounts"]).await;
        let target_token = create_token(&pool, &target, &["write:accounts", "read:accounts"]).await;

        // The target opts in by naming the source, exactly as a peer publishes
        // `alsoKnownAs`.
        let (status, body) = send(
            &app,
            &target_token,
            "POST",
            ALIASES,
            Some(json!({ "acct": format!("@{source_name}@social.test") })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let alias = json_of(&body);
        assert_eq!(alias["accounts"][0]["id"], json!(source), "body was {body}");

        let (status, body) = send(
            &app,
            &source_token,
            "POST",
            MOVE,
            Some(json!({ "acct": format!("@{target_name}@social.test") })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let moved = json_of(&body);
        assert_eq!(
            moved["moved"]["uri"],
            json!(format!("https://social.test/users/{target_name}")),
            "body was {body}"
        );
        assert_eq!(moved["moved_to"], moved["moved"], "both spellings agree");
        assert_eq!(
            moved["moved"]["acct"],
            json!(format!("{target_name}@social.test"))
        );

        // The public account document carries the redirect, not only the write's answer.
        let (status, body) = send_anon(&app, "GET", &format!("/api/v1/accounts/{source}")).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let profile = json_of(&body);
        assert_eq!(
            profile["moved_to"]["uri"],
            json!(format!("https://social.test/users/{target_name}")),
            "body was {body}"
        );

        // A status's author document is a second, independent builder of the same shape.
        let status_id = create_status(&pool, &source, "still here", "public", &[], &[]).await;
        let (status, body) = send_anon(&app, "GET", &format!("/api/v1/statuses/{status_id}")).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let status = json_of(&body);
        assert_eq!(
            status["account"]["moved_to"]["uri"],
            json!(format!("https://social.test/users/{target_name}")),
            "body was {body}"
        );

        // The ActivityPub profile publishes the same redirect, and the target publishes
        // the consent that allowed it, so a peer can check both without a second fetch.
        let (status, body) = send_anon(&app, "GET", &format!("/users/{source_name}")).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(
            json_of(&body)["movedTo"],
            json!(format!("https://social.test/users/{target_name}")),
            "body was {body}"
        );
        let (status, body) = send_anon(&app, "GET", &format!("/users/{target_name}")).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(
            json_of(&body)["alsoKnownAs"],
            json!([format!("https://social.test/users/{source_name}")]),
            "body was {body}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_second_move_is_refused() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let source = create_account(&pool, "twice").await;
        let target = create_account(&pool, "first").await;
        let source_name = username(&store, &source).await;
        let target_name = username(&store, &target).await;
        let source_token = create_token(&pool, &source, &["write:accounts", "read:accounts"]).await;
        let target_token = create_token(&pool, &target, &["write:accounts", "read:accounts"]).await;

        let (status, body) = send(
            &app,
            &target_token,
            "POST",
            ALIASES,
            Some(json!({ "acct": format!("@{source_name}@social.test") })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");

        let (status, body) = send(
            &app,
            &source_token,
            "POST",
            MOVE,
            Some(json!({ "acct": format!("@{target_name}@social.test") })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");

        let (status, body) = send(
            &app,
            &source_token,
            "POST",
            MOVE,
            Some(json!({ "acct": format!("@{target_name}@social.test") })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body was {body}");
        assert_eq!(refusal(&body), "This account has already moved");
    })
    .await;
}

#[tokio::test]
async fn a_known_remote_target_can_be_moved_to() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let source = create_account(&pool, "localmover").await;
        let source_name = username(&store, &source).await;
        let token = create_token(&pool, &source, &["write:accounts"]).await;

        let remote = nodus_server_store::accounts::upsert_remote(
            &pool,
            &nodus_server_store::accounts::RemoteAccount {
                uri: "https://remote.test/users/remote_heir",
                username: "remote_heir",
                domain: "remote.test",
                display_name: "Remote Heir",
                note: "",
                avatar_url: None,
                header_url: None,
                inbox_url: Some("https://remote.test/users/remote_heir/inbox"),
                shared_inbox_url: None,
                public_key_pem: None,
                locked: false,
                bot: false,
            },
        )
        .await
        .expect("insert remote target");
        nodus_server_store::accounts::set_also_known_as(
            &pool,
            "https://remote.test/users/remote_heir",
            &[format!("https://social.test/users/{source_name}")],
        )
        .await
        .expect("record consent");

        let (status, body) = send(
            &app,
            &token,
            "POST",
            MOVE,
            Some(json!({ "acct": "@remote_heir@remote.test" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(
            json_of(&body)["moved_to"]["uri"],
            json!("https://remote.test/users/remote_heir"),
            "body was {body}"
        );
        let moved = store
            .account(&source)
            .await
            .expect("read source")
            .expect("source");
        assert_eq!(moved.moved_to.as_deref(), remote.uri.as_deref());
    })
    .await;
}

#[tokio::test]
async fn aliases_are_listed_and_removed() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let source = create_account(&pool, "aliases").await;
        let target = create_account(&pool, "destination").await;
        let target_name = username(&store, &target).await;
        let token = create_token(&pool, &source, &["write:accounts", "read:accounts"]).await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            ALIASES,
            Some(json!({ "acct": format!("@{target_name}@social.test") })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");

        let (status, body) = send(&app, &token, "GET", ALIASES, None).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let aliases = json_of(&body);
        assert_eq!(aliases.as_array().map(Vec::len), Some(1), "body was {body}");
        assert_eq!(aliases[0]["id"], json!(target), "body was {body}");

        let (status, body) =
            send(&app, &token, "DELETE", &format!("{ALIASES}/{target}"), None).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "body was {body}");

        let (status, body) = send(&app, &token, "GET", ALIASES, None).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(json_of(&body), json!([]));
    })
    .await;
}
