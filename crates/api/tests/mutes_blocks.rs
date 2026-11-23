//! The mute and block verbs, the lists they feed, and the relationship they answer.
//!
//! Mastodon posts `POST /api/v1/accounts/{id}/{mute,unmute,block,unblock}` and reads the
//! result as a relationship object; the two list routes are the only other way a client
//! sees the same state. Mute takes an optional body (`{"notifications": bool, "duration":
//! seconds}`), a body of `{}`, or no body at all, and an empty body must not be a 415.

mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};

use support::{
    create_account, create_token, expect_ok, follow, json_of, run_db_test, send, send_anon,
    send_form,
};

async fn listed(app: &axum::Router, token: &str, path: &str) -> Vec<String> {
    let (status, body) = send(app, token, "GET", path, None).await;
    let body = expect_ok(status, &body, &format!("GET {path}"));
    json_of(&body)
        .as_array()
        .expect("a list of accounts")
        .iter()
        .filter_map(|account| account["id"].as_str().map(str::to_owned))
        .collect()
}

async fn relationship_of(app: &axum::Router, token: &str, target: &str) -> Value {
    let (status, body) = send(
        app,
        token,
        "GET",
        &format!("/api/v1/accounts/relationships?id[]={target}"),
        None,
    )
    .await;
    let body = expect_ok(status, &body, "GET …/accounts/relationships");
    let relationships = json_of(&body);
    relationships[0].clone()
}

#[tokio::test]
async fn mute_answers_the_relationship_and_feeds_the_mute_list() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let target = create_account(&pool, "target").await;
        let token = create_token(&pool, &reader, &["read", "write"]).await;

        // `{}` is a body with no members: mute with the defaults.
        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/accounts/{target}/mute"),
            Some(json!({})),
        )
        .await;
        let body = expect_ok(status, &body, "POST …/mute with {}");
        let relationship = json_of(&body);
        assert_eq!(
            relationship["id"], target,
            "the relationship names the target"
        );
        assert_eq!(relationship["muting"], true, "mute reports itself");
        assert_eq!(
            relationship["muting_notifications"], true,
            "an absent `notifications` defaults to true"
        );
        assert_eq!(relationship["blocking"], false, "a mute is not a block");
        assert!(
            listed(&app, &token, "/api/v1/mutes")
                .await
                .contains(&target),
            "the mute list names the muted account"
        );

        // No body at all is the shape the pinned client posts; it must not be a 415.
        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/accounts/{target}/mute"),
            None,
        )
        .await;
        let body = expect_ok(status, &body, "POST …/mute with no body");
        assert_eq!(json_of(&body)["muting"], true, "a bodiless mute took");

        // A form body is the other encoding Mastodon clients use.
        let (status, body) = send_form(
            &app,
            &token,
            "POST",
            &format!("/api/v1/accounts/{target}/mute"),
            &[("notifications", "false")],
        )
        .await;
        let body = expect_ok(status, &body, "POST …/mute as a form");
        assert_eq!(
            json_of(&body)["muting_notifications"],
            false,
            "the form's `notifications=false` is honoured"
        );

        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/accounts/{target}/unmute"),
            None,
        )
        .await;
        let body = expect_ok(status, &body, "POST …/unmute");
        let relationship = json_of(&body);
        assert_eq!(relationship["muting"], false, "unmute reports itself");
        assert_eq!(relationship["blocking"], false, "unmute is not an unblock");
        assert!(
            listed(&app, &token, "/api/v1/mutes").await.is_empty(),
            "the mute list is empty after unmute"
        );

        // Unmuting what was never muted is a no-op, not a 500.
        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/accounts/{target}/unmute"),
            None,
        )
        .await;
        expect_ok(status, &body, "second POST …/unmute");
    })
    .await;
}

#[tokio::test]
async fn mute_accepts_duration_and_reports_no_expiry() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let target = create_account(&pool, "target").await;
        let token = create_token(&pool, &reader, &["read", "write"]).await;

        // `account_relation` has no expiry column, so a timed mute is stored as an
        // indefinite one and `/api/v1/mutes` must not invent an `expires_at`.
        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/accounts/{target}/mute"),
            Some(json!({ "notifications": true, "duration": 300 })),
        )
        .await;
        let body = expect_ok(status, &body, "POST …/mute with duration");
        let relationship = json_of(&body);
        assert_eq!(relationship["muting"], true, "a timed mute still mutes");
        assert!(
            relationship.get("expires_at").is_none(),
            "the relationship does not claim an expiry we do not store"
        );

        let (status, body) = send(&app, &token, "GET", "/api/v1/mutes", None).await;
        let body = expect_ok(status, &body, "GET /api/v1/mutes");
        let mutes = json_of(&body);
        assert!(
            mutes[0].get("expires_at").is_none(),
            "the mute list does not claim an expiry we do not store"
        );
    })
    .await;
}

#[tokio::test]
async fn block_answers_the_relationship_feeds_the_block_list_and_drops_follows() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let target = create_account(&pool, "target").await;
        let token = create_token(&pool, &reader, &["read", "write"]).await;
        follow(&pool, &reader, &target).await;
        follow(&pool, &target, &reader).await;
        let both_ways = relationship_of(&app, &token, &target).await;
        assert_eq!(
            both_ways["following"], true,
            "the reader follows the target"
        );
        assert_eq!(
            both_ways["followed_by"], true,
            "the target follows the reader"
        );

        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/accounts/{target}/block"),
            None,
        )
        .await;
        let body = expect_ok(status, &body, "POST …/block");
        let relationship = json_of(&body);
        assert_eq!(
            relationship["id"], target,
            "the relationship names the target"
        );
        assert_eq!(relationship["blocking"], true, "block reports itself");
        assert_eq!(relationship["muting"], false, "a block is not a mute");
        assert_eq!(
            relationship["following"], false,
            "block drops the outbound follow"
        );
        assert_eq!(
            relationship["followed_by"], false,
            "block drops the inbound follow"
        );

        let proven = relationship_of(&app, &token, &target).await;
        assert_eq!(proven["following"], false, "the stored follow is gone");
        assert_eq!(proven["followed_by"], false, "the reverse follow is gone");
        assert!(
            listed(&app, &token, "/api/v1/blocks")
                .await
                .contains(&target),
            "the block list names the blocked account"
        );

        // Blocking again is idempotent.
        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/accounts/{target}/block"),
            None,
        )
        .await;
        let body = expect_ok(status, &body, "second POST …/block");
        assert_eq!(
            json_of(&body)["blocking"],
            true,
            "a repeated block is idempotent"
        );

        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/accounts/{target}/unblock"),
            None,
        )
        .await;
        let body = expect_ok(status, &body, "POST …/unblock");
        let relationship = json_of(&body);
        assert_eq!(relationship["blocking"], false, "unblock reports itself");
        assert_eq!(relationship["muting"], false, "unblock is not an unmute");
        assert!(
            listed(&app, &token, "/api/v1/blocks").await.is_empty(),
            "the block list is empty after unblock"
        );

        // Unblocking what was never blocked is a no-op, not a 500.
        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/accounts/{target}/unblock"),
            None,
        )
        .await;
        expect_ok(status, &body, "second POST …/unblock");
    })
    .await;
}

#[tokio::test]
async fn blocking_or_muting_yourself_is_refused_by_name() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let token = create_token(&pool, &reader, &["read", "write"]).await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/accounts/{reader}/block"),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "self-block is a 422"
        );
        let error = json_of(&body)["error"]
            .as_str()
            .expect("an error message")
            .to_owned();
        assert!(
            error.contains("block") && error.contains("yourself"),
            "the message names the reason: {error}"
        );

        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/accounts/{reader}/mute"),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "self-mute is a 422"
        );
        let error = json_of(&body)["error"]
            .as_str()
            .expect("an error message")
            .to_owned();
        assert!(
            error.contains("mute") && error.contains("yourself"),
            "the message names the reason: {error}"
        );
    })
    .await;
}

#[tokio::test]
async fn an_unknown_target_is_a_404_in_every_verb() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let token = create_token(&pool, &reader, &["read", "write"]).await;
        let missing = "01j0000000000000000000000z";

        for verb in ["block", "unblock", "mute", "unmute"] {
            let (status, body) = send(
                &app,
                &token,
                "POST",
                &format!("/api/v1/accounts/{missing}/{verb}"),
                None,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "POST …/{verb} on an unknown id must be a 404, not a 500: {body}"
            );
            let error = json_of(&body)["error"]
                .as_str()
                .expect("an error message")
                .to_owned();
            assert!(
                error.to_lowercase().contains("not found"),
                "the message says what is wrong: {error}"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn the_lists_require_a_token() {
    run_db_test(|store, app| async move {
        let _ = store;
        for path in ["/api/v1/mutes", "/api/v1/blocks"] {
            let (status, _) = send_anon(&app, "GET", path).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "GET {path} must not read an anonymous actor's list"
            );
        }
    })
    .await;
}
