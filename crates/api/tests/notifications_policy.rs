//! The Notifications settings tab: the policy a reader edits, end to end.
//!
//! `GET|PUT /api/v2/notifications/policy` speaks Mastodon's flat map of kind to
//! `accept|filter|drop`. These tests pin the three promises the tab depends on: a fresh
//! account hears the default for every kind, a partial edit changes only what it names, and
//! one account's policy is invisible to another.

mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};

use nodus_server_store::notification_policy::{KINDS, VALUES};

use support::{create_account, create_token, expect_ok, json_of, run_db_test, send};

const POLICY: &str = "/api/v2/notifications/policy";

async fn policy_of(app: &axum::Router, token: &str) -> Value {
    let (status, body) = send(app, token, "GET", POLICY, None).await;
    json_of(&expect_ok(status, &body, POLICY))
}

#[tokio::test]
async fn a_fresh_account_hears_the_default_for_every_kind() {
    run_db_test(|store, app| async move {
        let account = create_account(store.pool(), "policy-default").await;
        let token = create_token(store.pool(), &account, &["read:notifications"]).await;

        let answer = policy_of(&app, &token).await;
        let object = answer.as_object().expect("the policy is an object");
        assert_eq!(
            object.len(),
            KINDS.len(),
            "GET answers every known kind: {answer}"
        );
        for kind in KINDS {
            assert_eq!(
                object.get(kind).and_then(Value::as_str),
                Some("accept"),
                "{kind} must default to accept: {answer}"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn a_policy_round_trips() {
    run_db_test(|store, app| async move {
        let account = create_account(store.pool(), "policy-round-trip").await;
        let token = create_token(
            store.pool(),
            &account,
            &["read:notifications", "write:notifications"],
        )
        .await;

        let (status, body) = send(
            &app,
            &token,
            "PUT",
            POLICY,
            Some(json!({"mention": "drop", "reblog": "filter"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "PUT: {body}");

        let answer = policy_of(&app, &token).await;
        assert_eq!(answer["mention"], "drop", "answer: {answer}");
        assert_eq!(answer["reblog"], "filter", "answer: {answer}");
        assert_eq!(answer["favourite"], "accept", "answer: {answer}");
    })
    .await;
}

#[tokio::test]
async fn a_partial_update_does_not_clobber_untouched_kinds() {
    run_db_test(|store, app| async move {
        let account = create_account(store.pool(), "policy-partial").await;
        let token = create_token(
            store.pool(),
            &account,
            &["read:notifications", "write:notifications"],
        )
        .await;

        let (status, body) = send(
            &app,
            &token,
            "PUT",
            POLICY,
            Some(json!({"mention": "drop", "reblog": "filter"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "first PUT: {body}");

        let (status, body) = send(
            &app,
            &token,
            "PUT",
            POLICY,
            Some(json!({"favourite": "filter"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "second PUT: {body}");

        let answer = policy_of(&app, &token).await;
        assert_eq!(answer["mention"], "drop", "answer: {answer}");
        assert_eq!(answer["reblog"], "filter", "answer: {answer}");
        assert_eq!(answer["favourite"], "filter", "answer: {answer}");
        assert_eq!(answer["follow"], "accept", "answer: {answer}");
    })
    .await;
}

#[tokio::test]
async fn an_unknown_kind_is_refused_by_name() {
    run_db_test(|store, app| async move {
        let account = create_account(store.pool(), "policy-bad-kind").await;
        let token = create_token(
            store.pool(),
            &account,
            &["read:notifications", "write:notifications"],
        )
        .await;

        let (status, body) = send(
            &app,
            &token,
            "PUT",
            POLICY,
            Some(json!({"mention": "drop", "toot": "drop"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
        assert!(body.contains("toot"), "the message names the kind: {body}");

        // The refused request wrote nothing, including the kind that was valid.
        let answer = policy_of(&app, &token).await;
        assert_eq!(answer["mention"], "accept", "answer: {answer}");
    })
    .await;
}

#[tokio::test]
async fn an_unknown_value_is_refused_with_the_three_allowed() {
    run_db_test(|store, app| async move {
        let account = create_account(store.pool(), "policy-bad-value").await;
        let token = create_token(
            store.pool(),
            &account,
            &["read:notifications", "write:notifications"],
        )
        .await;

        let (status, body) = send(
            &app,
            &token,
            "PUT",
            POLICY,
            Some(json!({"mention": "silence"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
        assert!(
            body.contains("silence"),
            "the message names the value: {body}"
        );
        for allowed in VALUES {
            assert!(
                body.contains(allowed),
                "the message lists {allowed}: {body}"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn writing_the_policy_needs_write_notifications() {
    run_db_test(|store, app| async move {
        let account = create_account(store.pool(), "policy-scope").await;
        let token = create_token(store.pool(), &account, &["read:notifications"]).await;

        // Reading the tab is the read grant's business.
        let (status, body) = send(&app, &token, "GET", POLICY, None).await;
        assert_eq!(status, StatusCode::OK, "GET: {body}");

        let (status, body) = send(
            &app,
            &token,
            "PUT",
            POLICY,
            Some(json!({"mention": "drop"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "PUT: {body}");
        assert!(
            body.contains("write:notifications"),
            "the refusal names the scope: {body}"
        );
    })
    .await;
}

#[tokio::test]
async fn two_accounts_do_not_see_each_others_policy() {
    run_db_test(|store, app| async move {
        let alice = create_account(store.pool(), "policy-alice").await;
        let bob = create_account(store.pool(), "policy-bob").await;
        let alice_token = create_token(
            store.pool(),
            &alice,
            &["read:notifications", "write:notifications"],
        )
        .await;
        let bob_token = create_token(
            store.pool(),
            &bob,
            &["read:notifications", "write:notifications"],
        )
        .await;

        let (status, body) = send(
            &app,
            &alice_token,
            "PUT",
            POLICY,
            Some(json!({"mention": "drop"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "PUT: {body}");

        assert_eq!(policy_of(&app, &alice_token).await["mention"], "drop");
        assert_eq!(policy_of(&app, &bob_token).await["mention"], "accept");
    })
    .await;
}
