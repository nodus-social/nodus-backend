//! The Notifications settings tab: the policy a reader edits, end to end.
//!
//! `GET|PUT /api/v2/notifications/policy` speaks Mastodon's flat map of kind to
//! `accept|filter|drop`. These tests pin the three promises the tab depends on: a fresh
//! account hears the default for every kind, a partial edit changes only what it names, and
//! one account's policy is invisible to another.

mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};

use nodus_server_store::live;
use nodus_server_store::notification_policy::{policy_kind_for, KINDS, VALUES};
use nodus_server_store::social;

use support::{create_account, create_status, create_token, expect_ok, json_of, run_db_test, send};

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

// ---------------------------------------------------------------------------
// Enforcement: the policy decides at the write site, not at read time.
// ---------------------------------------------------------------------------

async fn put_policy(app: &axum::Router, token: &str, body: Value) {
    let (status, response) = send(app, token, "PUT", POLICY, Some(body)).await;
    assert_eq!(status, StatusCode::OK, "PUT {POLICY}: {response}");
}

async fn inbox(app: &axum::Router, token: &str, filtered: bool) -> Vec<Value> {
    let uri = if filtered {
        "/api/v1/notifications?filtered=true"
    } else {
        "/api/v1/notifications"
    };
    let (status, body) = send(app, token, "GET", uri, None).await;
    json_of(&expect_ok(status, &body, uri))
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("{uri} did not answer an array: {body}"))
}

async fn favourite(app: &axum::Router, token: &str, status_id: &str) {
    let uri = format!("/api/v1/statuses/{status_id}/favourite");
    let (status, body) = send(app, token, "POST", &uri, None).await;
    expect_ok(status, &body, &uri);
}

#[test]
fn the_policy_kind_table_names_every_policy_entry_and_leaves_safety_notices_alone() {
    for kind in KINDS {
        assert_eq!(
            policy_kind_for(kind),
            Some(kind),
            "{kind} must map to its policy entry"
        );
    }
    // `poll` is not one of Mastodon's policy kinds; `appeal` and `moderation` are this
    // instance's safety notices. None of the three may be silenced by a settings tab.
    for kind in ["poll", "appeal", "moderation", "not-a-kind"] {
        assert_eq!(policy_kind_for(kind), None, "{kind} has no policy entry");
    }
}

#[tokio::test]
async fn a_drop_policy_for_favourite_writes_no_row_and_publishes_no_stream_event() {
    run_db_test(|store, app| async move {
        let bob = create_account(store.pool(), "policy-drop-recipient").await;
        let alice = create_account(store.pool(), "policy-drop-sender").await;
        let bob_token = create_token(
            store.pool(),
            &bob,
            &["read:notifications", "write:notifications"],
        )
        .await;
        let alice_token = create_token(store.pool(), &alice, &["write:favourites"]).await;
        let status = create_status(store.pool(), &bob, "drop me", "public", &[], &[]).await;

        put_policy(&app, &bob_token, json!({"favourite": "drop"})).await;
        let mut events = live::subscribe_account(&bob);
        favourite(&app, &alice_token, &status).await;

        assert!(
            inbox(&app, &bob_token, false).await.is_empty(),
            "a dropped notification is absent from the ordinary list"
        );
        assert!(
            inbox(&app, &bob_token, true).await.is_empty(),
            "a dropped notification is absent from the filtered list too"
        );
        assert_eq!(
            social::filtered_count(store.pool(), &bob)
                .await
                .expect("count"),
            0
        );
        assert!(
            matches!(
                events.try_recv(),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
            ),
            "a dropped notification must not reach a streaming client"
        );
    })
    .await;
}

#[tokio::test]
async fn a_filter_policy_for_favourite_hides_the_row_from_the_ordinary_list_only() {
    run_db_test(|store, app| async move {
        let bob = create_account(store.pool(), "policy-filter-recipient").await;
        let alice = create_account(store.pool(), "policy-filter-sender").await;
        let bob_token = create_token(
            store.pool(),
            &bob,
            &["read:notifications", "write:notifications"],
        )
        .await;
        let alice_token = create_token(store.pool(), &alice, &["write:favourites"]).await;
        let status = create_status(store.pool(), &bob, "filter me", "public", &[], &[]).await;

        put_policy(&app, &bob_token, json!({"favourite": "filter"})).await;
        let mut events = live::subscribe_account(&bob);
        favourite(&app, &alice_token, &status).await;

        assert!(
            inbox(&app, &bob_token, false).await.is_empty(),
            "a filtered notification is kept out of the ordinary list"
        );
        let filtered = inbox(&app, &bob_token, true).await;
        assert_eq!(filtered.len(), 1, "?filtered=true finds it: {filtered:?}");
        assert_eq!(filtered[0]["type"], "favourite");
        assert_eq!(
            social::filtered_count(store.pool(), &bob)
                .await
                .expect("count"),
            1
        );
        assert!(
            matches!(
                events.try_recv(),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
            ),
            "a filtered notification must not reach a streaming client either"
        );
    })
    .await;
}

#[tokio::test]
async fn an_accept_policy_still_delivers_and_streams() {
    run_db_test(|store, app| async move {
        let bob = create_account(store.pool(), "policy-accept-recipient").await;
        let alice = create_account(store.pool(), "policy-accept-sender").await;
        let bob_token = create_token(store.pool(), &bob, &["read:notifications"]).await;
        let alice_token = create_token(store.pool(), &alice, &["write:favourites"]).await;
        let status = create_status(store.pool(), &bob, "accept me", "public", &[], &[]).await;

        let mut events = live::subscribe_account(&bob);
        favourite(&app, &alice_token, &status).await;

        let ordinary = inbox(&app, &bob_token, false).await;
        assert_eq!(ordinary.len(), 1, "accept is unchanged: {ordinary:?}");
        assert_eq!(ordinary[0]["type"], "favourite");
        assert!(
            matches!(
                events.try_recv(),
                Ok(event) if matches!(event.as_ref(), live::LiveEvent::Notification { .. })
            ),
            "accepted notifications still stream"
        );
    })
    .await;
}

#[tokio::test]
async fn a_policy_change_applies_to_the_next_notification_not_retroactively() {
    run_db_test(|store, app| async move {
        let bob = create_account(store.pool(), "policy-next-recipient").await;
        let alice = create_account(store.pool(), "policy-next-sender").await;
        let bob_token = create_token(
            store.pool(),
            &bob,
            &["read:notifications", "write:notifications"],
        )
        .await;
        let alice_token = create_token(store.pool(), &alice, &["write:favourites"]).await;
        let before = create_status(store.pool(), &bob, "before", "public", &[], &[]).await;
        let after = create_status(store.pool(), &bob, "after", "public", &[], &[]).await;

        favourite(&app, &alice_token, &before).await;
        let first = inbox(&app, &bob_token, false).await;
        assert_eq!(first.len(), 1, "the first favourite is accepted: {first:?}");
        let first_id = first[0]["id"].clone();

        put_policy(&app, &bob_token, json!({"favourite": "filter"})).await;
        favourite(&app, &alice_token, &after).await;

        let ordinary = inbox(&app, &bob_token, false).await;
        assert_eq!(
            ordinary.len(),
            1,
            "the row written before the policy change stays: {ordinary:?}"
        );
        assert_eq!(
            ordinary[0]["id"], first_id,
            "the old notification is not retroactively filtered"
        );
        let filtered = inbox(&app, &bob_token, true).await;
        assert_eq!(
            filtered.len(),
            1,
            "the next notification follows the new policy: {filtered:?}"
        );
        assert_ne!(
            filtered[0]["id"], first_id,
            "the newly filtered row is the second notification"
        );
    })
    .await;
}
