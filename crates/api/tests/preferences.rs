//! The Preferences tab: the nine defaults a client reads and edits, end to end.
//!
//! `GET|PUT /api/v1/preferences` speaks Mastodon's flat map of key to value. These tests
//! pin the promises the tab depends on: a fresh account reads Mastodon's defaults, a
//! partial edit changes only what it names, a refused edit writes nothing, and one
//! account's values are invisible to another.

mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};

use support::{create_account, create_token, expect_ok, json_of, run_db_test, send};

const PREFERENCES: &str = "/api/v1/preferences";

async fn preferences_of(app: &axum::Router, token: &str) -> Value {
    let (status, body) = send(app, token, "GET", PREFERENCES, None).await;
    json_of(&expect_ok(status, &body, PREFERENCES))
}

fn defaults() -> Value {
    json!({
        "posting:default:visibility": "public",
        "posting:default:sensitive": false,
        "posting:default:language": null,
        "posting:default:quote_policy": "public",
        "reading:expand:media": "default",
        "reading:expand:spoilers": false,
        "reading:autoplay:gifs": false,
        "notification:email": true,
        "notification:report": true,
    })
}

#[tokio::test]
async fn a_fresh_account_reads_mastodon_defaults() {
    run_db_test(|store, app| async move {
        let account = create_account(store.pool(), "prefs-default").await;
        let token = create_token(store.pool(), &account, &["read:accounts"]).await;

        assert_eq!(preferences_of(&app, &token).await, defaults());
    })
    .await;
}

#[tokio::test]
async fn a_partial_write_leaves_other_keys_alone() {
    run_db_test(|store, app| async move {
        let account = create_account(store.pool(), "prefs-partial").await;
        let token =
            create_token(store.pool(), &account, &["read:accounts", "write:accounts"]).await;

        let (status, body) = send(
            &app,
            &token,
            "PUT",
            PREFERENCES,
            Some(json!({
                "posting:default:visibility": "unlisted",
                "posting:default:quote_policy": "followers",
                "reading:expand:spoilers": true,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "PUT: {body}");

        let (status, body) = send(
            &app,
            &token,
            "PUT",
            PREFERENCES,
            Some(json!({"notification:email": false})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "second PUT: {body}");

        let answer = preferences_of(&app, &token).await;
        assert_eq!(answer["posting:default:visibility"], "unlisted", "{answer}");
        assert_eq!(
            answer["posting:default:quote_policy"], "followers",
            "{answer}"
        );
        assert_eq!(answer["reading:expand:spoilers"], true, "{answer}");
        assert_eq!(answer["notification:email"], false, "{answer}");
        assert_eq!(answer["posting:default:language"], Value::Null, "{answer}");
        assert_eq!(answer["reading:expand:media"], "default", "{answer}");
        assert_eq!(answer["notification:report"], true, "{answer}");
    })
    .await;
}

#[tokio::test]
async fn an_unknown_key_is_refused_by_name_and_changes_nothing() {
    run_db_test(|store, app| async move {
        let account = create_account(store.pool(), "prefs-bad-key").await;
        let token =
            create_token(store.pool(), &account, &["read:accounts", "write:accounts"]).await;

        let (status, body) = send(
            &app,
            &token,
            "PUT",
            PREFERENCES,
            Some(json!({
                "posting:default:visibility": "private",
                "posting:default:colour": "blue",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
        assert!(
            body.contains("posting:default:colour"),
            "the message names the key: {body}"
        );

        assert_eq!(
            preferences_of(&app, &token).await,
            defaults(),
            "a refused write must not land the keys it accepted"
        );
    })
    .await;
}

#[tokio::test]
async fn an_invalid_value_is_refused_with_the_allowed_values() {
    run_db_test(|store, app| async move {
        let account = create_account(store.pool(), "prefs-bad-value").await;
        let token =
            create_token(store.pool(), &account, &["read:accounts", "write:accounts"]).await;

        let (status, body) = send(
            &app,
            &token,
            "PUT",
            PREFERENCES,
            Some(json!({"reading:expand:media": "sometimes"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
        assert!(
            body.contains("reading:expand:media"),
            "the message names the key: {body}"
        );
        assert!(
            body.contains("show_all") && body.contains("hide_all"),
            "the message names the allowed values: {body}"
        );

        let (status, body) = send(
            &app,
            &token,
            "PUT",
            PREFERENCES,
            Some(json!({"posting:default:sensitive": "yes"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
        assert!(
            body.contains("posting:default:sensitive") && body.contains("true and false"),
            "the message names the key and its values: {body}"
        );

        let (status, body) = send(
            &app,
            &token,
            "PUT",
            PREFERENCES,
            Some(json!({"posting:default:quote_policy": "friends"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
        assert!(
            body.contains("posting:default:quote_policy")
                && body.contains("public, followers and nobody"),
            "the message names the key and its values: {body}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_second_account_cannot_see_the_first_accounts_values() {
    run_db_test(|store, app| async move {
        let one = create_account(store.pool(), "prefs-one").await;
        let one_token =
            create_token(store.pool(), &one, &["read:accounts", "write:accounts"]).await;
        let two = create_account(store.pool(), "prefs-two").await;
        let two_token = create_token(store.pool(), &two, &["read:accounts"]).await;

        let (status, body) = send(
            &app,
            &one_token,
            "PUT",
            PREFERENCES,
            Some(json!({"posting:default:visibility": "private"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "PUT: {body}");

        assert_eq!(
            preferences_of(&app, &one_token).await["posting:default:visibility"],
            "private"
        );
        assert_eq!(preferences_of(&app, &two_token).await, defaults());
    })
    .await;
}
