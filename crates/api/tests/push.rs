//! Web Push registration: the subscription store behind `POST|GET|PUT|DELETE
//! /api/v1/push/subscription`.
//!
//! These tests pin the promises slice 2 will build on: a subscription round-trips, the same
//! endpoint posts idempotently (browsers rotate keys, so a second POST must replace, not
//! duplicate), deleting is scoped to the caller, a failed delivery is counted without
//! erasing the row, and every verb is behind a token.

mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};

use nodus_server_store::push;

use support::{create_account, create_token, json_of, run_db_test, send, send_anon, send_form};

const PATH: &str = "/api/v1/push/subscription";
const ENDPOINT: &str = "https://push.example/abcd";

fn body(endpoint: &str, p256dh: &str, auth: &str, mention: bool) -> Value {
    json!({
        "subscription": {
            "endpoint": endpoint,
            "keys": { "p256dh": p256dh, "auth": auth }
        },
        "data": { "alerts": { "mention": mention, "reblog": false } }
    })
}

async fn token_for(store: &nodus_server_store::Store, label: &str) -> (String, String) {
    let account = create_account(store.pool(), label).await;
    let token = create_token(store.pool(), &account, &["push"]).await;
    (account, token)
}

#[tokio::test]
async fn a_subscription_round_trips() {
    run_db_test(|store, app| async move {
        let (_, token) = token_for(&store, "push-round-trip").await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            PATH,
            Some(body(ENDPOINT, "p256dh-one", "auth-one", true)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "POST: {body}");
        let created = json_of(&body);
        assert_eq!(created["endpoint"], ENDPOINT, "answer: {created}");
        assert_eq!(
            created["server_key"],
            support::test_vapid().public_key(),
            "clients build a subscription from the key the endpoint hands back"
        );
        assert!(!created["id"].as_str().unwrap_or_default().is_empty());
        assert_eq!(created["alerts"]["mention"], true);
        assert_eq!(created["alerts"]["reblog"], false);
        assert_eq!(
            created["alerts"]["follow"], true,
            "an alert the POST omits stays enabled: {created}"
        );

        let (status, body) = send(&app, &token, "GET", PATH, None).await;
        assert_eq!(status, StatusCode::OK, "GET: {body}");
        let fetched = json_of(&body);
        assert_eq!(fetched["id"], created["id"]);
        assert_eq!(fetched["endpoint"], ENDPOINT);
        assert_eq!(fetched["server_key"], created["server_key"]);
        assert_eq!(fetched["alerts"], created["alerts"]);
    })
    .await;
}

#[tokio::test]
async fn a_form_encoded_subscription_round_trips_too() {
    run_db_test(|store, app| async move {
        let (_, token) = token_for(&store, "push-form").await;

        let (status, body) = send_form(
            &app,
            &token,
            "POST",
            PATH,
            &[
                ("subscription[endpoint]", ENDPOINT),
                ("subscription[keys][p256dh]", "p256dh-form"),
                ("subscription[keys][auth]", "auth-form"),
                ("data[alerts][mention]", "false"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "POST form: {body}");
        let created = json_of(&body);
        assert_eq!(created["endpoint"], ENDPOINT);
        assert_eq!(created["alerts"]["mention"], false);
        assert_eq!(created["alerts"]["favourite"], true);
    })
    .await;
}

#[tokio::test]
async fn a_second_post_with_the_same_endpoint_updates_rather_than_duplicates() {
    run_db_test(|store, app| async move {
        let (account, token) = token_for(&store, "push-idempotent").await;

        let (_, first) = send(
            &app,
            &token,
            "POST",
            PATH,
            Some(body(ENDPOINT, "p256dh-one", "auth-one", true)),
        )
        .await;
        let first = json_of(&first);

        let (status, second) = send(
            &app,
            &token,
            "POST",
            PATH,
            Some(body(ENDPOINT, "p256dh-two", "auth-two", false)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "second POST: {second}");
        let second = json_of(&second);
        assert_eq!(
            second["id"], first["id"],
            "the same endpoint is the same subscription"
        );
        assert_eq!(second["alerts"]["mention"], false);

        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM push_subscription WHERE account_id = $1")
                .bind(&account)
                .fetch_one(store.pool())
                .await
                .expect("count rows");
        assert_eq!(rows, 1, "a second POST must not add a row");
    })
    .await;
}

#[tokio::test]
async fn a_rotated_key_replaces_the_old_one() {
    run_db_test(|store, app| async move {
        let (account, token) = token_for(&store, "push-rotation").await;

        for (p256dh, auth) in [("old-key", "old-auth"), ("new-key", "new-auth")] {
            let (status, body) = send(
                &app,
                &token,
                "POST",
                PATH,
                Some(body(ENDPOINT, p256dh, auth, true)),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "POST {p256dh}: {body}");
        }

        let stored: Vec<(String, String)> =
            sqlx::query_as("SELECT p256dh, auth FROM push_subscription WHERE account_id = $1")
                .bind(&account)
                .fetch_all(store.pool())
                .await
                .expect("read keys");
        assert_eq!(
            stored,
            vec![("new-key".to_owned(), "new-auth".to_owned())],
            "the rotated key must replace the old one, not sit beside it"
        );
    })
    .await;
}

#[tokio::test]
async fn put_changes_alerts_without_touching_the_keys() {
    run_db_test(|store, app| async move {
        let (account, token) = token_for(&store, "push-alerts").await;
        send(
            &app,
            &token,
            "POST",
            PATH,
            Some(body(ENDPOINT, "p256dh-one", "auth-one", true)),
        )
        .await;

        let (status, body) = send(
            &app,
            &token,
            "PUT",
            PATH,
            Some(json!({"data": {"alerts": {"mention": false, "poll": false}}})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "PUT: {body}");
        let updated = json_of(&body);
        assert_eq!(updated["alerts"]["mention"], false);
        assert_eq!(updated["alerts"]["poll"], false);
        assert_eq!(
            updated["alerts"]["reblog"], false,
            "a kind the PUT omits keeps its stored answer"
        );

        let keys: (String, String) =
            sqlx::query_as("SELECT p256dh, auth FROM push_subscription WHERE account_id = $1")
                .bind(&account)
                .fetch_one(store.pool())
                .await
                .expect("read keys");
        assert_eq!(keys, ("p256dh-one".to_owned(), "auth-one".to_owned()));
    })
    .await;
}

#[tokio::test]
async fn delete_removes_only_the_callers_row_and_answers_204() {
    run_db_test(|store, app| async move {
        let (_, alice) = token_for(&store, "push-delete-alice").await;
        let (_, bob) = token_for(&store, "push-delete-bob").await;

        for token in [&alice, &bob] {
            let (status, body) = send(
                &app,
                token,
                "POST",
                PATH,
                Some(body(ENDPOINT, "p256dh-one", "auth-one", true)),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "POST: {body}");
        }

        let (status, body) = send(
            &app,
            &alice,
            "DELETE",
            PATH,
            Some(json!({"subscription": {"endpoint": ENDPOINT}})),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "DELETE: {body}");

        let (status, body) = send(&app, &alice, "GET", PATH, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, r#"{"error":"Record not found"}"#);

        let (status, body) = send(&app, &bob, "GET", PATH, None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the other account's row survives: {body}"
        );
        assert_eq!(json_of(&body)["endpoint"], ENDPOINT);

        let (status, _) = send(
            &app,
            &alice,
            "DELETE",
            PATH,
            Some(json!({"subscription": {"endpoint": ENDPOINT}})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "a second DELETE is still 204"
        );
    })
    .await;
}

#[tokio::test]
async fn record_failure_increments_and_the_row_survives() {
    run_db_test(|store, app| async move {
        let (account, token) = token_for(&store, "push-failure").await;
        send(
            &app,
            &token,
            "POST",
            PATH,
            Some(body(ENDPOINT, "p256dh-one", "auth-one", true)),
        )
        .await;

        let first = push::record_failure(store.pool(), &account, ENDPOINT)
            .await
            .expect("record failure")
            .expect("row survives");
        let second = push::record_failure(store.pool(), &account, ENDPOINT)
            .await
            .expect("record failure")
            .expect("row survives");
        assert_eq!(first.failure_count, 1);
        assert_eq!(second.failure_count, 2);

        let (status, body) = send(&app, &token, "GET", PATH, None).await;
        assert_eq!(status, StatusCode::OK, "the row still answers: {body}");
        assert_eq!(json_of(&body)["endpoint"], ENDPOINT);
    })
    .await;
}

#[tokio::test]
async fn an_unauthorised_caller_gets_401_on_all_four_verbs() {
    run_db_test(|store, app| async move {
        let _ = store;
        for method in ["GET", "POST", "PUT", "DELETE"] {
            let (status, body) = send_anon(&app, method, PATH).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{method} without a token must be 401, not a subscription: {body}"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn web_push_off_501_with_message_but_delete_succeeds() {
    support::run_db_test_without_vapid(|store, app| async move {
        let (account, token) = token_for(&store, "push-off").await;

        for method in ["GET", "POST", "PUT"] {
            let body_value = match method {
                "POST" => Some(body(ENDPOINT, "p256dh-test", "auth-test", true)),
                "PUT" => Some(json!({"data": {"alerts": {"mention": false}}})),
                _ => None,
            };
            let (status, body) = send(&app, &token, method, PATH, body_value).await;
            assert_eq!(
                status,
                StatusCode::NOT_IMPLEMENTED,
                "{method} with vapid: None must be 501: {body}"
            );
            assert!(
                body.contains("Web Push is not configured on this instance")
                    && body.contains("NODUS_VAPID_PUBLIC_KEY")
                    && body.contains("NODUS_VAPID_PRIVATE_KEY"),
                "{method} error must be a sentence naming both environment variables: {body}"
            );
        }

        // A row written while the server still had a key must remain removable after the
        // key is withdrawn, otherwise the client is stuck with a subscription nobody can
        // delete.
        push::upsert(
            store.pool(),
            &account,
            ENDPOINT,
            "p256dh-off",
            "auth-off",
            &json!({"mention": true}),
            None,
        )
        .await
        .expect("seed a subscription from before the key was withdrawn");

        let (status, body) = send(
            &app,
            &token,
            "DELETE",
            PATH,
            Some(json!({"subscription": {"endpoint": ENDPOINT}})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "DELETE with vapid: None must be 204: {body}"
        );

        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM push_subscription WHERE account_id = $1")
                .bind(&account)
                .fetch_one(store.pool())
                .await
                .expect("count rows");
        assert_eq!(rows, 0, "DELETE with push off must remove the row");
    })
    .await;
}
