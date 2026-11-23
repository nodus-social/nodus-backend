//! The published-banner surface: an owner's write and any reader's read.

mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};

use nodus_server_store::style_public::StylePublic;

use support::{create_account, create_token, expect_ok, json_of, run_db_test, send, send_anon};

const PUBLISH: &str = "/api/v1/style/public";

fn public_style() -> Value {
    json!({
        "top": {
            "split": "vertical",
            "slots": [
                {
                    "url": "https://media.social.test/banner.png",
                    "alt": "A wide banner",
                    "media_id": "01j00000000000000000000000",
                    "sensitive": true
                },
                {"url": "/media/local-banner.png"}
            ]
        },
        "left": {
            "slots": [{"url": "http://cdn.social.test/left.webp", "alt": "Left rail"}]
        },
        "right": {"hidden": true}
    })
}

fn read_path(account_id: &str) -> String {
    format!("/api/v1/accounts/{account_id}/style_public")
}

#[tokio::test]
async fn a_published_style_round_trips() {
    run_db_test(|store, app| async move {
        let owner = create_account(store.pool(), "style_owner").await;
        let token = create_token(store.pool(), &owner, &["read:accounts", "write:accounts"]).await;
        let expected: StylePublic = serde_json::from_value(public_style()).expect("style fixture");

        let (status, body) = send(&app, &token, "PUT", PUBLISH, Some(public_style())).await;
        let stored = expect_ok(status, &body, PUBLISH);
        let written: StylePublic = support::decode(&stored);
        assert_eq!(
            written, expected,
            "the write answers the document it stored"
        );
        assert!(
            written.top.slots[0].sensitive,
            "sensitive survives the write"
        );

        let (status, body) = send_anon(&app, "GET", &read_path(&owner)).await;
        let served = expect_ok(status, &body, &read_path(&owner));
        let read: StylePublic = support::decode(&served);
        assert_eq!(
            read, expected,
            "another reader sees exactly what was published"
        );
    })
    .await;
}

#[tokio::test]
async fn a_write_replaces_only_the_callers_style() {
    run_db_test(|store, app| async move {
        let owner = create_account(store.pool(), "style_first").await;
        let other = create_account(store.pool(), "style_second").await;
        let owner_token =
            create_token(store.pool(), &owner, &["read:accounts", "write:accounts"]).await;
        let other_token =
            create_token(store.pool(), &other, &["read:accounts", "write:accounts"]).await;

        let (status, body) = send(&app, &owner_token, "PUT", PUBLISH, Some(public_style())).await;
        expect_ok(status, &body, PUBLISH);

        let second = json!({"top": {"slots": [{"url": "/media/second.png"}]}});
        let (status, body) = send(&app, &other_token, "PUT", PUBLISH, Some(second)).await;
        expect_ok(status, &body, PUBLISH);

        let (status, body) = send_anon(&app, "GET", &read_path(&owner)).await;
        let served = expect_ok(status, &body, &read_path(&owner));
        let read: StylePublic = support::decode(&served);
        assert_eq!(
            read,
            serde_json::from_value(public_style()).expect("style fixture"),
            "the second account's write must not touch the first account's banners"
        );
    })
    .await;
}

#[tokio::test]
async fn invalid_slots_are_refused_by_name() {
    run_db_test(|store, app| async move {
        let owner = create_account(store.pool(), "style_invalid").await;
        let token = create_token(store.pool(), &owner, &["read:accounts", "write:accounts"]).await;
        let cases = [
            (
                json!({"top": {"slots": [{"url": "javascript:alert(1)"}]}}),
                "top.slots[0].url",
            ),
            (
                json!({"top": {"slots": [{"url": "/media/a.png", "alt": "a".repeat(201)}]}}),
                "top.slots[0].alt",
            ),
            (
                json!({"top": {"slots": [{"url": "/media/a.png", "media_id": "m".repeat(49)}]}}),
                "top.slots[0].media_id",
            ),
        ];
        for (body, row) in cases {
            let (status, response) = send(&app, &token, "PUT", PUBLISH, Some(body)).await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{row}: {response}"
            );
            let error = json_of(&response)["error"]
                .as_str()
                .expect("error body names the row")
                .to_owned();
            assert!(error.contains(row), "refusal must name {row}: {error}");
        }

        let (status, _) = send_anon(&app, "GET", &read_path(&owner)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "nothing was stored");
    })
    .await;
}

#[tokio::test]
async fn a_profile_that_never_published_answers_404() {
    run_db_test(|store, app| async move {
        let account = create_account(store.pool(), "style_never").await;
        let (status, body) = send_anon(&app, "GET", &read_path(&account)).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "never-published is a 404, not an empty object: {body}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_suspended_accounts_style_is_not_served() {
    run_db_test(|store, app| async move {
        let owner = create_account(store.pool(), "style_suspended").await;
        let token = create_token(store.pool(), &owner, &["read:accounts", "write:accounts"]).await;
        let (status, body) = send(&app, &token, "PUT", PUBLISH, Some(public_style())).await;
        expect_ok(status, &body, PUBLISH);

        sqlx::query("UPDATE account SET suspended_at = now() WHERE id = $1")
            .bind(&owner)
            .execute(store.pool())
            .await
            .expect("suspend account");

        let (status, body) = send_anon(&app, "GET", &read_path(&owner)).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a suspended account's published banners are out of view: {body}"
        );
    })
    .await;
}

#[tokio::test]
async fn the_payload_carries_only_banner_regions() {
    run_db_test(|store, app| async move {
        let owner = create_account(store.pool(), "style_shape").await;
        let token = create_token(store.pool(), &owner, &["read:accounts", "write:accounts"]).await;

        let private = json!({
            "top": {"slots": []},
            "nav": {"placement": "left"},
        });
        let (status, body) = send(&app, &token, "PUT", PUBLISH, Some(private)).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "a private arrangement key is refused: {body}"
        );
        assert!(body.contains("nav"), "the refusal names the key: {body}");

        let (status, body) = send(&app, &token, "PUT", PUBLISH, Some(public_style())).await;
        expect_ok(status, &body, PUBLISH);
        let (status, body) = send_anon(&app, "GET", &read_path(&owner)).await;
        let served = expect_ok(status, &body, &read_path(&owner));
        let document: Value = json_of(&served);
        let keys: Vec<&str> = document
            .as_object()
            .expect("a published style is an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["left", "right", "top"]);
        for private_key in ["nav", "nav_layout", "modules", "categories"] {
            assert!(
                !served.contains(&format!("\"{private_key}\"")),
                "the public document must not carry {private_key}: {served}"
            );
        }
    })
    .await;
}
