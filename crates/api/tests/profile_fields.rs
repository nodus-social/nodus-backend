//! The profile's name/value rows as a client edits them.
//!
//! The rows ride on the same authenticated self-service write as the display name and the
//! bio, so every test drives `PATCH /api/v1/accounts/update_credentials` and reads the
//! result back from `verify_credentials` — the two calls a profile editor makes.

mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};
use support::{create_account, create_token, json_of, run_db_test, send};

const CREDENTIALS: &str = "/api/v1/accounts/update_credentials";
const VERIFY: &str = "/api/v1/accounts/verify_credentials";

/// The error message a `422` carried, for a test that asserts on the reason rather than
/// only the status.
fn reason(body: &str) -> String {
    json_of(body)["error"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn a_field_pair_round_trips() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "fields").await;
        let token = create_token(&pool, &account, &["read", "write"]).await;

        // The form posts what the reader typed, so surrounding space is the server's job.
        let (status, body) = send(
            &app,
            &token,
            "PATCH",
            CREDENTIALS,
            Some(json!({
                "fields": [
                    { "name": " Blog ", "value": " https://example.test " },
                    { "name": "Pronouns", "value": "they/them" },
                ]
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let saved = json_of(&body)["fields"].clone();
        assert_eq!(
            saved,
            json!([
                { "name": "Blog", "value": "https://example.test", "verified_at": null },
                { "name": "Pronouns", "value": "they/them", "verified_at": null },
            ])
        );

        let (status, body) = send(&app, &token, "GET", VERIFY, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json_of(&body)["fields"], saved);

        // A save that does not mention the rows leaves them alone, which is what a form
        // that only touches the display name relies on.
        let (status, body) = send(
            &app,
            &token,
            "PATCH",
            CREDENTIALS,
            Some(json!({ "display_name": "Renamed" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(json_of(&body)["fields"], saved);

        // An empty list is how the editor removes every row.
        let (status, body) = send(
            &app,
            &token,
            "PATCH",
            CREDENTIALS,
            Some(json!({ "fields": [] })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(json_of(&body)["fields"], json!([]));
    })
    .await;
}

#[tokio::test]
async fn a_seventh_field_is_refused() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "toomany").await;
        let token = create_token(&pool, &account, &["read", "write"]).await;

        let rows: Vec<Value> = (1..=7)
            .map(|number| json!({ "name": format!("Row {number}"), "value": "v" }))
            .collect();
        let (status, body) = send(
            &app,
            &token,
            "PATCH",
            CREDENTIALS,
            Some(json!({ "fields": rows })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body was {body}");
        assert!(reason(&body).contains("at most 6 fields"), "{body}");

        let (_, body) = send(&app, &token, "GET", VERIFY, None).await;
        assert_eq!(json_of(&body)["fields"], json!([]), "nothing was stored");
    })
    .await;
}

#[tokio::test]
async fn a_duplicate_name_is_refused() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "dupe").await;
        let token = create_token(&pool, &account, &["read", "write"]).await;

        // Names are compared after trimming and without case, so the two spellings of
        // "blog" that a reader would leave in a form do not become two rows.
        let (status, body) = send(
            &app,
            &token,
            "PATCH",
            CREDENTIALS,
            Some(json!({
                "fields": [
                    { "name": "Blog", "value": "https://one.test" },
                    { "name": " blog", "value": "https://two.test" },
                ]
            })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body was {body}");
        assert!(reason(&body).contains("fields 1 and 2"), "{body}");
    })
    .await;
}

#[tokio::test]
async fn markup_in_a_value_is_refused() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "markup").await;
        let token = create_token(&pool, &account, &["read", "write"]).await;

        let (status, body) = send(
            &app,
            &token,
            "PATCH",
            CREDENTIALS,
            Some(json!({
                "fields": [{ "name": "Blog", "value": "<a href=\"https://x.test\">x</a>" }]
            })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body was {body}");
        assert!(reason(&body).contains("plain text"), "{body}");
    })
    .await;
}

#[tokio::test]
async fn an_overlong_or_nameless_field_is_refused() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "limits").await;
        let token = create_token(&pool, &account, &["read", "write"]).await;

        let (status, body) = send(
            &app,
            &token,
            "PATCH",
            CREDENTIALS,
            Some(json!({ "fields": [{ "name": "x".repeat(256), "value": "v" }] })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body was {body}");
        assert!(reason(&body).contains("255 characters"), "{body}");

        let (status, body) = send(
            &app,
            &token,
            "PATCH",
            CREDENTIALS,
            Some(json!({ "fields": [{ "name": "  ", "value": "https://x.test" }] })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body was {body}");
        assert!(reason(&body).contains("needs a name"), "{body}");
    })
    .await;
}

#[tokio::test]
async fn an_unchanged_row_keeps_its_verification() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "verified").await;
        let token = create_token(&pool, &account, &["read", "write"]).await;

        // No verifier writes this column yet, so the state is seeded directly — the point
        // of the test is that an unrelated save does not throw it away.
        sqlx::query("UPDATE account SET fields = $1 WHERE id = $2")
            .bind(json!([{
                "name": "Blog",
                "value": "https://example.test",
                "verified_at": "2026-01-01T00:00:00Z"
            }]))
            .bind(&account)
            .execute(&pool)
            .await
            .expect("seed verified row");

        let (status, body) = send(
            &app,
            &token,
            "PATCH",
            CREDENTIALS,
            Some(json!({
                "fields": [
                    { "name": "Blog", "value": "https://example.test" },
                    { "name": "Pronouns", "value": "they/them" },
                ]
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let saved = json_of(&body)["fields"].clone();
        assert_eq!(saved[0]["verified_at"], json!("2026-01-01T00:00:00Z"));
        assert_eq!(saved[1]["verified_at"], Value::Null);
    })
    .await;
}
