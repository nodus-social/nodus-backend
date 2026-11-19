//! What a person can take away: one document holding their posts, their graph, their
//! notifications, their appeals and every moderation decision recorded about them.
//!
//! Four promises are pinned here, because each one is a way an export goes wrong:
//!
//! * a populated account gets its statuses and its moderation history back — the sections
//!   are not empty shells that answer 200;
//! * another person's export is refused, while a staff token reads it, because a record
//!   that names a moderator's reason is not the same audience as a public profile;
//! * an unknown id is a 404, not an empty document that looks like a clean history;
//! * nothing credential-shaped is in the bytes. That last assertion is made on the raw
//!   response body rather than on the parsed struct: a field that leaks would be dropped by
//!   the parse and the test would pass while the network carried it.

use axum::http::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;

use nodus_server_store::accounts;
use nodus_server_store::moderation;

mod support;

use support::{create_account, create_status, create_token, run_db_test, send};

/// A staff account with `admin:read`: the console operator a support request is answered by.
async fn staff(pool: &PgPool, label: &str) -> (String, String) {
    let id = create_account(pool, label).await;
    accounts::set_staff_role(pool, &id, "admin")
        .await
        .expect("grant role");
    let token = create_token(pool, &id, &["admin:read", "read:accounts"]).await;
    (id, token)
}

fn export_path(id: &str) -> String {
    format!("/api/v1/accounts/{id}/export")
}

#[tokio::test]
async fn a_populated_account_exports_its_statuses_and_its_moderation_history() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let id = create_account(pool, "export_subject").await;
        let status = create_status(pool, &id, "a post that is mine to take", "public", &[], &[]).await;
        let (moderator, _) = staff(pool, "export_moderator").await;

        // The three records moderation leaves: an audit row (the action), a strike (what
        // escalation counts) and a warning (the one decision that restricts nothing).
        moderation::audit(
            pool,
            &moderator,
            "account_silence",
            "account",
            Some(&id),
            &json!({ "text": "kept posting the same slur" }),
        )
        .await
        .expect("audit row");
        sqlx::query(
            "INSERT INTO moderation_strike (id, account_id, action, reason, expires_at) \
             VALUES ($1, $2, 'silence', 'kept posting the same slur', now() + interval '90 days')",
        )
        .bind(nodus_server_core::Id::new().to_string())
        .bind(&id)
        .execute(pool)
        .await
        .expect("strike");
        sqlx::query(
            "INSERT INTO notification \
                (id, account_id, kind, from_account_id, moderation_action, \
                 moderation_reason, note) \
             VALUES ($1, $2, 'moderation', $3, 'warn', 'first and only warning', \
                     'You were warned.')",
        )
        .bind(nodus_server_core::Id::new().to_string())
        .bind(&id)
        .bind(&moderator)
        .execute(pool)
        .await
        .expect("warning notification");

        let token = create_token(pool, &id, &["read:accounts"]).await;
        let (code, body) = send(&app, &token, "GET", &export_path(&id), None).await;
        assert_eq!(code, StatusCode::OK, "own export failed: {body}");
        let document: Value = serde_json::from_str(&body).expect("export is JSON");

        let statuses = document["statuses"].as_array().expect("statuses array");
        assert_eq!(statuses.len(), 1, "export lost the status: {document}");
        assert_eq!(statuses[0]["id"], status.as_str());
        assert_eq!(statuses[0]["content"], "a post that is mine to take");
        assert!(
            statuses[0]["media"].is_array(),
            "media must be described, even when empty"
        );

        let moderation = &document["moderation"];
        assert_eq!(
            moderation["actions"][0]["action"], "account_silence",
            "the moderation action is missing from the export"
        );
        assert_eq!(
            moderation["actions"][0]["detail"]["text"], "kept posting the same slur",
            "an action without its reason is not an export"
        );
        assert_eq!(moderation["strikes"][0]["action"], "silence");
        assert_eq!(moderation["strikes"][0]["reason"], "kept posting the same slur");
        assert_eq!(
            moderation["warnings"][0]["moderation_reason"], "first and only warning",
            "a warning carries the sentence it was issued with"
        );

        // The document says what it is and where the next page is, so a client can tell a
        // finished export from a first page.
        assert_eq!(document["contract"], "nodus-1");
        assert!(document["paging"]["statuses"].is_object());
    })
    .await;
}

#[tokio::test]
async fn a_foreign_token_is_refused_and_a_staff_token_is_not() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let subject = create_account(pool, "export_target").await;
        let stranger = create_account(pool, "export_stranger").await;
        create_status(pool, &subject, "not for a stranger", "public", &[], &[]).await;

        let foreign = create_token(pool, &stranger, &["read:accounts"]).await;
        let (code, _) = send(&app, &foreign, "GET", &export_path(&subject), None).await;
        assert_eq!(
            code,
            StatusCode::FORBIDDEN,
            "another person's export was served to a reachable token"
        );

        let (_, staff_token) = staff(pool, "export_staff").await;
        let (code, body) = send(&app, &staff_token, "GET", &export_path(&subject), None).await;
        assert_eq!(code, StatusCode::OK, "staff export failed: {body}");
        let document: Value = serde_json::from_str(&body).expect("export is JSON");
        assert_eq!(document["account"]["id"], subject.as_str());
    })
    .await;
}

#[tokio::test]
async fn an_unknown_account_is_a_404() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let id = create_account(pool, "export_unknown_caller").await;
        let token = create_token(pool, &id, &["read:accounts", "admin:read"]).await;
        let (code, body) = send(
            &app,
            &token,
            "GET",
            "/api/v1/accounts/01j00000000000000000000000/export",
            None,
        )
        .await;
        assert_eq!(
            code,
            StatusCode::NOT_FOUND,
            "an unknown account must not export an empty history: {body}"
        );
    })
    .await;
}

#[tokio::test]
async fn no_email_and_no_token_material_appears_anywhere_in_the_body() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let id = create_account(pool, "export_secrets").await;
        let email = format!("secret-{id}@example.test");
        sqlx::query(
            "INSERT INTO account_credential (account_id, email, password_hash) \
             VALUES ($1, $2, 'argon2-hash-that-must-not-ship')",
        )
        .bind(&id)
        .bind(&email)
        .execute(pool)
        .await
        .expect("credential");
        sqlx::query(
            "INSERT INTO auth_session (id, account_id, token_hash, expires_at) \
             VALUES ($1, $2, 'session-hash-that-must-not-ship', now() + interval '1 day')",
        )
        .bind(nodus_server_core::Id::new().to_string())
        .bind(&id)
        .execute(pool)
        .await
        .expect("session");
        create_status(pool, &id, "a post", "public", &[], &[]).await;
        let token = create_token(pool, &id, &["read:accounts"]).await;

        let (code, body) = send(&app, &token, "GET", &export_path(&id), None).await;
        assert_eq!(code, StatusCode::OK, "own export failed: {body}");

        // Asserted on the raw bytes. A parsed-struct assertion would be satisfied by a
        // field the parser never read, which is exactly the leak this test exists for.
        for secret in [
            email.as_str(),
            "argon2-hash-that-must-not-ship",
            "session-hash-that-must-not-ship",
            token.as_str(),
            "password_hash",
            "token_hash",
            "private_key",
            "client_secret",
        ] {
            assert!(
                !body.contains(secret),
                "export body leaked `{secret}`: {body}"
            );
        }
    })
    .await;
}
