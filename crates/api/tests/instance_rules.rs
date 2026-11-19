//! The instance's rules and the reports that cite them.
//!
//! A rule is a numbered promise, and the number is the part people quote back: "you broke
//! rule 3". So the tests here pin the order, the fact that a position is never shared,
//! and that a citation survives the rule being deleted — history is not rewritten by a
//! later edit of the document.

use axum::http::StatusCode;
use axum::Router;
use serde_json::{json, Value};
use sqlx::PgPool;

use nodus_server_store::accounts;

mod support;

use support::{create_account, create_token, json_of, run_db_test, send, send_anon};

/// A staff account and a token carrying exactly the scopes under test.
async fn staff(pool: &PgPool, label: &str, role: &str, scopes: &[&str]) -> String {
    let id = create_account(pool, label).await;
    accounts::set_staff_role(pool, &id, role)
        .await
        .expect("grant role");
    create_token(pool, &id, scopes).await
}

async fn create_rule(app: &Router, token: &str, text: &str, ordinal: Option<i32>) -> String {
    let body = match ordinal {
        Some(ordinal) => json!({ "text": text, "ordinal": ordinal }),
        None => json!({ "text": text }),
    };
    let (status, body) = send(app, token, "POST", "/api/v1/admin/rules", Some(body)).await;
    assert_eq!(status, StatusCode::OK, "create rule: {body}");
    let rule = json_of(&body);
    assert_eq!(rule["text"], json!(text), "body was {body}");
    rule["id"].as_str().expect("rule id").to_owned()
}

async fn admin_rules(app: &Router, token: &str) -> Vec<Value> {
    let (status, body) = send(app, token, "GET", "/api/v1/admin/rules", None).await;
    assert_eq!(status, StatusCode::OK, "list rules: {body}");
    json_of(&body).as_array().cloned().expect("rule list")
}

/// The ordinals a client would read from a listing, in listed order.
fn ordinals(rules: &[Value]) -> Vec<i64> {
    rules
        .iter()
        .map(|rule| rule["ordinal"].as_i64().expect("ordinal"))
        .collect()
}

#[tokio::test]
async fn the_public_instance_document_lists_rules_in_ordinal_order() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let admin = staff(
            &pool,
            "admin",
            "admin",
            &["read", "admin:read", "admin:write"],
        )
        .await;

        // Created out of order on purpose: the listing follows `ordinal`, not insertion.
        create_rule(&app, &admin, "Third", Some(2)).await;
        create_rule(&app, &admin, "First", Some(0)).await;
        create_rule(&app, &admin, "Second", Some(1)).await;

        let (status, body) = send_anon(&app, "GET", "/api/v1/instance").await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let document = json_of(&body);
        let rules = document["rules"].as_array().expect("rules array");
        let texts: Vec<&str> = rules
            .iter()
            .map(|rule| rule["text"].as_str().expect("rule text"))
            .collect();
        assert_eq!(texts, vec!["First", "Second", "Third"], "body was {body}");
        assert!(
            rules.iter().all(|rule| rule["id"].is_string()),
            "every rule carries its id: {body}"
        );

        // The standalone route answers the same list, for a client that wants only this.
        let (status, body) = send_anon(&app, "GET", "/api/v1/instance/rules").await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let standalone = json_of(&body);
        let standalone = standalone.as_array().expect("rules array");
        let standalone_texts: Vec<&str> = standalone
            .iter()
            .map(|rule| rule["text"].as_str().expect("rule text"))
            .collect();
        assert_eq!(standalone_texts, texts, "both routes agree: {body}");
    })
    .await;
}

#[tokio::test]
async fn creating_without_an_ordinal_appends_to_the_end() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let admin = staff(
            &pool,
            "admin",
            "admin",
            &["read", "admin:read", "admin:write"],
        )
        .await;

        create_rule(&app, &admin, "Be kind", None).await;
        create_rule(&app, &admin, "No spam", None).await;
        create_rule(&app, &admin, "No bigotry", None).await;

        let rules = admin_rules(&app, &admin).await;
        assert_eq!(ordinals(&rules), vec![0, 1, 2], "rules were {rules:?}");
        assert_eq!(rules[2]["text"], json!("No bigotry"));
    })
    .await;
}

#[tokio::test]
async fn reordering_shifts_the_others_without_duplicating_a_position() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let admin = staff(
            &pool,
            "admin",
            "admin",
            &["read", "admin:read", "admin:write"],
        )
        .await;

        let first = create_rule(&app, &admin, "First", None).await;
        create_rule(&app, &admin, "Second", None).await;
        create_rule(&app, &admin, "Third", None).await;

        // Move the first rule to the end; the other two close the gap in one transaction.
        let (status, body) = send(
            &app,
            &admin,
            "PUT",
            &format!("/api/v1/admin/rules/{first}"),
            Some(json!({ "ordinal": 2 })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(json_of(&body)["ordinal"], json!(2));

        let rules = admin_rules(&app, &admin).await;
        assert_eq!(ordinals(&rules), vec![0, 1, 2], "rules were {rules:?}");
        let texts: Vec<&str> = rules
            .iter()
            .map(|rule| rule["text"].as_str().expect("text"))
            .collect();
        assert_eq!(texts, vec!["Second", "Third", "First"]);

        // Moving one rule must not leave two rows claiming the same position.
        let positions: std::collections::HashSet<i64> = ordinals(&rules).into_iter().collect();
        assert_eq!(
            positions.len(),
            rules.len(),
            "duplicate position: {rules:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_report_stores_its_rule_ids_and_rejects_an_unknown_one() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let admin = staff(
            &pool,
            "admin",
            "admin",
            &["read", "admin:read", "admin:write"],
        )
        .await;
        let reporter = create_account(&pool, "reporter").await;
        let token = create_token(&pool, &reporter, &["read", "write"]).await;
        let target = create_account(&pool, "target").await;

        let rule = create_rule(&app, &admin, "Be kind", None).await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/reports",
            Some(json!({
                "account_id": target,
                "comment": "this post is cruel",
                "rule_ids": rule,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let report = json_of(&body);
        assert_eq!(report["rule_ids"], json!([rule]), "body was {body}");
        assert_eq!(report["rules"][0]["id"], json!(rule));
        assert_eq!(report["rules"][0]["text"], json!("Be kind"));
        assert_eq!(report["missing_rule_ids"], json!([]));
        let report_id = report["id"].as_str().expect("report id").to_owned();

        // The queue shows the same citation with its current text.
        let (status, body) = send(&app, &admin, "GET", "/api/v1/admin/reports", None).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let queue = json_of(&body);
        let enqueued = queue
            .as_array()
            .expect("queue")
            .iter()
            .find(|row| row["id"] == json!(report_id))
            .expect("the report reached the queue");
        assert_eq!(enqueued["rule_ids"], json!([rule]));

        // An id that names nothing is the request's mistake, and the error names it.
        let unknown = "01JZZZZZZZZZZZZZZZZZZZZZZZ".to_lowercase();
        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/reports",
            Some(json!({
                "account_id": target,
                "comment": "cites a rule nobody wrote",
                "rule_ids": unknown,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body was {body}");
        assert!(body.contains(&unknown), "the error names the id: {body}");
    })
    .await;
}

#[tokio::test]
async fn a_deleted_rule_leaves_the_citation_and_is_marked_missing() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let admin = staff(
            &pool,
            "admin",
            "admin",
            &["read", "admin:read", "admin:write"],
        )
        .await;
        let reporter = create_account(&pool, "reporter").await;
        let token = create_token(&pool, &reporter, &["read", "write"]).await;
        let target = create_account(&pool, "target").await;

        let rule = create_rule(&app, &admin, "Temporary rule", None).await;
        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/reports",
            Some(json!({ "account_id": target, "rule_ids": rule })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let report_id = json_of(&body)["id"].as_str().expect("report id").to_owned();

        let (status, _) = send(
            &app,
            &admin,
            "DELETE",
            &format!("/api/v1/admin/rules/{rule}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (status, body) = send(&app, &admin, "GET", "/api/v1/admin/reports", None).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let queue = json_of(&body);
        let report = queue
            .as_array()
            .expect("queue")
            .iter()
            .find(|row| row["id"] == json!(report_id))
            .expect("the report is still in the queue");
        assert_eq!(
            report["rule_ids"],
            json!([rule]),
            "the citation is kept: {report:?}"
        );
        assert_eq!(report["missing_rule_ids"], json!([rule]));
        assert_eq!(report["rules"][0]["id"], json!(rule));
        assert!(
            report["rules"][0]["text"].is_null(),
            "a deleted rule has no text to show: {report:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_read_only_token_cannot_create_or_reorder() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let admin = staff(
            &pool,
            "admin",
            "admin",
            &["read", "admin:read", "admin:write"],
        )
        .await;
        let rule = create_rule(&app, &admin, "Be kind", None).await;

        // An administrator who only granted the read scope can look, and nothing else.
        let reader = staff(&pool, "reader", "admin", &["read", "admin:read"]).await;
        let (status, body) = send(&app, &reader, "GET", "/api/v1/admin/rules", None).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");

        let (status, body) = send(
            &app,
            &reader,
            "POST",
            "/api/v1/admin/rules",
            Some(json!({ "text": "Sneaky" })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "body was {body}");

        let (status, body) = send(
            &app,
            &reader,
            "PUT",
            &format!("/api/v1/admin/rules/{rule}"),
            Some(json!({ "ordinal": 0 })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "body was {body}");

        let (status, body) = send(
            &app,
            &reader,
            "DELETE",
            &format!("/api/v1/admin/rules/{rule}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "body was {body}");

        // Nothing above wrote anything: the list is what the admin left behind.
        assert_eq!(admin_rules(&app, &admin).await.len(), 1);
    })
    .await;
}
