//! Rules that act by themselves, and the trail they must leave.
//!
//! The tests drive the seam the ingest path itself calls — `rulewatch::screen`, invoked at
//! the end of `store_note_extras` for arrivals and from `publish`/the Misskey note route
//! for local posts — so what is asserted here is what a delivery does, without needing a
//! signed inbox request to say it.
//!
//! Three of these tests are about the trail rather than the action: a fired rule counts a
//! hit, writes an audit row and opens a queue entry that names it, and disabling the rule
//! afterwards removes none of the three.

use axum::http::StatusCode;
use axum::Router;
use serde_json::{json, Value};
use sqlx::PgPool;

use nodus_server_store::accounts;

mod support;

use support::{create_account, create_status, create_token, json_of, run_db_test, send, send_anon};

/// A staff account holding exactly the scopes under test.
async fn staff(pool: &PgPool, label: &str, scopes: &[&str]) -> String {
    let id = create_account(pool, label).await;
    accounts::set_staff_role(pool, &id, "admin")
        .await
        .expect("grant role");
    create_token(pool, &id, scopes).await
}

/// Creates a rule through the API, the way the console does, and returns its id.
async fn create_rule(app: &Router, token: &str, body: Value) -> String {
    let (status, body) = send(
        app,
        token,
        "POST",
        "/api/v1/admin/moderation-rules",
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create rule: {body}");
    json_of(&body)["id"].as_str().expect("rule id").to_owned()
}

async fn hits(pool: &PgPool, rule: &str) -> i64 {
    sqlx::query_scalar("SELECT hits FROM moderation_rule WHERE id = $1::uuid")
        .bind(rule)
        .fetch_one(pool)
        .await
        .expect("read hits")
}

/// The audit rows a rule's firings left behind, newest last.
async fn fired_rows(pool: &PgPool, rule: &str) -> Vec<Value> {
    sqlx::query_scalar(
        "SELECT detail FROM audit_log \
         WHERE action = 'moderation_rule_fired' AND target_type = 'moderation_rule' \
             AND target_id = $1 ORDER BY created_at ASC",
    )
    .bind(rule)
    .fetch_all(pool)
    .await
    .expect("read audit rows")
}

async fn reports_for(pool: &PgPool, account: &str) -> Vec<(String, String, Vec<String>)> {
    sqlx::query_as(
        "SELECT state, comment, rule_ids FROM report WHERE target_account_id = $1 \
         ORDER BY created_at ASC",
    )
    .bind(account)
    .fetch_all(pool)
    .await
    .expect("read reports")
}

async fn is_suspended(pool: &PgPool, account: &str) -> bool {
    sqlx::query_scalar::<_, Option<chrono::DateTime<chrono::Utc>>>(
        "SELECT suspended_at FROM account WHERE id = $1",
    )
    .bind(account)
    .fetch_one(pool)
    .await
    .expect("read account")
    .is_some()
}

#[tokio::test]
async fn an_inbound_post_matching_a_keyword_rule_opens_a_flagged_report_naming_it() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let admin = staff(&pool, "rule-admin", &["admin:read", "admin:write"]).await;
        let author = create_account(&pool, "spammer").await;
        let rule = create_rule(
            &app,
            &admin,
            json!({
                "name": "Follower spam",
                "pattern": "buy-cheap-followers",
                "pattern_kind": "keyword",
                "scope": "inbound",
                "action": "flag",
            }),
        )
        .await;

        let text = "hello, buy-cheap-followers today and every day";
        let status = create_status(&pool, &author, text, "public", &[], &[]).await;
        // This is the call `store_note_extras` makes once an inbound note is stored.
        nodus_server_api::rulewatch::screen(&pool, "inbound", &status, &author, text).await;

        let reports = reports_for(&pool, &author).await;
        assert_eq!(reports.len(), 1, "one report, got {reports:?}");
        let (state, comment, rule_ids) = &reports[0];
        assert_eq!(state, "open", "a flagged post waits for a person");
        assert!(
            comment.contains("Follower spam"),
            "the queue entry names the rule: {comment}"
        );
        assert!(
            comment.contains("buy-cheap-followers"),
            "and what matched: {comment}"
        );
        assert!(
            rule_ids.is_empty(),
            "moderation rules are not instance rules: {rule_ids:?}"
        );
        assert!(
            !is_suspended(&pool, &author).await,
            "flag does not act on the account"
        );
        assert_eq!(hits(&pool, &rule).await, 1);

        let rows = fired_rows(&pool, &rule).await;
        assert_eq!(rows.len(), 1, "one audit row: {rows:?}");
        assert_eq!(rows[0]["rule_id"], json!(rule));
        assert_eq!(rows[0]["rule_name"], json!("Follower spam"));
        assert_eq!(rows[0]["matched"], json!("buy-cheap-followers"));
        assert_eq!(rows[0]["status_id"], json!(status));
    })
    .await;
}

#[tokio::test]
async fn a_suspend_rule_suspends_the_author_and_writes_the_audit_row() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let admin = staff(&pool, "rule-admin", &["admin:read", "admin:write"]).await;
        let author = create_account(&pool, "spammer").await;
        let rule = create_rule(
            &app,
            &admin,
            json!({
                "name": "Crypto shill",
                "pattern": "double-your-sats",
                "pattern_kind": "keyword",
                "scope": "both",
                "action": "suspend",
            }),
        )
        .await;

        let text = "double-your-sats in one week, guaranteed";
        let status = create_status(&pool, &author, text, "public", &[], &[]).await;
        // A local post: the publish path makes the same call with scope "local".
        nodus_server_api::rulewatch::screen(&pool, "local", &status, &author, text).await;

        assert!(
            is_suspended(&pool, &author).await,
            "the action went through moderation::apply_action_in"
        );
        let rows = fired_rows(&pool, &rule).await;
        assert_eq!(rows.len(), 1, "the suspension is explained: {rows:?}");
        assert_eq!(rows[0]["action"], json!("suspend"));
        assert_eq!(rows[0]["applied"], json!("suspend"));
        assert_eq!(rows[0]["downgraded"], json!(false));
        assert_eq!(rows[0]["account_id"], json!(author));
        assert_eq!(hits(&pool, &rule).await, 1);

        let reports = reports_for(&pool, &author).await;
        assert_eq!(reports.len(), 1);
        assert!(
            reports[0].1.contains("Crypto shill") && reports[0].1.contains("suspended"),
            "the queue says the rule suspended the account: {}",
            reports[0].1
        );
    })
    .await;
}

#[tokio::test]
async fn an_invalid_regex_is_refused_with_the_position() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let admin = staff(&pool, "rule-admin", &["admin:read", "admin:write"]).await;

        let (status, body) = send(
            &app,
            &admin,
            "POST",
            "/api/v1/admin/moderation-rules",
            Some(json!({
                "name": "Broken",
                "pattern": "spam(",
                "pattern_kind": "regex",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body was {body}");
        let answer = json_of(&body);
        let error = answer["error"].as_str().expect("error message");
        assert!(
            error.contains("parse error at byte 4"),
            "the position is named: {error}"
        );

        let (status, body) =
            send(&app, &admin, "GET", "/api/v1/admin/moderation-rules", None).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert!(
            json_of(&body).as_array().expect("list").is_empty(),
            "a pattern that cannot compile is never stored: {body}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_dry_run_reports_match_and_no_match_without_writing_anything() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let admin = staff(&pool, "rule-admin", &["admin:read", "admin:write"]).await;
        let rule = create_rule(
            &app,
            &admin,
            json!({
                "name": "Follower spam",
                "pattern": "buy-cheap-followers",
                "pattern_kind": "keyword",
                "scope": "inbound",
                "action": "flag",
                "enabled": false,
            }),
        )
        .await;

        let uri = format!("/api/v1/admin/moderation-rules/{rule}/dry-run");
        let (status, body) = send(
            &app,
            &admin,
            "POST",
            &uri,
            Some(json!({ "sample": "they said buy-cheap-followers again" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let answer = json_of(&body);
        assert_eq!(answer["matched"], json!(true), "body was {body}");
        assert_eq!(answer["rule"]["id"], json!(rule));
        assert_eq!(answer["rule"]["name"], json!("Follower spam"));
        assert_eq!(answer["span"]["start"], json!(10));
        assert_eq!(answer["span"]["end"], json!(29));
        assert_eq!(answer["span"]["text"], json!("buy-cheap-followers"));
        assert!(
            answer["reason"]
                .as_str()
                .expect("reason")
                .contains("Follower spam"),
            "the reason names the rule: {body}"
        );
        assert_eq!(answer["rule"]["enabled"], json!(false));

        let (status, body) = send(
            &app,
            &admin,
            "POST",
            &uri,
            Some(json!({ "sample": "a perfectly ordinary post" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let answer = json_of(&body);
        assert_eq!(answer["matched"], json!(false), "body was {body}");
        assert!(answer["span"].is_null(), "no match has no span: {body}");

        // A test is not an action: no hit, no audit row, no queue entry.
        assert_eq!(hits(&pool, &rule).await, 0, "the dry run counted a hit");
        assert!(
            fired_rows(&pool, &rule).await.is_empty(),
            "the dry run audited"
        );
        let reports: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM report")
            .fetch_one(&pool)
            .await
            .expect("count reports");
        assert_eq!(reports, 0, "the dry run opened a report");
    })
    .await;
}

#[tokio::test]
async fn a_disabled_rule_does_nothing() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let admin = staff(&pool, "rule-admin", &["admin:read", "admin:write"]).await;
        let author = create_account(&pool, "author").await;
        let rule = create_rule(
            &app,
            &admin,
            json!({
                "name": "Paused",
                "pattern": "buy-cheap-followers",
                "pattern_kind": "keyword",
                "action": "suspend",
                "enabled": false,
            }),
        )
        .await;

        let text = "buy-cheap-followers";
        let status = create_status(&pool, &author, text, "public", &[], &[]).await;
        nodus_server_api::rulewatch::screen(&pool, "inbound", &status, &author, text).await;

        assert!(!is_suspended(&pool, &author).await, "a paused rule acted");
        assert_eq!(hits(&pool, &rule).await, 0);
        assert!(fired_rows(&pool, &rule).await.is_empty());
        assert!(reports_for(&pool, &author).await.is_empty());

        // And a rule switched off after it fired keeps what it did.
        let (status, body) = send(
            &app,
            &admin,
            "PUT",
            &format!("/api/v1/admin/moderation-rules/{rule}"),
            Some(json!({ "enabled": true })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "enable: {body}");
        let second = create_status(&pool, &author, text, "public", &[], &[]).await;
        nodus_server_api::rulewatch::screen(&pool, "inbound", &second, &author, text).await;
        assert_eq!(hits(&pool, &rule).await, 1);

        let (status, body) = send(
            &app,
            &admin,
            "PUT",
            &format!("/api/v1/admin/moderation-rules/{rule}"),
            Some(json!({ "enabled": false })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "disable: {body}");
        assert_eq!(hits(&pool, &rule).await, 1, "disabling kept the count");
        assert_eq!(
            fired_rows(&pool, &rule).await.len(),
            1,
            "disabling kept the audit row"
        );
        assert_eq!(
            reports_for(&pool, &author).await.len(),
            1,
            "disabling kept the queue entry"
        );
    })
    .await;
}

#[tokio::test]
async fn a_long_post_is_scanned_only_up_to_the_byte_cap() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let admin = staff(&pool, "rule-admin", &["admin:read", "admin:write"]).await;
        let author = create_account(&pool, "author").await;
        let rule = create_rule(
            &app,
            &admin,
            json!({
                "name": "Follower spam",
                "pattern": "buy-cheap-followers",
                "pattern_kind": "keyword",
            }),
        )
        .await;
        let uri = format!("/api/v1/admin/moderation-rules/{rule}/dry-run");

        // The keyword sits past the cap: ingest never reads that far, so the rule must not
        // fire — a rule that scanned the whole post would be a per-delivery cost anyone
        // can choose by sending a longer post.
        let far = format!("{}{}", "a".repeat(5000), "buy-cheap-followers");
        let (status, body) = send(&app, &admin, "POST", &uri, Some(json!({ "sample": far }))).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let answer = json_of(&body);
        assert_eq!(answer["matched"], json!(false), "body was {body}");
        assert_eq!(answer["scanned_bytes"], json!(4096), "body was {body}");
        assert_eq!(answer["truncated"], json!(true), "body was {body}");

        let status_row = create_status(&pool, &author, &far, "public", &[], &[]).await;
        nodus_server_api::rulewatch::screen(&pool, "inbound", &status_row, &author, &far).await;
        assert_eq!(hits(&pool, &rule).await, 0, "the tail was never scanned");
        assert!(reports_for(&pool, &author).await.is_empty());

        // Just inside the cap it does fire, so the cap bounds the work and not the rule.
        let near = format!("{}buy-cheap-followers", "a".repeat(4000));
        let (status, body) =
            send(&app, &admin, "POST", &uri, Some(json!({ "sample": near }))).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let answer = json_of(&body);
        assert_eq!(answer["matched"], json!(true), "body was {body}");
        assert_eq!(answer["span"]["start"], json!(4000));
        assert_eq!(answer["truncated"], json!(false), "body was {body}");
    })
    .await;
}

#[tokio::test]
async fn a_post_is_tested_against_at_most_the_rule_cap() {
    run_db_test(|store, _app| async move {
        let pool = store.pool().clone();
        let author = create_account(&pool, "author").await;

        // More rules than one post may be tested against. They all match, so the number
        // that fired is the cap itself.
        for index in 0..40 {
            nodus_server_store::moderation_rules::create(
                &pool,
                &nodus_server_store::moderation_rules::NewRule {
                    name: &format!("Rule {index}"),
                    pattern: "spam",
                    pattern_kind: "keyword",
                    scope: "inbound",
                    action: "flag",
                    enabled: true,
                    created_by: None,
                },
            )
            .await
            .expect("create rule");
        }

        let text = "spam";
        let status = create_status(&pool, &author, text, "public", &[], &[]).await;
        nodus_server_api::rulewatch::screen(&pool, "inbound", &status, &author, text).await;

        let fired: i64 =
            sqlx::query_scalar("SELECT count(*)::bigint FROM moderation_rule WHERE hits > 0")
                .fetch_one(&pool)
                .await
                .expect("count fired rules");
        assert_eq!(
            fired,
            nodus_server_store::moderation_rules::RULE_CAP,
            "a post is tested against at most RULE_CAP rules"
        );
        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM audit_log WHERE action = 'moderation_rule_fired'",
        )
        .fetch_one(&pool)
        .await
        .expect("count audit rows");
        assert_eq!(rows, fired, "every firing is in the audit log");
    })
    .await;
}

#[tokio::test]
async fn every_rule_route_is_closed_to_anonymous_callers() {
    run_db_test(|_store, app| async move {
        let id = "00000000-0000-0000-0000-000000000000";
        let routes = [
            ("GET", "/api/v1/admin/moderation-rules".to_owned()),
            ("POST", "/api/v1/admin/moderation-rules".to_owned()),
            ("GET", format!("/api/v1/admin/moderation-rules/{id}")),
            ("PUT", format!("/api/v1/admin/moderation-rules/{id}")),
            ("DELETE", format!("/api/v1/admin/moderation-rules/{id}")),
            (
                "POST",
                format!("/api/v1/admin/moderation-rules/{id}/dry-run"),
            ),
        ];
        for (method, uri) in routes {
            let (status, body) = send_anon(&app, method, &uri).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}: {body}");
            assert!(
                json_of(&body)["error"].is_string(),
                "{method} {uri} answered non-JSON: {body}"
            );
        }
    })
    .await;
}
