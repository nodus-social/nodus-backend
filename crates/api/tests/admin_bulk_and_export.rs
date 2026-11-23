//! Bulk moderation and the audit export.
//!
//! A moderator selects a page of accounts or reports, not one row at a time, and the audit
//! trail has to leave the console. These tests pin the contract that makes both safe: one
//! transaction per request, a result per id, one audit row per applied id, and a CSV whose
//! free text cannot escape its column.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

use nodus_server_store::accounts;
use nodus_server_store::moderation::{self, NewReport};

mod support;

use support::{create_account, create_token, json_of, run_db_test, send};

/// A staff account and a token carrying exactly the scopes under test.
async fn staff(pool: &PgPool, label: &str, role: &str, scopes: &[&str]) -> (String, String) {
    let id = create_account(pool, label).await;
    accounts::set_staff_role(pool, &id, role)
        .await
        .expect("grant role");
    let token = create_token(pool, &id, scopes).await;
    (id, token)
}

/// A GET that keeps the headers, which is how the CSV's content type is checked.
async fn get_with_headers(app: &Router, token: &str, uri: &str) -> (StatusCode, String, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router response");
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (
        status,
        content_type,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn bulk_suspend_applies_every_account_and_writes_every_audit_row() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (actor, token) =
            staff(pool, "bulk-admin", "admin", &["admin:read", "admin:write"]).await;
        let ids = vec![
            create_account(pool, "bulk-a").await,
            create_account(pool, "bulk-b").await,
            create_account(pool, "bulk-c").await,
        ];

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/admin/accounts/bulk",
            Some(json!({
                "ids": ids,
                "action": "suspend",
                "reason": "coordinated brigading",
                "notify": false,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "batch refused: {body}");

        let value = json_of(&body);
        assert_eq!(value["applied"], json!(3), "body: {body}");
        let results = value["results"].as_array().expect("results array");
        assert_eq!(results.len(), 3);
        assert!(
            results.iter().all(|row| row["ok"] == json!(true)),
            "body: {body}"
        );

        let suspended: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM account \
             WHERE id = ANY($1) AND suspended_at IS NOT NULL",
        )
        .bind(ids.clone())
        .fetch_one(pool)
        .await
        .expect("count suspended");
        assert_eq!(suspended, 3, "every selected account is suspended");

        // One row per applied account, carrying the actor, the target and the reason.
        let rows: Vec<(Option<String>, Option<String>, String)> = sqlx::query_as(
            "SELECT target_id, actor_id, detail->>'text' FROM audit_log \
             WHERE action = 'account_suspend' AND target_id = ANY($1)",
        )
        .bind(ids.clone())
        .fetch_all(pool)
        .await
        .expect("audit rows");
        assert_eq!(rows.len(), 3, "one audit row per applied account");
        for (target, written_by, reason) in rows {
            assert!(ids.contains(&target.expect("target id")));
            assert_eq!(written_by.as_deref(), Some(actor.as_str()));
            assert_eq!(reason, "coordinated brigading");
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_batch_with_one_missing_id_applies_the_rest_and_names_the_failure() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, token) = staff(pool, "bulk-admin", "admin", &["admin:read", "admin:write"]).await;
        let first = create_account(pool, "bulk-first").await;
        let second = create_account(pool, "bulk-second").await;
        let missing = "no-such-account-id".to_owned();

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/admin/accounts/bulk",
            Some(json!({
                "ids": [first, missing, second],
                "action": "silence",
                "reason": "spam wave",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");

        let value = json_of(&body);
        assert_eq!(value["applied"], json!(2), "body: {body}");
        let results = value["results"].as_array().expect("results array");
        assert_eq!(results.len(), 3);
        assert_eq!(results[0]["ok"], json!(true));
        assert_eq!(results[1]["account_id"], json!("no-such-account-id"));
        assert_eq!(results[1]["ok"], json!(false));
        let error = results[1]["error"].as_str().expect("error message");
        assert!(error.contains("does not exist"), "error was: {error}");
        assert_eq!(results[2]["ok"], json!(true));

        let silenced: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM account \
             WHERE id = ANY($1) AND silenced_at IS NOT NULL",
        )
        .bind(vec![first, second])
        .fetch_one(pool)
        .await
        .expect("count silenced");
        assert_eq!(silenced, 2);

        let audit: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM audit_log WHERE action = 'account_silence'",
        )
        .fetch_one(pool)
        .await
        .expect("count audit");
        assert_eq!(audit, 2, "a failed id writes no audit row");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_batch_over_the_cap_is_refused_before_anything_is_touched() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, token) = staff(pool, "bulk-admin", "admin", &["admin:read", "admin:write"]).await;
        let real = create_account(pool, "bulk-capped").await;

        let mut ids = vec![real.clone()];
        ids.extend((0..100).map(|n| format!("imaginary-{n}")));
        assert_eq!(ids.len(), 101);

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/admin/accounts/bulk",
            Some(json!({"ids": ids, "action": "suspend", "reason": "too many"})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "101 ids must be a 422: {body}"
        );
        assert!(
            body.contains("at most 100"),
            "the refusal must name the limit: {body}"
        );

        let suspended: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM account WHERE id = $1 AND suspended_at IS NOT NULL",
        )
        .bind(&real)
        .fetch_one(pool)
        .await
        .expect("count suspended");
        assert_eq!(suspended, 0, "nothing is applied past the cap");
        let audit: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM audit_log WHERE action = 'account_suspend'",
        )
        .fetch_one(pool)
        .await
        .expect("count audit");
        assert_eq!(audit, 0);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_only_grant_is_refused_both_batches() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, token) = staff(pool, "bulk-reader", "moderator", &["admin:read"]).await;
        let target = create_account(pool, "bulk-target").await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/admin/accounts/bulk",
            Some(json!({"ids": [target], "action": "suspend"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/admin/reports/bulk",
            Some(json!({"ids": ["whatever"], "action": "resolve"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");

        // The reader may still export the trail: exporting is reading.
        let (status, content_type, _) =
            get_with_headers(&app, &token, "/api/v1/admin/audit.csv").await;
        assert_eq!(status, StatusCode::OK);
        assert!(content_type.starts_with("text/csv"), "was: {content_type}");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sensitive_marks_media_and_an_unsuspend_keeps_the_earlier_decision_on_record() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, token) = staff(pool, "bulk-admin", "admin", &["admin:read", "admin:write"]).await;
        let target = create_account(pool, "bulk-media").await;

        // Suspend, then lift it. The audit trail must keep both sentences rather than
        // rewriting the first one: that is what `apply_action_noted` writes per id.
        for (action, reason) in [("suspend", "spam wave"), ("unsuspend", "appeal upheld")] {
            let (status, body) = send(
                &app,
                &token,
                "POST",
                "/api/v1/admin/accounts/bulk",
                Some(json!({"ids": [target], "action": action, "text": reason})),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{action}: {body}");
            assert_eq!(json_of(&body)["applied"], json!(1), "{action}: {body}");
        }
        let still_suspended: bool = sqlx::query_scalar(
            "SELECT suspended_at IS NOT NULL FROM account WHERE id = $1",
        )
        .bind(&target)
        .fetch_one(pool)
        .await
        .expect("read suspension");
        assert!(!still_suspended, "the unsuspend lifted the suspension");
        let history: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT action, detail->>'text' FROM audit_log \
             WHERE target_id = $1 AND action IN ('account_suspend', 'account_unsuspend') \
             ORDER BY created_at",
        )
        .bind(&target)
        .fetch_all(pool)
        .await
        .expect("audit history");
        assert_eq!(history.len(), 2, "both decisions stay on the record");
        assert_eq!(history[0].0, "account_suspend");
        assert_eq!(history[0].1.as_deref(), Some("spam wave"));
        assert_eq!(history[1].0, "account_unsuspend");
        assert_eq!(history[1].1.as_deref(), Some("appeal upheld"));

        // Marking media sensitive is the third action shape: it changes no restriction.
        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/admin/accounts/bulk",
            Some(json!({"ids": [target], "action": "sensitive", "text": "nsfw under a joke"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "sensitive: {body}");
        let marked: bool =
            sqlx::query_scalar("SELECT sensitized_at IS NOT NULL FROM account WHERE id = $1")
                .bind(&target)
                .fetch_one(pool)
                .await
                .expect("read sensitive flag");
        assert!(marked, "the sensitive action sets the flag");
        let audit: Option<String> = sqlx::query_scalar(
            "SELECT detail->>'text' FROM audit_log \
             WHERE target_id = $1 AND action = 'account_sensitive'",
        )
        .bind(&target)
        .fetch_one(pool)
        .await
        .expect("sensitive audit row");
        assert_eq!(audit.as_deref(), Some("nsfw under a joke"));

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/admin/accounts/bulk",
            Some(json!({"ids": [target], "action": "unsensitive"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unsensitive: {body}");
        let still_marked: bool =
            sqlx::query_scalar("SELECT sensitized_at IS NOT NULL FROM account WHERE id = $1")
                .bind(&target)
                .fetch_one(pool)
                .await
                .expect("read sensitive flag");
        assert!(!still_marked, "unsensitive clears it");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_audit_csv_quotes_free_text_and_honours_the_filter() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (actor, token) = staff(pool, "csv-reader", "moderator", &["admin:read"]).await;
        let target = create_account(pool, "csv-target").await;

        moderation::audit(
            pool,
            &actor,
            "batch_alpha",
            "account",
            Some(&target),
            &json!({"text": "spam, blatant\nsecond line"}),
        )
        .await
        .expect("write alpha");
        moderation::audit(
            pool,
            &actor,
            "batch_beta",
            "report",
            None,
            &json!({"note": "quiet"}),
        )
        .await
        .expect("write beta");

        let (status, content_type, body) =
            get_with_headers(&app, &token, "/api/v1/admin/audit.csv?action=batch_alpha").await;
        assert_eq!(status, StatusCode::OK, "csv body: {body}");
        assert!(content_type.starts_with("text/csv"), "was: {content_type}");

        let header_row = body.split("\r\n").next().expect("header row").to_owned();
        assert_eq!(
            header_row,
            "id,created_at,actor_id,action,target_type,target_id,reason,detail"
        );
        assert!(body.contains("batch_alpha"), "row missing: {body}");
        assert!(
            !body.contains("batch_beta"),
            "the action filter was ignored: {body}"
        );
        // A comma and a newline in the reason stay inside one quoted cell.
        assert!(
            body.contains("\"spam, blatant\nsecond line\""),
            "the reason was not quoted: {body}"
        );
        // The header and exactly one entry were written.
        assert_eq!(body.matches("batch_alpha").count(), 1, "body: {body}");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn bulk_resolve_closes_the_selected_reports_and_audits_each_one() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (actor, token) = staff(
            pool,
            "bulk-mod",
            "moderator",
            &["admin:read", "admin:write"],
        )
        .await;
        let reporter = create_account(pool, "bulk-reporter").await;
        let target = create_account(pool, "bulk-reported").await;

        let mut reports = Vec::new();
        for category in ["spam", "harassment"] {
            let row = moderation::create_report(
                pool,
                &NewReport {
                    account_id: Some(&reporter),
                    target_account_id: &target,
                    status_ids: &[],
                    category,
                    comment: "",
                    rule_ids: &[],
                    activity_uri: None,
                },
            )
            .await
            .expect("create report");
            reports.push(row.id);
        }

        let mut ids = reports.clone();
        ids.push("no-such-report".to_owned());
        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/admin/reports/bulk",
            Some(json!({"ids": ids, "action": "resolve", "note": "reviewed"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");

        let value = json_of(&body);
        assert_eq!(value["applied"], json!(2), "body: {body}");
        let results = value["results"].as_array().expect("results array");
        assert_eq!(results.len(), 3);
        assert_eq!(results[2]["ok"], json!(false));
        assert!(results[2]["error"]
            .as_str()
            .expect("error")
            .contains("does not exist"));

        let resolved: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM report \
             WHERE id = ANY($1) AND state = 'resolved' AND action_taken_by_account_id = $2",
        )
        .bind(reports)
        .bind(&actor)
        .fetch_one(pool)
        .await
        .expect("count resolved");
        assert_eq!(resolved, 2);

        let audited: Vec<(Option<String>, String)> = sqlx::query_as(
            "SELECT target_id, detail->>'note' FROM audit_log \
             WHERE action = 'resolve_report_with_note' AND target_type = 'report'",
        )
        .fetch_all(pool)
        .await
        .expect("audit rows");
        assert_eq!(audited.len(), 2, "one audit row per resolved report");
        for (_, note) in audited {
            assert_eq!(note, "reviewed");
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_batch_from_a_report_closes_it_and_keeps_each_accounts_history() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, token) = staff(pool, "bulk-case", "admin", &["admin:read", "admin:write"]).await;
        let reporter = create_account(pool, "case-reporter").await;
        let target = create_account(pool, "case-target").await;

        let report = moderation::create_report(
            pool,
            &NewReport {
                account_id: Some(&reporter),
                target_account_id: &target,
                status_ids: &[],
                category: "spam",
                comment: "",
                rule_ids: &[],
                activity_uri: None,
            },
        )
        .await
        .expect("create report");

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/admin/accounts/bulk",
            Some(json!({
                "ids": [target],
                "action": "suspend",
                "text": "spam run",
                "report_id": report.id,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "batch refused: {body}");
        assert_eq!(json_of(&body)["applied"], json!(1));

        let resolved: Option<String> = sqlx::query_scalar(
            "SELECT state FROM report WHERE id = $1",
        )
        .bind(&report.id)
        .fetch_one(pool)
        .await
        .expect("report state");
        assert_eq!(resolved.as_deref(), Some("resolved"));

        // Lifting the restriction must not erase the case: both decisions stay in the
        // audit trail, and the report's own audit row is there too.
        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/admin/accounts/bulk",
            Some(json!({"ids": [target], "action": "unsuspend", "text": "appeal upheld"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unsuspend refused: {body}");

        let actions: Vec<String> = sqlx::query_scalar(
            "SELECT action FROM audit_log WHERE target_id = $1 ORDER BY created_at",
        )
        .bind(&target)
        .fetch_all(pool)
        .await
        .expect("account audit rows");
        assert_eq!(actions, vec!["account_suspend", "account_unsuspend"]);
        let report_rows: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM audit_log \
             WHERE action = 'resolve_report_with_note' AND target_id = $1",
        )
        .bind(&report.id)
        .fetch_one(pool)
        .await
        .expect("report audit row");
        assert_eq!(report_rows, 1);
        let suspended: Option<String> = sqlx::query_scalar(
            "SELECT suspended_at::text FROM account WHERE id = $1",
        )
        .bind(&target)
        .fetch_one(pool)
        .await
        .expect("account state");
        assert!(suspended.is_none(), "the account is no longer suspended");
    })
    .await;
}
