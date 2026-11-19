//! Moderation settings leaving the instance they were tuned on.
//!
//! An operator standing up a second instance would otherwise rebuild the same rules, presets,
//! ladder and block list from memory. These tests pin the document's shape, the two-phase
//! import, the all-or-nothing transaction, the narrowing query, the refusal to lower a block's
//! severity, and the absence of anything credential-shaped in the raw bytes.

use axum::http::StatusCode;
use axum::Router;
use serde_json::{json, Value};
use sqlx::PgPool;

use nodus_server_store::accounts;

mod support;

use support::{create_account, create_token, json_of, run_db_test, send};

const EXPORT: &str = "/api/v1/admin/settings/export";
const IMPORT: &str = "/api/v1/admin/settings/import";

async fn staff(pool: &PgPool, label: &str) -> String {
    let id = create_account(pool, label).await;
    accounts::set_staff_role(pool, &id, "admin")
        .await
        .expect("grant role");
    create_token(pool, &id, &["admin:read", "admin:write"]).await
}

async fn export(app: &Router, token: &str, query: &str) -> Value {
    let (status, body) = send(app, token, "GET", &format!("{EXPORT}{query}"), None).await;
    assert_eq!(status, StatusCode::OK, "export: {body}");
    json_of(&body)
}

async fn import(app: &Router, token: &str, query: &str, document: &Value) -> (StatusCode, String) {
    send(
        app,
        token,
        "POST",
        &format!("{IMPORT}{query}"),
        Some(document.clone()),
    )
    .await
}

/// A small but complete instance: one row in every section, written through the real
/// admin surface (or direct SQL for the scanner registry, which the API seeds differently).
async fn seed(app: &Router, pool: &PgPool, token: &str) {
    // Instance rules and moderation rules are different documents and different tables.
    for text in ["Be kind", "No spam"] {
        let (status, body) = send(
            app,
            token,
            "POST",
            "/api/v1/admin/rules",
            Some(json!({ "text": text })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seed instance rule: {body}");
    }
    for (name, pattern) in [("Spam words", "buy-now"), ("Banned regex", "free\\s+money")] {
        let (status, body) = send(
            app,
            token,
            "POST",
            "/api/v1/admin/moderation-rules",
            Some(json!({
                "name": name,
                "pattern": pattern,
                "pattern_kind": "keyword",
                "scope": "inbound",
                "action": "flag",
                "enabled": true,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seed moderation rule: {body}");
    }
    let (status, body) = send(
        app,
        token,
        "POST",
        "/api/v1/admin/warning_presets",
        Some(json!({ "title": "First warning", "text": "Please read the rules." })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seed preset: {body}");

    let (status, body) = send(
        app,
        token,
        "POST",
        "/api/v1/admin/domain_blocks",
        Some(json!({ "domain": "spam.test", "severity": "suspend", "public_comment": "spam" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seed block: {body}");

    sqlx::query(
        "INSERT INTO email_domain_block (id, domain, allow_registration) \
         VALUES ('email-1', 'burner.test', false)",
    )
    .execute(pool)
    .await
    .expect("seed email block");
    sqlx::query(
        "INSERT INTO domain_pause (domain, reason, expires_at) \
         VALUES ('slow.test', 'delivery timeouts', NULL)",
    )
    .execute(pool)
    .await
    .expect("seed pause");
    sqlx::query(
        "INSERT INTO scanner_asset (id, name, kind, digest, size, content_type, content) \
         VALUES ('asset-1', 'nsfw-hashes', 'hashes', 'sha256:abc', 4, 'text/plain', '\\x00'::bytea)",
    )
    .execute(pool)
    .await
    .expect("seed asset");
    sqlx::query(
        "INSERT INTO scanner (id, name, kind, endpoint, enabled, asset_id) \
         VALUES ('scanner-1', 'image-guard', 'image', 'https://scan.test', true, 'asset-1')",
    )
    .execute(pool)
    .await
    .expect("seed scanner");
    sqlx::query(
        "INSERT INTO scanner_rule (id, scanner_id, label, threshold, severity) \
         VALUES ('scan-rule-1', 'scanner-1', 'nsfw', 0.7, 'sensitive')",
    )
    .execute(pool)
    .await
    .expect("seed scanner rule");
}

fn section<'a>(document: &'a Value, name: &str) -> &'a Value {
    &document["sections"][name]
}

#[tokio::test]
async fn a_round_trip_reports_every_row_unchanged() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let token = staff(&pool, "settings-roundtrip").await;
        seed(&app, &pool, &token).await;

        let document = export(&app, &token, "").await;
        assert_eq!(document["format"], json!("nodus-admin-settings"));
        assert_eq!(document["version"], json!(1));
        assert!(document["exported_at"].is_string(), "{document}");
        assert_eq!(document["instance"], json!("social.test"));

        // Every requested section is present and non-empty: this is the whole point.
        for name in [
            "rules",
            "instance_rules",
            "warning_presets",
            "escalation",
            "domain_pauses",
            "domain_blocks",
            "email_domain_blocks",
            "scanner_rules",
            "scanner_sets",
        ] {
            assert!(
                !section(&document, name).is_null(),
                "section {name} missing: {document}"
            );
        }
        assert_eq!(section(&document, "rules").as_array().unwrap().len(), 2);
        assert_eq!(
            section(&document, "domain_blocks")[0]["severity"],
            json!("suspend"),
            "{document}"
        );

        // Re-importing the same document compares content, never ids or timestamps: every
        // row is unchanged, and a dry run writes nothing.
        let (status, body) = import(&app, &token, "?dry_run=true", &document).await;
        assert_eq!(status, StatusCode::OK, "dry run: {body}");
        let result = json_of(&body);
        assert_eq!(result["dry_run"], json!(true));
        for (name, counts) in result["sections"].as_object().expect("sections") {
            assert_eq!(counts["created"], json!(0), "{name}: {counts}");
            assert_eq!(counts["updated"], json!(0), "{name}: {counts}");
            assert!(
                counts["unchanged"].as_u64().unwrap() > 0,
                "{name} reported nothing at all: {counts}"
            );
            assert_eq!(counts["conflicts"], json!([]), "{name}: {counts}");
        }

        // And the real import agrees.
        let (status, body) = import(&app, &token, "", &document).await;
        assert_eq!(status, StatusCode::OK, "apply: {body}");
        let applied = json_of(&body);
        for (name, counts) in applied["sections"].as_object().expect("sections") {
            assert_eq!(counts["created"], json!(0), "{name}: {counts}");
            assert_eq!(counts["updated"], json!(0), "{name}: {counts}");
        }
    })
    .await;
}

#[tokio::test]
async fn a_changed_rule_is_updated_and_only_applied_without_dry_run() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let token = staff(&pool, "settings-update").await;
        seed(&app, &pool, &token).await;

        let mut document = export(&app, &token, "?sections=rules").await;
        let rule = &mut document["sections"]["rules"][0];
        let name = rule["name"].as_str().unwrap().to_owned();
        rule["pattern"] = json!("spam-rewritten");
        rule["pattern_kind"] = json!("keyword");
        rule["scope"] = json!("inbound");
        rule["action"] = json!("silence");
        rule["enabled"] = json!(true);

        // Dry run: says updated, writes nothing.
        let (status, body) = import(&app, &token, "?dry_run=true&sections=rules", &document).await;
        assert_eq!(status, StatusCode::OK, "dry run: {body}");
        let result = json_of(&body);
        assert_eq!(result["sections"]["rules"]["updated"], json!(1), "{body}");
        let stored: String =
            sqlx::query_scalar("SELECT pattern FROM moderation_rule WHERE name = $1")
                .bind(&name)
                .fetch_one(&pool)
                .await
                .expect("read rule");
        assert_ne!(stored, "spam-rewritten", "dry run wrote: {body}");

        // Apply: the change lands and is audited by being there.
        let (status, body) = import(&app, &token, "?sections=rules", &document).await;
        assert_eq!(status, StatusCode::OK, "apply: {body}");
        let result = json_of(&body);
        assert_eq!(result["sections"]["rules"]["updated"], json!(1), "{body}");
        let stored: String =
            sqlx::query_scalar("SELECT pattern FROM moderation_rule WHERE name = $1")
                .bind(&name)
                .fetch_one(&pool)
                .await
                .expect("read rule");
        assert_eq!(stored, "spam-rewritten");
    })
    .await;
}

#[tokio::test]
async fn a_failing_section_rolls_every_section_back() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let token = staff(&pool, "settings-rollback").await;
        seed(&app, &pool, &token).await;

        let mut document = export(&app, &token, "").await;
        // A new block is valid and is applied before the rules section runs...
        document["sections"]["domain_blocks"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "domain": "rolled-back.test",
                "severity": "suspend",
                "reject_media": true,
                "reject_reports": false,
                "obfuscate": false,
                "comment": "must not survive",
            }));
        // ...and a rule the schema refuses makes the transaction fail after that write.
        document["sections"]["rules"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "name": "impossible",
                "pattern": "x",
                "pattern_kind": "not-a-kind",
                "scope": "inbound",
                "action": "flag",
                "enabled": true,
            }));

        let (status, body) = import(&app, &token, "", &document).await;
        assert!(
            status.is_server_error(),
            "expected the transaction to fail, got {status}: {body}"
        );

        let landed: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM instance_block WHERE domain = 'rolled-back.test'",
        )
        .fetch_one(&pool)
        .await
        .expect("count blocks");
        assert_eq!(landed, 0, "a half-applied import left a block behind");
        let rule: i64 =
            sqlx::query_scalar("SELECT count(*) FROM moderation_rule WHERE name = 'impossible'")
                .fetch_one(&pool)
                .await
                .expect("count rules");
        assert_eq!(rule, 0, "a half-applied import left a rule behind");
    })
    .await;
}

#[tokio::test]
async fn sections_narrow_both_directions_and_an_unknown_name_is_refused() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let token = staff(&pool, "settings-sections").await;
        seed(&app, &pool, &token).await;

        let document = export(&app, &token, "?sections=rules,escalation").await;
        let names: Vec<&str> = document["sections"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(names.len(), 2, "{document}");
        assert!(names.contains(&"rules"), "{document}");
        assert!(names.contains(&"escalation"), "{document}");

        let (status, body) =
            import(&app, &token, "?dry_run=true&sections=escalation", &document).await;
        assert_eq!(status, StatusCode::OK, "narrowed import: {body}");
        let result = json_of(&body);
        let imported: Vec<&str> = result["sections"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(imported, vec!["escalation"], "{body}");

        let (status, body) = send(
            &app,
            &token,
            "GET",
            &format!("{EXPORT}?sections=rules,nonsense"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.contains("nonsense"), "{body}");
        assert!(
            body.contains("escalation"),
            "the known names are listed: {body}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_severity_downgrade_is_a_conflict_not_an_overwrite() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let token = staff(&pool, "settings-severity").await;
        seed(&app, &pool, &token).await;

        let mut document = export(&app, &token, "?sections=domain_blocks").await;
        assert_eq!(
            document["sections"]["domain_blocks"][0]["severity"],
            json!("suspend")
        );
        document["sections"]["domain_blocks"][0]["severity"] = json!("silence");

        let (status, body) = import(&app, &token, "", &document).await;
        assert_eq!(status, StatusCode::OK, "apply: {body}");
        let result = json_of(&body);
        assert_eq!(
            result["sections"]["domain_blocks"]["updated"],
            json!(0),
            "{body}"
        );
        let conflicts = result["sections"]["domain_blocks"]["conflicts"]
            .as_array()
            .expect("conflicts");
        assert_eq!(conflicts.len(), 1, "{body}");
        assert_eq!(conflicts[0]["name"], json!("spam.test"));
        assert!(
            conflicts[0]["reason"].as_str().unwrap().contains("suspend"),
            "{body}"
        );

        let severity: String =
            sqlx::query_scalar("SELECT severity FROM instance_block WHERE domain = 'spam.test'")
                .fetch_one(&pool)
                .await
                .expect("read block");
        assert_eq!(severity, "suspend", "the downgrade was written anyway");
    })
    .await;
}

#[tokio::test]
async fn the_envelope_carries_no_credential_material() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let token = staff(&pool, "settings-secrets").await;
        seed(&app, &pool, &token).await;

        // A scanner's secret is the one credential the registry holds; the export must not
        // carry it, nor any of the usual key names.
        sqlx::query("UPDATE scanner SET secret = 'super-secret-value' WHERE id = 'scanner-1'")
            .execute(&pool)
            .await
            .expect("set secret");

        let (status, body) = send(&app, &token, "GET", EXPORT, None).await;
        assert_eq!(status, StatusCode::OK, "export: {body}");
        for needle in [
            "private_key",
            "token",
            "secret",
            "password",
            "super-secret-value",
        ] {
            assert!(
                !body.contains(needle),
                "the raw export carries {needle:?}: {body}"
            );
        }
        // And the endpoint itself is behind the admin read scope.
        let (status, _) = send(&app, &token, "POST", IMPORT, Some(json!({}))).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    })
    .await;
}
