//! Block lists that travel.
//!
//! Blocking a domain is one decision; carrying a thousand of them between instances is the
//! chore. These tests pin what makes the transfer safe to run against a live instance: an
//! export that comes back in as the same blocks, a dry run that writes nothing at all, an
//! existing block that is updated rather than duplicated, a malformed line that names
//! itself and does not take its neighbours down with it, and a subscription that is only
//! allowed to point at a public https list.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

use nodus_server_store::accounts;
use nodus_server_store::blocklist;

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

/// A block written the way the console writes one, so the export has something to carry.
async fn block(
    pool: &PgPool,
    domain: &str,
    severity: &str,
    reject_media: bool,
    reject_reports: bool,
    reject_follows: bool,
    comment: &str,
) {
    sqlx::query(
        "INSERT INTO instance_block \
         (id, domain, severity, reject_media, reject_reports, reject_follows, public_comment) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(nodus_server_core::Id::new().to_string())
    .bind(domain)
    .bind(severity)
    .bind(reject_media)
    .bind(reject_reports)
    .bind(reject_follows)
    .bind(comment)
    .execute(pool)
    .await
    .expect("insert block");
}

/// Every observable field of every block, in a stable order.
///
/// `created_at` is deliberately not part of it: the export carries the timestamp, and an
/// import cannot restore it — the row it makes is new on the instance that receives it.
async fn snapshot(pool: &PgPool) -> Vec<(String, String, bool, bool, bool, String)> {
    sqlx::query_as(
        "SELECT domain::text, severity, reject_media, reject_reports, reject_follows, \
         public_comment FROM instance_block ORDER BY domain",
    )
    .fetch_all(pool)
    .await
    .expect("read blocks")
}

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

/// A POST whose body is a file, not a form.
async fn post_raw(
    app: &Router,
    token: &str,
    uri: &str,
    content_type: &str,
    body: &str,
) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, content_type)
                .body(Body::from(body.to_owned()))
                .expect("request"),
        )
        .await
        .expect("router response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_export_imported_into_an_empty_instance_is_the_same_blocks() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, token) = staff(pool, "transfer", "admin", &["admin:read", "admin:write"]).await;

        block(
            pool,
            "spam.example",
            "suspend",
            true,
            false,
            true,
            "bulk mail, \"verified\" by nobody",
        )
        .await;
        block(pool, "loud.example", "silence", false, true, false, "").await;
        block(pool, "plain.example", "suspend", false, false, false, "").await;
        let before = snapshot(pool).await;

        let (status, content_type, csv) = get_with_headers(
            &app,
            &token,
            "/api/v1/admin/domain-blocks/export?format=csv",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "export refused: {csv}");
        assert!(
            content_type.starts_with("text/csv"),
            "content type was {content_type}"
        );
        assert!(
            csv.starts_with(
                "domain,severity,reject_media,reject_reports,reject_follows,comment,created_at\r\n"
            ),
            "header line was wrong: {csv}"
        );
        // RFC 4180: the comma and the quotes inside the comment stay inside its column.
        assert!(
            csv.contains("\"bulk mail, \"\"verified\"\" by nobody\""),
            "comment was not quoted: {csv}"
        );

        // An empty instance, then the file comes in through the ordinary route.
        sqlx::query("DELETE FROM instance_block")
            .execute(pool)
            .await
            .expect("empty the block list");
        assert_eq!(
            snapshot(pool).await,
            Vec::new(),
            "the file was applied anyway"
        );

        let (status, body) = post_raw(
            &app,
            &token,
            "/api/v1/admin/domain-blocks/import",
            "text/csv",
            &csv,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "import refused: {body}");
        let report = json_of(&body);
        assert_eq!(report["new"], json!(3), "body: {body}");
        assert_eq!(report["updated"], json!(0), "body: {body}");
        assert_eq!(report["unchanged"], json!(0), "body: {body}");
        assert_eq!(report["invalid"], json!([]), "body: {body}");

        assert_eq!(snapshot(pool).await, before, "round trip changed the list");

        // Every applied row is on the record, and the record says where it came from.
        let sources: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT action, detail->>'source' FROM audit_log \
             WHERE action IN ('create_domain_block', 'update_domain_block')",
        )
        .fetch_all(pool)
        .await
        .expect("audit rows");
        assert_eq!(sources.len(), 3, "one audit row per applied block");
        for (action, source) in sources {
            assert_eq!(action, "create_domain_block");
            assert_eq!(source.as_deref(), Some("import"));
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dry_run_reports_what_it_would_do_and_writes_nothing() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, token) = staff(pool, "dry", "admin", &["admin:read", "admin:write"]).await;
        block(pool, "known.example", "silence", false, false, false, "").await;
        let before = snapshot(pool).await;

        // One unchanged row, one row that would be rewritten, one that is new.
        let payload = json!([
            {
                "domain": "known.example",
                "severity": "silence",
                "reject_media": false,
                "reject_reports": false,
                "reject_follows": false,
                "comment": ""
            },
            {
                "domain": "known.example",
                "severity": "suspend",
                "reject_media": true,
                "reject_reports": false,
                "reject_follows": false,
                "comment": "rewritten"
            },
            {
                "domain": "fresh.example",
                "severity": "suspend",
                "reject_media": true,
                "reject_reports": true,
                "reject_follows": true,
                "comment": "new"
            }
        ]);
        // The second object repeats a domain, so the run sees the first as unchanged and the
        // second as an update of the same row: what a moderator sees is the last word.
        let (status, body) = post_raw(
            &app,
            &token,
            "/api/v1/admin/domain-blocks/import?dry_run=true",
            "application/json",
            &payload.to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "dry run refused: {body}");
        let report = json_of(&body);
        assert_eq!(report["parsed"], json!(3), "body: {body}");
        assert_eq!(report["unchanged"], json!(1), "body: {body}");
        assert_eq!(report["updated"], json!(1), "body: {body}");
        assert_eq!(report["new"], json!(1), "body: {body}");

        assert_eq!(
            snapshot(pool).await,
            before,
            "a dry run changed the block list"
        );
        let audited: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM audit_log \
             WHERE action IN ('create_domain_block', 'update_domain_block')",
        )
        .fetch_one(pool)
        .await
        .expect("audit count");
        assert_eq!(audited, 0, "a dry run wrote an audit row");

        // The same call without the flag does apply it.
        let (status, body) = post_raw(
            &app,
            &token,
            "/api/v1/admin/domain-blocks/import",
            "application/json",
            &payload.to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "import refused: {body}");
        let report = json_of(&body);
        assert_eq!(report["new"], json!(1), "body: {body}");
        assert_eq!(report["updated"], json!(1), "body: {body}");
        assert_eq!(
            snapshot(pool).await,
            vec![
                (
                    "fresh.example".to_owned(),
                    "suspend".to_owned(),
                    true,
                    true,
                    true,
                    "new".to_owned()
                ),
                (
                    "known.example".to_owned(),
                    "suspend".to_owned(),
                    true,
                    false,
                    false,
                    "rewritten".to_owned()
                ),
            ],
            "the applied import did not land as reported"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_block_that_already_exists_is_updated_not_duplicated() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, token) = staff(pool, "merge", "admin", &["admin:read", "admin:write"]).await;
        block(
            pool,
            "repeat.example",
            "silence",
            false,
            false,
            false,
            "old",
        )
        .await;

        let csv = "domain,severity,reject_media,reject_reports,reject_follows,comment\r\n\
                   repeat.example,suspend,true,true,true,newer\r\n";
        let (status, body) = post_raw(
            &app,
            &token,
            "/api/v1/admin/domain-blocks/import",
            "text/csv",
            csv,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "import refused: {body}");
        let report = json_of(&body);
        assert_eq!(report["updated"], json!(1), "body: {body}");
        assert_eq!(report["new"], json!(0), "body: {body}");

        let rows = snapshot(pool).await;
        assert_eq!(rows.len(), 1, "the domain is blocked twice: {rows:?}");
        assert_eq!(
            rows[0],
            (
                "repeat.example".to_owned(),
                "suspend".to_owned(),
                true,
                true,
                true,
                "newer".to_owned()
            )
        );

        let action: String =
            sqlx::query_scalar("SELECT action FROM audit_log WHERE target_id = 'repeat.example'")
                .fetch_one(pool)
                .await
                .expect("audit row");
        assert_eq!(action, "update_domain_block");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_line_names_itself_and_the_good_lines_still_apply() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, token) = staff(pool, "ragged", "admin", &["admin:read", "admin:write"]).await;

        let csv = "domain,severity,reject_media\r\n\
                   good.example,suspend,true\r\n\
                   not a domain,suspend,true\r\n\
                   also-good.example,silence,false\r\n\
                   loud.example,shout,true\r\n";
        let (status, body) = post_raw(
            &app,
            &token,
            "/api/v1/admin/domain-blocks/import",
            "text/csv",
            csv,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "import refused: {body}");
        let report = json_of(&body);
        assert_eq!(report["new"], json!(2), "body: {body}");
        let invalid = report["invalid"].as_array().expect("invalid array");
        assert_eq!(invalid.len(), 2, "body: {body}");
        // Line numbers count the header: the header is line 1.
        assert_eq!(invalid[0]["line"], json!(3), "body: {body}");
        assert_eq!(invalid[1]["line"], json!(5), "body: {body}");
        assert!(
            invalid[0]["reason"]
                .as_str()
                .unwrap_or("")
                .contains("domain"),
            "body: {body}"
        );

        let domains: Vec<String> = snapshot(pool).await.into_iter().map(|row| row.0).collect();
        assert_eq!(domains, vec!["also-good.example", "good.example"]);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_headerless_payload_is_refused_outright() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, token) = staff(pool, "noheader", "admin", &["admin:read", "admin:write"]).await;

        let (status, body) = post_raw(
            &app,
            &token,
            "/api/v1/admin/domain-blocks/import",
            "text/csv",
            "spam.example,suspend,true\r\n",
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "a headerless file was accepted: {body}"
        );
        let error = json_of(&body);
        assert!(
            error["error"].as_str().unwrap_or("").contains("header"),
            "body: {body}"
        );
        assert!(snapshot(pool).await.is_empty(), "{body}");
    })
    .await;
}

/// A 304 only moves the clock.
///
/// The choice, stated: a peer saying "not modified" leaves every block row and the stored
/// validators exactly as they were, and only advances `last_synced_at` (clearing
/// `last_error`). Advancing the timestamp is what keeps a healthy subscription from being
/// swept again on every tick — a poll that succeeded is evidence the peer is alive, and
/// there is nothing to re-apply. A 304 is simulated by calling the same function the sync's
/// 304 branch calls, because the outbound guard refuses a loopback TLS peer and the point
/// under test is the bookkeeping, not the socket.
#[tokio::test(flavor = "multi_thread")]
async fn a_not_modified_sync_advances_the_clock_and_leaves_the_rows_alone() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, token) = staff(pool, "etag", "admin", &["admin:read", "admin:write"]).await;
        block(pool, "kept.example", "suspend", true, false, false, "kept").await;
        let before = snapshot(pool).await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/admin/domain-blocks/subscriptions",
            Some(json!({"url": "https://lists.example/blocks.csv", "format": "csv"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "subscription refused: {body}");
        let created = json_of(&body);
        let id = created["id"].as_str().expect("id").to_owned();
        assert!(created["last_synced_at"].is_null(), "body: {body}");

        // The validators a first successful pull would have stored.
        blocklist::record_sync(
            pool,
            &id,
            Some("\"v1\""),
            Some("Wed, 21 Oct 2015 07:28:00 GMT"),
        )
        .await
        .expect("store validators");
        let synced_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
            "SELECT last_synced_at FROM domain_block_subscription WHERE id = $1",
        )
        .bind(&id)
        .fetch_one(pool)
        .await
        .expect("synced at");
        let audited_before: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM audit_log")
            .fetch_one(pool)
            .await
            .expect("audit count");

        blocklist::record_unchanged(pool, &id)
            .await
            .expect("record 304");

        let (etag, last_modified, last_error, after): (
            Option<String>,
            Option<String>,
            Option<String>,
            chrono::DateTime<chrono::Utc>,
        ) = sqlx::query_as(
            "SELECT etag, last_modified, last_error, last_synced_at \
             FROM domain_block_subscription WHERE id = $1",
        )
        .bind(&id)
        .fetch_one(pool)
        .await
        .expect("subscription row");
        assert_eq!(etag.as_deref(), Some("\"v1\""), "a 304 rewrote the etag");
        assert_eq!(
            last_modified.as_deref(),
            Some("Wed, 21 Oct 2015 07:28:00 GMT"),
            "a 304 rewrote the last-modified stamp"
        );
        assert_eq!(last_error, None, "a 304 recorded an error");
        assert!(after >= synced_at, "the clock went backwards");
        assert_eq!(snapshot(pool).await, before, "a 304 touched block rows");

        let audited_after: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM audit_log")
            .fetch_one(pool)
            .await
            .expect("audit count");
        assert_eq!(
            audited_after, audited_before,
            "a 304 wrote an audit row for a change that did not happen"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_subscription_that_is_not_public_https_is_refused() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, token) = staff(pool, "guard", "admin", &["admin:read", "admin:write"]).await;

        for url in [
            "http://lists.example/blocks.csv",
            "https://127.0.0.1/blocks.csv",
            "https://192.168.1.10/blocks.csv",
            "https://localhost/blocks.csv",
            "https://user:secret@lists.example/blocks.csv",
            "file:///etc/passwd",
        ] {
            let (status, body) = send(
                &app,
                &token,
                "POST",
                "/api/v1/admin/domain-blocks/subscriptions",
                Some(json!({ "url": url })),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{url} was accepted: {body}"
            );
        }

        let (status, body) = send(
            &app,
            &token,
            "GET",
            "/api/v1/admin/domain-blocks/subscriptions",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            json_of(&body),
            json!([]),
            "a refused URL was stored anyway: {body}"
        );
    })
    .await;
}

/// The peer is unreachable: the row says so, and the loop stays up.
#[tokio::test(flavor = "multi_thread")]
async fn a_sync_against_an_unreachable_peer_records_why_instead_of_failing_the_loop() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, token) = staff(pool, "offline", "admin", &["admin:read", "admin:write"]).await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/admin/domain-blocks/subscriptions",
            Some(json!({"url": "https://lists.invalid/blocks.csv"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "subscription refused: {body}");
        let id = json_of(&body)["id"].as_str().expect("id").to_owned();

        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/admin/domain-blocks/subscriptions/{id}/sync"),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_GATEWAY,
            "an unreachable peer did not report itself: {body}"
        );

        let last_error: Option<String> =
            sqlx::query_scalar("SELECT last_error FROM domain_block_subscription WHERE id = $1")
                .bind(&id)
                .fetch_one(pool)
                .await
                .expect("subscription row");
        assert!(
            last_error.is_some(),
            "the failure was not written down for the console to show"
        );
        // A failed pull is not a successful one: the clock stays where it was.
        let synced: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
            "SELECT last_synced_at FROM domain_block_subscription WHERE id = $1",
        )
        .bind(&id)
        .fetch_one(pool)
        .await
        .expect("subscription row");
        assert!(synced.is_none(), "a failed pull advanced the clock");
    })
    .await;
}
