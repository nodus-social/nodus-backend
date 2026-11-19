//! Being told why.
//!
//! A silence or a suspension used to exist only as an effect: the person could still sign
//! in, found nothing explaining anything, and the appeal endpoint (migration 39) was never
//! pointed at from anywhere. These tests hold the three promises that fix that:
//!
//! * every account-level decision writes a `moderation` notification naming the action, the
//!   reason, the rule when a rule decided, and the expiry when there is one;
//! * lifting a decision is its own notification, and the original stays as it was written;
//! * a warning notifies without touching the account at all.
//!
//! The rule-caused case goes through `moderation_rules::screen`, the same call the ingest
//! path makes, so the notification is proven to come from the real entry point rather than
//! from a helper only the tests use.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

use nodus_server_api::{root_router, AppState, InstanceConfig};
use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount};
use nodus_server_store::{apps, moderation_rules, Store};

fn instance_config() -> InstanceConfig {
    InstanceConfig {
        domain: "social.test".to_owned(),
        base_url: "https://social.test".to_owned(),
        title: "Nodus test".to_owned(),
        description: "A test instance".to_owned(),
        contact_email: None,
        api_version: "4.3.0".to_owned(),
        version: "0.1.0".to_owned(),
        registrations_open: false,
    }
}

async fn connect_isolated_store() -> Option<(Store, Store, String)> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let admin = Store::connect(&url, 1).await.expect("connect to postgres");
    let schema = format!("pgtest_{}", Id::new()).to_lowercase();
    sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
        .execute(admin.pool())
        .await
        .expect("create isolated test schema");

    let sep = if url.contains('?') { '&' } else { '?' };
    let schema_url = format!("{url}{sep}options=-csearch_path%3D{schema}%2Cpublic");
    let store = Store::connect(&schema_url, 5)
        .await
        .expect("connect isolated store");
    store.migrate().await.expect("run migrations");
    Some((admin, store, schema))
}

async fn run_db_test<F, Fut>(body: F)
where
    F: FnOnce(Store, Router) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some((admin, store, schema)) = connect_isolated_store().await else {
        return;
    };
    let app = root_router(AppState::new(store.clone(), instance_config()));
    let outcome = tokio::spawn(async move { body(store, app).await }).await;

    let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
        .execute(admin.pool())
        .await;

    if let Err(err) = outcome {
        std::panic::resume_unwind(err.into_panic());
    }
}

async fn create_account(pool: &PgPool, label: &str) -> String {
    let username = format!("pgtest_{label}_{}", Id::new());
    accounts::insert(
        pool,
        &NewAccount {
            username: &username,
            display_name: &username,
            note: "",
            bot: false,
            locked: false,
        },
    )
    .await
    .expect("insert account")
    .id
}

async fn create_token(pool: &PgPool, account_id: &str, scopes: &[&str]) -> String {
    let app_id = Id::new().to_string();
    let client_id = format!("pgtest-client-{app_id}");
    let owned: Vec<String> = scopes.iter().map(|scope| (*scope).to_owned()).collect();
    apps::register(
        pool,
        &app_id,
        &client_id,
        "unused",
        "pgtest",
        None,
        &["urn:ietf:wg:oauth:2.0:oob".to_owned()],
        &owned,
    )
    .await
    .expect("register app");

    let token = format!("pgtest-token-{}", Id::new());
    let digest = format!("{:x}", Sha256::digest(token.as_bytes()));
    sqlx::query(
        "INSERT INTO oauth_token (id, app_id, account_id, token_hash, scopes) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Id::new().to_string())
    .bind(&app_id)
    .bind(account_id)
    .bind(&digest)
    .bind(&owned)
    .execute(pool)
    .await
    .expect("insert oauth token");
    token
}

async fn make_staff(pool: &PgPool, account_id: &str) {
    sqlx::query("UPDATE account SET admin = true, staff_role = 'admin' WHERE id = $1")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("make staff");
}

/// `(suspended, silenced, approved)` as the database holds them now.
async fn state(pool: &PgPool, account_id: &str) -> (bool, bool, bool) {
    sqlx::query_as::<_, (bool, bool, bool)>(
        "SELECT suspended_at IS NOT NULL, silenced_at IS NOT NULL, approved \
           FROM account WHERE id = $1",
    )
    .bind(account_id)
    .fetch_one(pool)
    .await
    .expect("account state")
}

/// Every row written about this account, oldest first, as the columns the promise is
/// about. Read straight from the table so a field the API forgets to serialise still
/// fails the test.
async fn notices(pool: &PgPool, account_id: &str) -> Vec<Notice> {
    sqlx::query_as::<_, Notice>(
        "SELECT kind, note, moderation_action, moderation_reason, moderation_rule, \
                moderation_expires_at \
           FROM notification WHERE account_id = $1 ORDER BY created_at, id",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await
    .expect("notifications")
}

#[derive(Debug, sqlx::FromRow)]
struct Notice {
    kind: String,
    note: Option<String>,
    moderation_action: Option<String>,
    moderation_reason: Option<String>,
    moderation_rule: Option<String>,
    moderation_expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

async fn send(
    app: &Router,
    token: &str,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    let request = match body {
        None => builder.body(Body::empty()).expect("request"),
        Some(value) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            builder
                .body(Body::from(value.to_string()))
                .expect("request")
        }
    };
    let response = app.clone().oneshot(request).await.expect("router response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn parse(body: &str) -> Value {
    serde_json::from_str(body).expect("json body")
}

/// The `moderation` entry for one action in a notification listing.
fn moderation<'a>(items: &'a Value, action: &str) -> &'a Value {
    items
        .as_array()
        .expect("notification array")
        .iter()
        .find(|item| {
            item["type"] == "moderation" && item["moderation"]["action"] == action
        })
        .unwrap_or_else(|| panic!("no moderation notification for {action}: {items}"))
}

#[tokio::test]
async fn silencing_tells_the_person_why_and_that_they_may_appeal() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let admin = create_account(pool, "mod").await;
        make_staff(pool, &admin).await;
        let admin_token = create_token(pool, &admin, &["admin:write", "admin:read"]).await;
        let member = create_account(pool, "member").await;
        let member_token = create_token(pool, &member, &["read:notifications"]).await;

        let (status, body) = send(
            &app,
            &admin_token,
            "POST",
            &format!("/api/v1/admin/accounts/{member}/action"),
            Some(json!({ "type": "silence", "text": "a spam wave, not you" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let rows = notices(pool, &member).await;
        assert_eq!(rows.len(), 1, "one decision, one notification: {rows:?}");
        assert_eq!(rows[0].kind, "moderation");
        assert_eq!(rows[0].moderation_action.as_deref(), Some("silence"));
        assert_eq!(
            rows[0].moderation_reason.as_deref(),
            Some("a spam wave, not you")
        );
        // No rule decided, so none is named — naming one would send the person to look up
        // a rule that did not act.
        assert_eq!(rows[0].moderation_rule, None);
        // A silence here has no end date; the field says so rather than guessing one.
        assert_eq!(rows[0].moderation_expires_at, None);
        let note = rows[0].note.as_deref().expect("a sentence");
        assert!(note.contains("silenced"), "{note}");
        assert!(note.contains("a spam wave, not you"), "{note}");

        // And the person's own view says they may answer it.
        let (status, body) =
            send(&app, &member_token, "GET", "/api/v1/notifications", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let items = parse(&body);
        let notice = moderation(&items, "silence");
        assert_eq!(notice["moderation"]["reason"], "a spam wave, not you");
        assert_eq!(notice["moderation"]["can_appeal"], true);
        assert!(notice["moderation"].get("appeal").is_none(), "{notice}");
    })
    .await;
}

#[tokio::test]
async fn lifting_a_silence_is_its_own_notification_and_the_old_one_is_untouched() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let admin = create_account(pool, "mod").await;
        make_staff(pool, &admin).await;
        let admin_token = create_token(pool, &admin, &["admin:write", "admin:read"]).await;
        let member = create_account(pool, "member").await;

        let (status, body) = send(
            &app,
            &admin_token,
            "POST",
            &format!("/api/v1/admin/accounts/{member}/action"),
            Some(json!({ "type": "silence", "text": "cooling off" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let before = notices(pool, &member).await;
        assert_eq!(before.len(), 1);

        let (status, body) = send(
            &app,
            &admin_token,
            "POST",
            &format!("/api/v1/admin/accounts/{member}/action"),
            Some(json!({ "type": "unsilence" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let after = notices(pool, &member).await;
        assert_eq!(after.len(), 2, "the lift is a second sentence: {after:?}");
        // The record of what was decided stays exactly as it was written: a person can
        // still see that they were silenced and why, and then that it was undone.
        assert_eq!(after[0].moderation_action, before[0].moderation_action);
        assert_eq!(after[0].moderation_reason, before[0].moderation_reason);
        assert_eq!(after[0].note, before[0].note);
        assert_eq!(after[1].moderation_action.as_deref(), Some("unsilence"));
        let note = after[1].note.as_deref().expect("a sentence");
        assert_eq!(note, "Your silence was lifted.");
    })
    .await;
}

#[tokio::test]
async fn a_warning_is_delivered_and_changes_nothing_about_the_account() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let admin = create_account(pool, "mod").await;
        make_staff(pool, &admin).await;
        let admin_token = create_token(pool, &admin, &["admin:write", "admin:read"]).await;
        let member = create_account(pool, "member").await;
        let member_token = create_token(pool, &member, &["read:notifications"]).await;
        let before = state(pool, &member).await;

        let (status, body) = send(
            &app,
            &admin_token,
            "POST",
            &format!("/api/v1/admin/accounts/{member}/warn"),
            Some(json!({
                "text": "Please keep the tone down; this is a warning, not a silence.",
                "rule_ids": [],
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // Untouched: no silence, no suspension, no change to approval. A warning that
        // moved any of these would be a restriction wearing another name.
        assert_eq!(state(pool, &member).await, before);

        let rows = notices(pool, &member).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].moderation_action.as_deref(), Some("warn"));
        assert_eq!(
            rows[0].moderation_reason.as_deref(),
            Some("Please keep the tone down; this is a warning, not a silence.")
        );

        // The audit row carries the same words, so the moderator's trail and the person's
        // page cannot tell two stories.
        let audited: Option<String> = sqlx::query_scalar(
            "SELECT detail->>'text' FROM audit_log \
              WHERE action = 'account_warn' AND target_id = $1",
        )
        .bind(&member)
        .fetch_optional(pool)
        .await
        .expect("audit row");
        assert_eq!(
            audited.as_deref(),
            rows[0].moderation_reason.as_deref(),
            "audit and notification must agree"
        );

        let (status, body) =
            send(&app, &member_token, "GET", "/api/v1/notifications", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let notice = parse(&body);
        let notice = moderation(&notice, "warn");
        // Nothing to appeal: the account was not restricted, so there is no decision to
        // answer — only something to read.
        assert_eq!(notice["moderation"]["can_appeal"], false);
    })
    .await;
}

#[tokio::test]
async fn a_rule_caused_action_names_the_rule_to_the_person() {
    run_db_test(|store, _app| async move {
        let pool = store.pool();
        let author = create_account(pool, "author").await;
        moderation_rules::create(
            pool,
            &moderation_rules::NewRule {
                name: "crypto shilling",
                pattern: "airdrop",
                pattern_kind: "keyword",
                scope: "both",
                action: "silence",
                enabled: true,
                created_by: None,
            },
        )
        .await
        .expect("create rule");

        let mut conn = pool.acquire().await.expect("connection");
        let fired = moderation_rules::screen(
            &mut conn,
            "local",
            &Id::new().to_string(),
            &author,
            "free airdrop, guaranteed returns",
        )
        .await
        .expect("screen");
        drop(conn);
        assert_eq!(fired.len(), 1, "the rule fires once");

        let rows = notices(pool, &author).await;
        assert_eq!(rows.len(), 1, "a rule that silences tells the person: {rows:?}");
        assert_eq!(rows[0].kind, "moderation");
        assert_eq!(rows[0].moderation_action.as_deref(), Some("silence"));
        assert_eq!(
            rows[0].moderation_rule.as_deref(),
            Some("crypto shilling"),
            "the name, so the person can look up what caught them"
        );
        let reason = rows[0].moderation_reason.as_deref().expect("a reason");
        // The same sentence the report comment carries: the rule, its pattern, the text
        // that matched. Person and moderator read one account of the event.
        assert!(reason.contains("crypto shilling"), "{reason}");
        assert!(reason.contains("airdrop"), "{reason}");
    })
    .await;
}

#[tokio::test]
async fn a_suspended_account_reads_its_own_notices_and_the_appeal_it_filed() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let admin = create_account(pool, "mod").await;
        make_staff(pool, &admin).await;
        let admin_token = create_token(pool, &admin, &["admin:write", "admin:read"]).await;
        let member = create_account(pool, "member").await;
        // A suspended account still holds a token; the appeal door resolves it through
        // `verify_token_any_state`, and so does the notification list.
        let member_token = create_token(
            pool,
            &member,
            &["read:notifications", "write:accounts", "read:accounts"],
        )
        .await;

        let (status, body) = send(
            &app,
            &admin_token,
            "POST",
            &format!("/api/v1/admin/accounts/{member}/action"),
            Some(json!({ "type": "suspend", "text": "ban evasion" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, body) =
            send(&app, &member_token, "GET", "/api/v1/notifications", None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a suspended person must still read why: {body}"
        );
        let items = parse(&body);
        let notice = moderation(&items, "suspend");
        assert_eq!(notice["moderation"]["reason"], "ban evasion");
        assert_eq!(notice["moderation"]["can_appeal"], true);

        // Filing the appeal changes the notice's answer: the next word is the moderator's.
        let (status, body) = send(
            &app,
            &member_token,
            "POST",
            "/api/v1/appeals",
            Some(json!({ "reason": "that was my brother's account, not mine" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, body) =
            send(&app, &member_token, "GET", "/api/v1/notifications", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let items = parse(&body);
        let notice = moderation(&items, "suspend");
        assert_eq!(notice["moderation"]["can_appeal"], false);
        assert_eq!(notice["moderation"]["appeal"]["status"], "pending");
        assert_eq!(
            notice["moderation"]["appeal"]["reason"],
            "that was my brother's account, not mine"
        );
    })
    .await;
}
