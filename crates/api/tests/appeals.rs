//! The appeal path: the one door a restricted account can still open, and the queue a
//! moderator reads to answer it.
//!
//! The interesting cases are the refusals: an unrestricted account cannot use the route
//! as a soapbox, a second appeal while one is open is refused by name, and deciding an
//! appeal twice must not lift a restriction twice.

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
use nodus_server_store::{apps, Store};

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

async fn silence(pool: &PgPool, account_id: &str) {
    sqlx::query("UPDATE account SET silenced_at = now() WHERE id = $1")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("silence");
}

async fn suspend(pool: &PgPool, account_id: &str) {
    sqlx::query("UPDATE account SET suspended_at = now() WHERE id = $1")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("suspend");
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

async fn notifications(pool: &PgPool, account_id: &str) -> Vec<(String, Option<String>)> {
    sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT kind, note FROM notification WHERE account_id = $1 ORDER BY created_at",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await
    .expect("notifications")
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

#[tokio::test]
async fn an_unrestricted_account_cannot_appeal() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let account = create_account(pool, "free").await;
        let token = create_token(pool, &account, &["read:accounts", "write:accounts"]).await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/appeals",
            Some(json!({ "reason": "please look again" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body.contains("not restricted"), "{body}");

        // The same door answers the person's own (empty) history; it is not a list of
        // everybody's appeals.
        let (status, body) = send(&app, &token, "GET", "/api/v1/appeals", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(parse(&body), json!([]));
    })
    .await;
}

#[tokio::test]
async fn a_restricted_account_may_appeal_once() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let account = create_account(pool, "silenced").await;
        silence(pool, &account).await;
        let token = create_token(pool, &account, &["read:accounts", "write:accounts"]).await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/appeals",
            Some(json!({ "reason": "I did not post that" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let opened = parse(&body);
        assert_eq!(opened["action"], "silence");
        assert_eq!(opened["status"], "pending");
        let id = opened["id"].as_str().expect("appeal id").to_owned();
        assert!(!id.is_empty());

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/appeals",
            Some(json!({ "reason": "and again" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body.contains(&id), "the open appeal is named: {body}");

        let (status, body) = send(&app, &token, "GET", "/api/v1/appeals", None).await;
        assert_eq!(status, StatusCode::OK);
        let rows = parse(&body);
        assert_eq!(rows.as_array().expect("rows").len(), 1);
        assert_eq!(rows[0]["reason"], "I did not post that");
    })
    .await;
}

#[tokio::test]
async fn accepting_lifts_the_restriction_and_tells_the_person() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let account = create_account(pool, "appellant").await;
        silence(pool, &account).await;
        let token = create_token(pool, &account, &["read:accounts", "write:accounts"]).await;
        let (_, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/appeals",
            Some(json!({ "reason": "a mistake" })),
        )
        .await;
        let appeal = parse(&body)["id"].as_str().expect("id").to_owned();

        let moderator = create_account(pool, "mod").await;
        make_staff(pool, &moderator).await;
        let moderator_token = create_token(pool, &moderator, &["admin:read", "admin:write"]).await;

        let (status, body) = send(
            &app,
            &moderator_token,
            "POST",
            &format!("/api/v1/admin/appeals/{appeal}/decide"),
            Some(json!({ "accept": true, "note": "you were right" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let decided = parse(&body);
        assert_eq!(decided["status"], "accepted");
        assert_eq!(decided["decision_note"], "you were right");
        assert_eq!(decided["decided_by"], moderator.as_str());

        let (suspended, silenced, approved) = state(pool, &account).await;
        assert!(!suspended);
        assert!(!silenced, "accepting a silence lifts it");
        assert!(approved);

        let rows = notifications(pool, &account).await;
        let (kind, note) = rows.last().expect("a notification");
        assert_eq!(kind, "appeal");
        let note = note.as_deref().expect("the decision note travels");
        assert!(note.contains("accepted"), "{note}");
        assert!(note.contains("you were right"), "{note}");

        let audited: (String,) = sqlx::query_as(
            "SELECT action FROM audit_log WHERE target_type = 'appeal' AND target_id = $1",
        )
        .bind(&appeal)
        .fetch_one(pool)
        .await
        .expect("audit row");
        assert_eq!(audited.0, "appeal_accept");
    })
    .await;
}

#[tokio::test]
async fn rejecting_keeps_the_restriction_and_tells_the_person() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let account = create_account(pool, "suspended").await;
        suspend(pool, &account).await;
        let token = create_token(pool, &account, &["read:accounts", "write:accounts"]).await;

        // The appeal door and the notification list are the two routes that open for a
        // suspended token; every other route still refuses it.
        let (status, _) = send(&app, &token, "GET", "/api/v1/accounts/verify_credentials", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/appeals",
            Some(json!({ "reason": "let me back in" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(parse(&body)["action"], "suspend");
        let appeal = parse(&body)["id"].as_str().expect("id").to_owned();

        let moderator = create_account(pool, "mod2").await;
        make_staff(pool, &moderator).await;
        let moderator_token = create_token(pool, &moderator, &["admin:read", "admin:write"]).await;
        let (status, body) = send(
            &app,
            &moderator_token,
            "POST",
            &format!("/api/v1/admin/appeals/{appeal}/decide"),
            Some(json!({ "accept": false, "note": "the posts are still there" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(parse(&body)["status"], "rejected");

        let (suspended, _, _) = state(pool, &account).await;
        assert!(suspended, "a rejected appeal changes nothing");

        let rows = notifications(pool, &account).await;
        let (kind, note) = rows.last().expect("a notification");
        assert_eq!(kind, "appeal");
        let note = note.as_deref().expect("the note travels");
        assert!(note.contains("rejected"), "{note}");
        assert!(note.contains("the posts are still there"), "{note}");
    })
    .await;
}

#[tokio::test]
async fn deciding_twice_is_a_conflict() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let account = create_account(pool, "twice").await;
        silence(pool, &account).await;
        let token = create_token(pool, &account, &["read:accounts", "write:accounts"]).await;
        let (_, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/appeals",
            Some(json!({ "reason": "once" })),
        )
        .await;
        let appeal = parse(&body)["id"].as_str().expect("id").to_owned();

        let moderator = create_account(pool, "mod3").await;
        make_staff(pool, &moderator).await;
        let moderator_token = create_token(pool, &moderator, &["admin:read", "admin:write"]).await;
        let uri = format!("/api/v1/admin/appeals/{appeal}/decide");
        let (status, _) = send(
            &app,
            &moderator_token,
            "POST",
            &uri,
            Some(json!({ "accept": true })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Accepting writes two sentences: the lift itself, and the appeal outcome.
        let after_accept = notifications(pool, &account).await.len();
        let (status, body) = send(
            &app,
            &moderator_token,
            "POST",
            &uri,
            Some(json!({ "accept": true })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        // Undoing the silence twice would also mean notifying twice.
        assert_eq!(notifications(pool, &account).await.len(), after_accept);
    })
    .await;
}

#[tokio::test]
async fn the_queue_filters_by_status_and_a_read_only_token_cannot_decide() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let moderator = create_account(pool, "reader").await;
        make_staff(pool, &moderator).await;
        let reader = create_token(pool, &moderator, &["admin:read"]).await;
        let writer = create_token(pool, &moderator, &["admin:read", "admin:write"]).await;

        let first = create_account(pool, "first").await;
        silence(pool, &first).await;
        let first_token = create_token(pool, &first, &["read:accounts", "write:accounts"]).await;
        let (_, body) = send(
            &app,
            &first_token,
            "POST",
            "/api/v1/appeals",
            Some(json!({ "reason": "accepted one" })),
        )
        .await;
        let accepted = parse(&body)["id"].as_str().expect("id").to_owned();

        let second = create_account(pool, "second").await;
        silence(pool, &second).await;
        let second_token = create_token(pool, &second, &["read:accounts", "write:accounts"]).await;
        let (_, body) = send(
            &app,
            &second_token,
            "POST",
            "/api/v1/appeals",
            Some(json!({ "reason": "pending one" })),
        )
        .await;
        let pending = parse(&body)["id"].as_str().expect("id").to_owned();

        let (status, _) = send(
            &app,
            &writer,
            "POST",
            &format!("/api/v1/admin/appeals/{accepted}/decide"),
            Some(json!({ "accept": true })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = send(
            &app,
            &reader,
            "GET",
            "/api/v1/admin/appeals?status=pending",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let rows = parse(&body);
        let rows = rows.as_array().expect("rows");
        assert_eq!(rows.len(), 1, "{body}");
        assert_eq!(rows[0]["id"], pending.as_str());
        assert_eq!(rows[0]["status"], "pending");
        assert_eq!(rows[0]["action"], "silence");
        assert_eq!(rows[0]["restriction"], "silence");
        assert!(rows[0]["age_seconds"].as_i64().is_some_and(|age| age >= 0));

        let (status, body) = send(
            &app,
            &reader,
            "GET",
            "/api/v1/admin/appeals?status=accepted",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let rows = parse(&body);
        let rows = rows.as_array().expect("rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["id"], accepted.as_str());

        let (status, _) = send(
            &app,
            &reader,
            "POST",
            &format!("/api/v1/admin/appeals/{pending}/decide"),
            Some(json!({ "accept": true })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (_, silenced, _) = state(pool, &second).await;
        assert!(silenced, "the read-only token changed nothing");
    })
    .await;
}
