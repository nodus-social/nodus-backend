//! Poll votes reach the author as one notification line per poll, not one per voter.
//!
//! The line names the latest voter and counts everyone behind it; a vote the author cast
//! themselves, a vote on an ended poll, and a vote on a poll nobody can see notify nobody.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

use nodus_server_api::{root_router, AppState, InstanceConfig};
use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount};
use nodus_server_store::polls::{self, NewPoll};
use nodus_server_store::statuses::{self, NewStatus};
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

async fn create_status(pool: &PgPool, account_id: &str, label: &str) -> String {
    let id = Id::new().to_string();
    let html = format!("<p>{label}</p>");
    statuses::create(
        pool,
        &NewStatus {
            id: &id,
            account_id,
            content: label,
            content_html: &html,
            content_source: Some(label),
            content_format: "html",
            spoiler_text: "",
            visibility: "public",
            sensitive: false,
            in_reply_to_id: None,
            in_reply_to_account_id: None,
            reblog_of_id: None,
            language: Some("en"),
        },
        &[],
        &[],
        &[],
    )
    .await
    .expect("insert status");
    id
}

async fn create_poll(
    pool: &PgPool,
    status_id: &str,
    expires_at: Option<chrono::DateTime<Utc>>,
) -> String {
    let id = Id::new().to_string();
    let options = vec!["yes".to_owned(), "no".to_owned()];
    polls::create(
        pool,
        &NewPoll {
            id: &id,
            status_id,
            options: &options,
            multiple: false,
            hide_totals: false,
            expires_at,
        },
    )
    .await
    .expect("insert poll");
    id
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let body = match body {
        Some(value) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(request.body(body).expect("build request"))
        .await
        .expect("route request");
    let status = response.status();
    let bytes = response.into_body().collect().await.expect("read body");
    let value = serde_json::from_slice(&bytes.to_bytes()).unwrap_or(Value::Null);
    (status, value)
}

/// The console votes the way Mastodon does: form-encoded `choices[]` pairs.
async fn vote(app: &Router, poll_id: &str, token: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/polls/{poll_id}/votes"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    let response = app
        .clone()
        .oneshot(request.body(Body::from("choices[]=0")).expect("build request"))
        .await
        .expect("route request");
    let status = response.status();
    let bytes = response.into_body().collect().await.expect("read body");
    let value = serde_json::from_slice(&bytes.to_bytes()).unwrap_or(Value::Null);
    (status, value)
}

/// `(from_account_id, group_count)` for the poll line on this status, if there is one.
async fn poll_line(pool: &PgPool, author: &str, status_id: &str) -> Option<(String, i32)> {
    sqlx::query_as::<_, (String, i32)>(
        "SELECT from_account_id, group_count FROM notification \
         WHERE account_id = $1 AND kind = 'poll' AND status_id = $2",
    )
    .bind(author)
    .bind(status_id)
    .fetch_optional(pool)
    .await
    .expect("read poll notification")
}

#[tokio::test(flavor = "multi_thread")]
async fn several_voters_are_one_line_naming_the_latest() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let author = create_account(pool, "author").await;
        let status = create_status(pool, &author, "poll").await;
        let poll = create_poll(pool, &status, None).await;
        let author_token = create_token(pool, &author, &["read"]).await;

        let mut voters = Vec::new();
        for label in ["first", "second", "third"] {
            let voter = create_account(pool, label).await;
            let token = create_token(pool, &voter, &["write"]).await;
            let (code, body) = vote(&app, &poll, &token).await;
            assert_eq!(code, StatusCode::OK, "{body}");
            voters.push(voter);
        }

        // One row, not three: the latest voter and the rest counted behind them.
        let (from, count) = poll_line(pool, &author, &status)
            .await
            .expect("the author has a poll notification");
        assert_eq!(from, voters[2]);
        assert_eq!(count, 3);

        let (code, body) = call(&app, "GET", "/api/v1/notifications", Some(&author_token), None).await;
        assert_eq!(code, StatusCode::OK);
        let lines = body.as_array().expect("a page of notifications");
        assert_eq!(lines.len(), 1, "{body}");
        assert_eq!(lines[0]["type"], "poll");
        assert_eq!(lines[0]["group_count"], 3);
        assert_eq!(lines[0]["account"]["id"], voters[2]);
        assert_eq!(lines[0]["group_key"], format!("poll:{status}"));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn voting_your_own_poll_notifies_nobody() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let author = create_account(pool, "author").await;
        let status = create_status(pool, &author, "poll").await;
        let poll = create_poll(pool, &status, None).await;
        let token = create_token(pool, &author, &["write"]).await;

        let (code, body) = vote(&app, &poll, &token).await;
        assert_eq!(code, StatusCode::OK, "{body}");
        assert_eq!(body["votes_count"], 1);
        assert!(poll_line(pool, &author, &status).await.is_none());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ended_poll_takes_no_vote_and_notifies_nobody() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let author = create_account(pool, "author").await;
        let status = create_status(pool, &author, "poll").await;
        let poll = create_poll(pool, &status, Some(Utc::now() - Duration::minutes(5))).await;
        let voter = create_account(pool, "voter").await;
        let token = create_token(pool, &voter, &["write"]).await;

        let (code, body) = vote(&app, &poll, &token).await;
        assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error"], "Validation failed: this poll has ended");
        assert!(poll_line(pool, &author, &status).await.is_none());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_vote_on_a_poll_nobody_can_see_notifies_nobody() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let author = create_account(pool, "author").await;
        let status = create_status(pool, &author, "poll").await;
        let poll = create_poll(pool, &status, None).await;
        let voter = create_account(pool, "voter").await;
        let token = create_token(pool, &voter, &["write"]).await;

        sqlx::query("UPDATE status SET deleted_at = now() WHERE id = $1")
            .bind(&status)
            .execute(pool)
            .await
            .expect("delete status");

        let (code, _) = vote(&app, &poll, &token).await;
        assert_eq!(code, StatusCode::NOT_FOUND);
        assert!(poll_line(pool, &author, &status).await.is_none());
    })
    .await;
}
