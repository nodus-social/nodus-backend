//! Polls: one vote per account, refusals that name the reason, and read-only remote polls.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

use nodus_server_api::{root_router, AppState, InstanceConfig};
use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount};
use nodus_server_store::polls::{self, NewPoll, NewRemotePoll};
use nodus_server_store::statuses::{self, NewRemoteStatus, NewStatus};
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
    options: &[&str],
    multiple: bool,
    expires_at: Option<chrono::DateTime<Utc>>,
) -> String {
    let id = Id::new().to_string();
    let options: Vec<String> = options.iter().map(|option| (*option).to_owned()).collect();
    polls::create(
        pool,
        &NewPoll {
            id: &id,
            status_id,
            options: &options,
            multiple,
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
async fn vote(app: &Router, poll_id: &str, token: &str, choices: &[i32]) -> (StatusCode, Value) {
    let body = choices
        .iter()
        .map(|choice| format!("choices[]={choice}"))
        .collect::<Vec<_>>()
        .join("&");
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/polls/{poll_id}/votes"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body)).expect("build request"))
        .await
        .expect("route request");
    let status = response.status();
    let bytes = response.into_body().collect().await.expect("read body");
    let value = serde_json::from_slice(&bytes.to_bytes()).unwrap_or(Value::Null);
    (status, value)
}

async fn poll_for(pool: &PgPool, label: &str, multiple: bool) -> (String, String) {
    let author = create_account(pool, label).await;
    let status = create_status(pool, &author, label).await;
    let poll = create_poll(pool, &status, &["yes", "no"], multiple, None).await;
    (author, poll)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_single_choice_vote_counts_once() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, poll) = poll_for(pool, "single", false).await;
        let voter = create_account(pool, "voter").await;
        let token = create_token(pool, &voter, &["write"]).await;

        let (status, body) = vote(&app, &poll, &token, &[0]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["votes_count"], 1);
        assert_eq!(body["options"][0]["votes_count"], 1);
        assert_eq!(body["options"][1]["votes_count"], 0);
        assert_eq!(body["voted"], true);
        assert_eq!(body["own_votes"], json!([0]));

        let (status, body) = call(&app, "GET", &format!("/api/v1/polls/{poll}"), None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["votes_count"], 1);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_vote_does_not_double_count() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, poll) = poll_for(pool, "retry", false).await;
        let voter = create_account(pool, "voter").await;
        let token = create_token(pool, &voter, &["write"]).await;

        let (status, _) = vote(&app, &poll, &token, &[0]).await;
        assert_eq!(status, StatusCode::OK);

        // A retry, even one that names the other option, returns the poll unchanged.
        let (status, body) = vote(&app, &poll, &token, &[1]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["votes_count"], 1);
        assert_eq!(body["voters_count"], 1);
        assert_eq!(body["options"][0]["votes_count"], 1);
        assert_eq!(body["options"][1]["votes_count"], 0);
        assert_eq!(body["own_votes"], json!([0]));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_extra_choice_is_refused_on_a_single_choice_poll() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, poll) = poll_for(pool, "extra", false).await;
        let voter = create_account(pool, "voter").await;
        let token = create_token(pool, &voter, &["write"]).await;

        let (status, body) = vote(&app, &poll, &token, &[0, 1]).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body["error"],
            "Validation failed: this poll does not allow multiple choices"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_out_of_range_choice_is_refused() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, poll) = poll_for(pool, "range", true).await;
        let voter = create_account(pool, "voter").await;
        let token = create_token(pool, &voter, &["write"]).await;

        let (status, body) = vote(&app, &poll, &token, &[9]).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["error"], "Validation failed: choice 9 is out of range");

        let (status, body) = call(&app, "GET", &format!("/api/v1/polls/{poll}"), None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["votes_count"], 0);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_poll_is_refused() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let author = create_account(pool, "expired").await;
        let status = create_status(pool, &author, "expired").await;
        let poll = create_poll(
            pool,
            &status,
            &["yes", "no"],
            false,
            Some(Utc::now() - Duration::minutes(1)),
        )
        .await;
        let voter = create_account(pool, "voter").await;
        let token = create_token(pool, &voter, &["write"]).await;

        let (status, body) = vote(&app, &poll, &token, &[0]).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["error"], "Validation failed: this poll has ended");

        let (status, body) = call(&app, "GET", &format!("/api/v1/polls/{poll}"), None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["expired"], true);
        assert_eq!(body["votes_count"], 0);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signed_out_get_omits_voted_and_own_votes() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (_, poll) = poll_for(pool, "anon", false).await;

        let (status, body) = call(&app, "GET", &format!("/api/v1/polls/{poll}"), None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], poll);
        assert_eq!(body["multiple"], false);
        assert_eq!(body["expired"], false);
        assert_eq!(body["voters_count"], 0);
        assert_eq!(body["options"][0]["title"], "yes");
        assert!(body.get("voted").is_none(), "signed out has no voted flag");
        assert!(
            body.get("own_votes").is_none(),
            "signed out has no own votes"
        );

        let voter = create_account(pool, "voter").await;
        let token = create_token(pool, &voter, &["read"]).await;
        let (status, body) = call(
            &app,
            "GET",
            &format!("/api/v1/polls/{poll}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["voted"], false);
        assert_eq!(body["own_votes"], json!([]));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_remote_poll_cannot_be_voted_on() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let author = create_account(pool, "remote").await;
        let status_id = Id::new().to_string();
        let uri = format!("https://remote.test/notes/{}", Id::new());
        statuses::upsert_remote(
            pool,
            &NewRemoteStatus {
                id: &status_id,
                account_id: &author,
                uri: &uri,
                content: "remote poll",
                content_html: "<p>remote poll</p>",
                spoiler_text: "",
                sensitive: false,
                visibility: "public",
                in_reply_to_id: None,
                in_reply_to_account_id: None,
                created_at: Utc::now(),
            },
        )
        .await
        .expect("insert remote status");
        let poll = polls::upsert_remote(
            pool,
            &NewRemotePoll {
                status_id: &status_id,
                options: &["yes".to_owned(), "no".to_owned()],
                multiple: false,
                expires_at: None,
                voters_count: 5,
                tallies: &[3, 2],
            },
        )
        .await
        .expect("insert remote poll")
        .id;

        let (status, body) = call(&app, "GET", &format!("/api/v1/polls/{poll}"), None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["options"][0]["title"], "yes");
        assert_eq!(body["options"][0]["votes_count"], 3);
        assert_eq!(body["options"][1]["votes_count"], 2);
        assert_eq!(body["votes_count"], 5);
        assert_eq!(body["voters_count"], 5);

        let voter = create_account(pool, "voter").await;
        let token = create_token(pool, &voter, &["write"]).await;
        let (status, body) = vote(&app, &poll, &token, &[0]).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body["error"],
            "Validation failed: this poll belongs to another instance"
        );
    })
    .await;
}
