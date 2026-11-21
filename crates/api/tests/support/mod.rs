//! Shared harness for the contract tests: an isolated schema, a migrated store and the
//! router the server actually mounts.
//!
//! Both `mastodon_parity.rs` and `sdk_contract.rs` drive the same stack, so the plumbing
//! lives here rather than being copied into each file. Everything is skipped when
//! `DATABASE_URL` is unset, which keeps `cargo test` usable without a database.

#![allow(
    dead_code,
    reason = "each consumer uses a different subset of the helpers"
)]

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;

use std::sync::Arc;

use nodus_server_api::home::{HomeCache, HomeShards};
use nodus_server_api::{root_router, AppState, InstanceConfig};
use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount};
use nodus_server_store::statuses::{self, NewStatus};
use nodus_server_store::{social, Store};

pub fn instance_config() -> InstanceConfig {
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

/// Runs `body` against a schema of its own, then drops the schema.
pub async fn run_db_test<F, Fut>(body: F)
where
    F: FnOnce(Store, Router) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some((admin, schema, store)) = isolated_store().await else {
        return;
    };
    // The auth pages live in their own router, the way the server mounts them.
    let api = root_router(AppState::new(store.clone(), instance_config()));
    let auth = nodus_auth::router(nodus_auth::AppState::new(
        nodus_auth::store::PgAuthStore::new(store.pool().clone()),
        nodus_auth::Config {
            domain: "social.test".to_owned(),
            issuer: "https://social.test".to_owned(),
            secure_cookies: false,
            registrations_open: false,
        },
    ));
    let app = api.merge(auth);

    let outcome = tokio::spawn(async move { body(store, app).await }).await;
    let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
        .execute(admin.pool())
        .await;
    if let Err(err) = outcome {
        std::panic::resume_unwind(err.into_panic());
    }
}

/// The same isolated schema, but the state handed to `body` has home timelines configured
/// with `caches` — and so does the router built over it. The caches are handed back to the
/// test because the interesting assertions are about what the server wrote into them.
pub async fn run_home_db_test<F, Fut>(caches: Vec<Arc<dyn HomeCache>>, body: F)
where
    F: FnOnce(Store, AppState, Arc<HomeShards>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some((admin, schema, store)) = isolated_store().await else {
        return;
    };
    let home = Arc::new(HomeShards::new(caches, nodus_server_api::home::DEFAULT_CAP));
    let state = AppState::new(store.clone(), instance_config()).with_home(Some(home.clone()));

    let outcome = tokio::spawn(async move { body(store, state, home).await }).await;
    let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
        .execute(admin.pool())
        .await;
    if let Err(err) = outcome {
        std::panic::resume_unwind(err.into_panic());
    }
}

/// The same isolated schema, handing `body` only the store.
///
/// The two-replica home tests build two states over one pool. Neither [`run_db_test`]
/// (which owns the router) nor [`run_home_db_test`] (which owns one state and one shard
/// set) can express that, and the schema has to outlive both replicas.
pub async fn run_shared_db_test<F, Fut>(body: F)
where
    F: FnOnce(Store) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some((admin, schema, store)) = isolated_store().await else {
        return;
    };
    let outcome = tokio::spawn(async move { body(store).await }).await;
    let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
        .execute(admin.pool())
        .await;
    if let Err(err) = outcome {
        std::panic::resume_unwind(err.into_panic());
    }
}

/// A schema that belongs to one test, with the migrations already applied.
///
/// `None` when `DATABASE_URL` is unset: every contract test is skipped rather than failed,
/// so `cargo test` works on a machine with no database.
async fn isolated_store() -> Option<(Store, String, Store)> {
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
    Some((admin, schema, store))
}

pub async fn create_account(pool: &PgPool, label: &str) -> String {
    let username = format!("pgtest_{label}_{}", Id::new()).to_lowercase();
    let row = accounts::insert(
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
    .expect("insert account");
    row.id
}

pub async fn create_token(pool: &PgPool, account_id: &str, scopes: &[&str]) -> String {
    let app_id = Id::new().to_string();
    let client_id = format!("pgtest-client-{app_id}");
    let owned: Vec<String> = scopes.iter().map(|s| (*s).to_owned()).collect();
    nodus_server_store::apps::register(
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
    let digest = format!(
        "{:x}",
        <sha2::Sha256 as sha2::Digest>::digest(token.as_bytes())
    );
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

pub async fn create_status(
    pool: &PgPool,
    account_id: &str,
    content: &str,
    visibility: &str,
    mentions: &[String],
    tags: &[&str],
) -> String {
    let id = Id::new().to_string();
    let owned_tags: Vec<String> = tags.iter().map(|t| (*t).to_owned()).collect();
    statuses::create(
        pool,
        &NewStatus {
            id: &id,
            account_id,
            content,
            content_html: content,
            content_source: None,
            content_format: "html",
            spoiler_text: "",
            visibility,
            sensitive: false,
            in_reply_to_id: None,
            in_reply_to_account_id: None,
            reblog_of_id: None,
            language: None,
        },
        &[],
        mentions,
        &owned_tags,
    )
    .await
    .expect("create status");
    id
}

/// Makes `follower` follow `target`, the way the client's own Follow button does.
pub async fn follow(pool: &PgPool, follower: &str, target: &str) {
    social::follow(pool, follower, target, true, false)
        .await
        .expect("follow");
}

pub async fn send(
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

/// A request with no `Authorization` header at all — an empty bearer token is a bad
/// token, not an anonymous reader.
pub async fn send_anon(app: &Router, method: &str, uri: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .expect("request");
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

pub async fn send_form(
    app: &Router,
    token: &str,
    method: &str,
    uri: &str,
    fields: &[(&str, &str)],
) -> (StatusCode, String) {
    let body = fields
        .iter()
        .map(|(key, value)| {
            let encoded: String = url::form_urlencoded::byte_serialize(key.as_bytes()).collect();
            let value: String = url::form_urlencoded::byte_serialize(value.as_bytes()).collect();
            format!("{encoded}={value}")
        })
        .collect::<Vec<_>>()
        .join("&");
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .expect("request");
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

pub fn json_of(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or_else(|err| panic!("body was not JSON ({err}): {body}"))
}

/// A JSON body decoded into one of the SDK's own types.
pub fn decode<T: serde::de::DeserializeOwned>(body: &str) -> T {
    serde_json::from_str(body).unwrap_or_else(|err| panic!("body did not decode ({err}): {body}"))
}

/// One page shape the client reads, asserted to decode into the SDK's type.
pub fn expect_ok(status: StatusCode, body: &str, uri: &str) -> String {
    assert!(
        status.is_success(),
        "{uri} answered {status}: {}",
        body.chars().take(400).collect::<String>()
    );
    body.to_owned()
}
