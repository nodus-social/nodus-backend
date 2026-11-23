//! The settings page's credential list: browser sessions and app authorizations.
//!
//! Each test drives the same router the browser and the console reach. "Current" is
//! proved from the cookie or bearer on the request, never from a field the caller sends.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;

use nodus_auth::domain::{opaque_token, token_hash};
use nodus_auth::store::{AuthStore as _, PgAuthStore};
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
    let schema = format!("pgtest_{}", Id::new());
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
    let api = root_router(AppState::new(store.clone(), instance_config()));
    let auth = nodus_auth::router(nodus_auth::AppState::new(
        PgAuthStore::new(store.pool().clone()),
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

async fn create_account(pool: &PgPool, label: &str) -> String {
    let suffix = Id::new().to_string();
    let username = format!("pgtest_{label}_{suffix}");
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
    let owned_scopes: Vec<String> = scopes.iter().map(|s| (*s).to_owned()).collect();
    apps::register(
        pool,
        &app_id,
        &client_id,
        "unused",
        "pgtest app",
        None,
        &["urn:ietf:wg:oauth:2.0:oob".to_owned()],
        &owned_scopes,
    )
    .await
    .expect("register app");

    let token = format!("pgtest-token-{}", Id::new());
    sqlx::query(
        "INSERT INTO oauth_token (id, app_id, account_id, token_hash, scopes) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Id::new().to_string())
    .bind(&app_id)
    .bind(account_id)
    .bind(token_hash(&token))
    .bind(&owned_scopes)
    .execute(pool)
    .await
    .expect("insert oauth token");
    token
}

async fn create_browser_session(pool: &PgPool, account_id: &str, user_agent: &str) -> String {
    let secret = opaque_token();
    PgAuthStore::new(pool.clone())
        .create_session(
            &token_hash(&secret),
            account_id,
            Utc::now() + Duration::hours(1),
            user_agent,
            Some("203.0.113.0/24"),
        )
        .await
        .expect("create browser session");
    secret
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    cookie: Option<&str>,
) -> (StatusCode, String) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(secret) = cookie {
        builder = builder.header(
            header::COOKIE,
            format!("{}={secret}", nodus_auth::SESSION_COOKIE),
        );
    }
    let request = builder.body(Body::empty()).expect("request");
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

async fn session_status(app: &Router, secret: &str) -> StatusCode {
    send(app, "GET", "/auth/session", None, Some(secret))
        .await
        .0
}

fn rows(body: &str) -> Vec<Value> {
    serde_json::from_str::<Value>(body)
        .expect("JSON body")
        .as_array()
        .expect("array body")
        .clone()
}

fn current(rows: &[Value]) -> &Value {
    let marked: Vec<&Value> = rows
        .iter()
        .filter(|row| row["current"] == Value::Bool(true))
        .collect();
    assert_eq!(marked.len(), 1, "exactly one row is current: {rows:?}");
    marked[0]
}

#[tokio::test]
async fn sessions_list_marks_the_presented_cookie_as_current() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let account = create_account(pool, "sessions").await;
        let token =
            create_token(pool, &account, &["read", "read:accounts", "write:accounts"]).await;
        let first = create_browser_session(pool, &account, "Browser One").await;
        let second = create_browser_session(pool, &account, "Browser Two").await;

        let (status, body) = send(
            &app,
            "GET",
            "/api/v1/auth/sessions",
            Some(&token),
            Some(&first),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let listed = rows(&body);
        assert_eq!(listed.len(), 2, "{body}");
        assert_eq!(
            current(&listed)["user_agent"],
            "Browser One",
            "current is the cookie that was presented: {body}"
        );
        assert!(listed.iter().all(|row| row["ip"] == "203.0.113.0/24"));
        assert!(listed.iter().all(|row| row["last_used_at"].is_string()));

        let (_, body) = send(
            &app,
            "GET",
            "/api/v1/auth/sessions",
            Some(&token),
            Some(&second),
        )
        .await;
        assert_eq!(
            current(&rows(&body))["user_agent"],
            "Browser Two",
            "the same list marks a different row for a different cookie"
        );

        let (status, _) = send(&app, "GET", "/api/v1/auth/sessions", Some(&token), None).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "an app token alone cannot name a browser session"
        );
        let (status, _) = send(&app, "GET", "/api/v1/auth/sessions", None, Some(&first)).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a cookie alone is not a grant"
        );
    })
    .await;
}

#[tokio::test]
async fn revoking_a_session_ends_it_on_the_very_next_request() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let account = create_account(pool, "revoke").await;
        let token =
            create_token(pool, &account, &["read", "read:accounts", "write:accounts"]).await;
        let kept = create_browser_session(pool, &account, "Kept").await;
        let doomed = create_browser_session(pool, &account, "Doomed").await;
        assert_eq!(session_status(&app, &doomed).await, StatusCode::OK);

        let (_, body) = send(
            &app,
            "GET",
            "/api/v1/auth/sessions",
            Some(&token),
            Some(&kept),
        )
        .await;
        let id = rows(&body)
            .iter()
            .find(|row| row["user_agent"] == "Doomed")
            .expect("doomed row")["id"]
            .as_str()
            .expect("id is a string")
            .to_owned();

        let (status, body) = send(
            &app,
            "DELETE",
            &format!("/api/v1/auth/sessions/{id}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        assert_eq!(
            session_status(&app, &doomed).await,
            StatusCode::UNAUTHORIZED,
            "the next request with the revoked cookie is refused"
        );
        assert_eq!(session_status(&app, &kept).await, StatusCode::OK);

        let (status, _) = send(
            &app,
            "DELETE",
            &format!("/api/v1/auth/sessions/{id}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a repeated revoke is a 404, not a 500"
        );

        // Revoking the caller's own session is allowed; the client then signs out.
        let (_, body) = send(
            &app,
            "GET",
            "/api/v1/auth/sessions",
            Some(&token),
            Some(&kept),
        )
        .await;
        let own = current(&rows(&body))["id"].as_str().expect("id").to_owned();
        let (status, _) = send(
            &app,
            "DELETE",
            &format!("/api/v1/auth/sessions/{own}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(session_status(&app, &kept).await, StatusCode::UNAUTHORIZED);
    })
    .await;
}

#[tokio::test]
async fn another_accounts_session_is_a_404_and_survives() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let owner = create_account(pool, "owner").await;
        let other = create_account(pool, "other").await;
        let other_token =
            create_token(pool, &other, &["read", "read:accounts", "write:accounts"]).await;
        let owner_session = create_browser_session(pool, &owner, "Owner browser").await;
        let owner_token = create_token(pool, &owner, &["read:accounts"]).await;

        let (_, body) = send(
            &app,
            "GET",
            "/api/v1/auth/sessions",
            Some(&owner_token),
            Some(&owner_session),
        )
        .await;
        let id = current(&rows(&body))["id"].as_str().expect("id").to_owned();

        let (status, _) = send(
            &app,
            "DELETE",
            &format!("/api/v1/auth/sessions/{id}"),
            Some(&other_token),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "another account's session is not found, not a 403 that would confirm it exists"
        );
        assert_eq!(session_status(&app, &owner_session).await, StatusCode::OK);
    })
    .await;
}

#[tokio::test]
async fn revoke_others_leaves_exactly_the_callers_session() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let account = create_account(pool, "others").await;
        let token =
            create_token(pool, &account, &["read", "read:accounts", "write:accounts"]).await;
        let mine = create_browser_session(pool, &account, "Mine").await;
        let first = create_browser_session(pool, &account, "First").await;
        let second = create_browser_session(pool, &account, "Second").await;

        let (status, body) = send(
            &app,
            "DELETE",
            "/api/v1/auth/sessions?scope=others",
            Some(&token),
            Some(&mine),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        assert_eq!(session_status(&app, &mine).await, StatusCode::OK);
        assert_eq!(session_status(&app, &first).await, StatusCode::UNAUTHORIZED);
        assert_eq!(
            session_status(&app, &second).await,
            StatusCode::UNAUTHORIZED
        );

        let (_, body) = send(
            &app,
            "GET",
            "/api/v1/auth/sessions",
            Some(&token),
            Some(&mine),
        )
        .await;
        let listed = rows(&body);
        assert_eq!(listed.len(), 1, "{body}");
        assert_eq!(current(&listed)["user_agent"], "Mine");

        let (status, _) = send(
            &app,
            "DELETE",
            "/api/v1/auth/sessions?scope=sideways",
            Some(&token),
            Some(&mine),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            session_status(&app, &mine).await,
            StatusCode::OK,
            "a refused request revokes nothing"
        );
    })
    .await;
}

#[tokio::test]
async fn revoking_everything_requires_the_explicit_scope() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let account = create_account(pool, "all").await;
        let token =
            create_token(pool, &account, &["read", "read:accounts", "write:accounts"]).await;
        let mine = create_browser_session(pool, &account, "Mine").await;
        let other = create_browser_session(pool, &account, "Other").await;

        // The bare form is "all except current", never "all".
        let (status, _) = send(
            &app,
            "DELETE",
            "/api/v1/auth/sessions",
            Some(&token),
            Some(&mine),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(session_status(&app, &mine).await, StatusCode::OK);
        assert_eq!(session_status(&app, &other).await, StatusCode::UNAUTHORIZED);

        let (status, _) = send(
            &app,
            "DELETE",
            "/api/v1/auth/sessions?scope=all",
            Some(&token),
            Some(&mine),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(
            session_status(&app, &mine).await,
            StatusCode::UNAUTHORIZED,
            "scope=all is the explicit form and takes the caller's session too"
        );
    })
    .await;
}

#[tokio::test]
async fn authorizations_list_and_revoke_the_app_token() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let account = create_account(pool, "apps").await;
        let token =
            create_token(pool, &account, &["read", "read:accounts", "write:accounts"]).await;

        let (status, body) = send(
            &app,
            "GET",
            "/api/v1/oauth/authorizations",
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let listed = rows(&body);
        assert_eq!(listed.len(), 1, "{body}");
        let row = current(&listed);
        assert_eq!(row["app"]["name"], "pgtest app", "{body}");
        assert!(row.get("app").and_then(|app| app.get("website")).is_none());
        assert_eq!(
            row["scopes"],
            serde_json::json!(["read", "read:accounts", "write:accounts"])
        );
        let id = row["id"].as_str().expect("id").to_owned();

        let (status, _) = send(
            &app,
            "DELETE",
            &format!("/api/v1/oauth/authorizations/{id}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = send(
            &app,
            "GET",
            "/api/v1/accounts/verify_credentials",
            Some(&token),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the revoked token no longer authenticates"
        );

        let (status, _) = send(
            &app,
            "DELETE",
            &format!("/api/v1/oauth/authorizations/{id}"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the token itself is what carries the revoke, so a second call cannot authenticate"
        );
    })
    .await;
}

#[tokio::test]
async fn another_accounts_authorization_is_a_404_and_survives() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let owner = create_account(pool, "appowner").await;
        let other = create_account(pool, "appother").await;
        let owner_token =
            create_token(pool, &owner, &["read", "read:accounts", "write:accounts"]).await;
        let other_token =
            create_token(pool, &other, &["read", "read:accounts", "write:accounts"]).await;

        let (_, body) = send(
            &app,
            "GET",
            "/api/v1/oauth/authorizations",
            Some(&owner_token),
            None,
        )
        .await;
        let id = current(&rows(&body))["id"].as_str().expect("id").to_owned();

        let (status, _) = send(
            &app,
            "DELETE",
            &format!("/api/v1/oauth/authorizations/{id}"),
            Some(&other_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = send(
            &app,
            "GET",
            "/api/v1/accounts/verify_credentials",
            Some(&owner_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the owner's token still works");
    })
    .await;
}

#[tokio::test]
async fn last_used_at_advances_once_a_minute_at_most() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let account = create_account(pool, "lastused").await;
        let secret = create_browser_session(pool, &account, "Clock").await;
        let digest = token_hash(&secret);

        sqlx::query(
            "UPDATE auth_session SET last_used_at = now() - interval '5 minutes' \
                     WHERE token_hash = $1",
        )
        .bind(&digest)
        .execute(pool)
        .await
        .expect("make the stamp stale");

        assert_eq!(session_status(&app, &secret).await, StatusCode::OK);
        let first = last_used(pool, &digest).await;
        assert!(
            first > Utc::now() - Duration::seconds(30),
            "a stale stamp moves on the next use: {first}"
        );

        // Two requests inside the same minute write once: the second leaves the value
        // untouched, which is the coarse touch working.
        assert_eq!(session_status(&app, &secret).await, StatusCode::OK);
        let second = last_used(pool, &digest).await;
        assert_eq!(
            first, second,
            "a second request in the same minute does not write"
        );

        sqlx::query(
            "UPDATE auth_session SET last_used_at = now() - interval '5 minutes' \
                     WHERE token_hash = $1",
        )
        .bind(&digest)
        .execute(pool)
        .await
        .expect("make the stamp stale again");
        assert_eq!(session_status(&app, &secret).await, StatusCode::OK);
        let third = last_used(pool, &digest).await;
        assert!(third > first, "the stamp moves again once it is stale");
    })
    .await;
}

async fn last_used(pool: &PgPool, digest: &str) -> chrono::DateTime<Utc> {
    sqlx::query_scalar("SELECT last_used_at FROM auth_session WHERE token_hash = $1")
        .bind(digest)
        .fetch_one(pool)
        .await
        .expect("stored last_used_at")
}
