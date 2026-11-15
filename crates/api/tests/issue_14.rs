use std::collections::HashMap;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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

async fn create_account(pool: &PgPool, label: &str, admin: bool) -> (String, String) {
    let suffix = Id::new().to_string();
    let username = format!("pgtest_{label}_{suffix}");
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
    if admin {
        accounts::set_admin(pool, &row.id, true)
            .await
            .expect("promote admin");
    }
    (row.id, username)
}

async fn create_token_with_scopes(pool: &PgPool, account_id: &str, scopes: &[&str]) -> String {
    let app_id = Id::new().to_string();
    let client_id = format!("pgtest-client-{app_id}");
    let owned_scopes: Vec<String> = scopes.iter().map(|s| (*s).to_owned()).collect();
    apps::register(
        pool,
        &app_id,
        &client_id,
        "unused",
        "pgtest",
        None,
        &["urn:ietf:wg:oauth:2.0:oob".to_owned()],
        &owned_scopes,
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
    .bind(&owned_scopes)
    .execute(pool)
    .await
    .expect("insert oauth token");

    token
}

async fn create_browser_session(pool: &PgPool, account_id: &str) -> String {
    let secret = opaque_token();
    PgAuthStore::new(pool.clone())
        .create_session(
            &token_hash(&secret),
            account_id,
            Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .expect("create browser session");
    secret
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app.clone().oneshot(request).await.expect("router response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

fn parse_cookies(headers: &axum::http::HeaderMap) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for val in headers.get_all(header::SET_COOKIE) {
        if let Ok(s) = val.to_str() {
            if let Some(pair) = s.split(';').next() {
                if let Some((k, v)) = pair.split_once('=') {
                    map.insert(k.trim().to_owned(), v.trim().to_owned());
                }
            }
        }
    }
    map
}

fn extract_csrf_input(html: &str) -> Option<String> {
    let needle = "name=\"csrf_token\"";
    let idx = html.find(needle)?;
    let rest = &html[idx..];
    let val_start = rest.find("value=\"")? + "value=\"".len();
    let val_end = rest[val_start..].find('"')?;
    Some(rest[val_start..val_start + val_end].to_owned())
}

fn form_body(pairs: &[(&str, &str)]) -> Body {
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().copied())
        .finish();
    Body::from(encoded)
}

async fn send_bearer(
    app: &Router,
    method: &str,
    uri: &str,
    token: &str,
    form: Option<&[(&str, &str)]>,
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    let body = match form {
        Some(pairs) => {
            builder = builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            form_body(pairs)
        }
        None => Body::empty(),
    };
    let (status, _, text) = send(app, builder.body(body).expect("request")).await;
    (status, text)
}

async fn register_app(app: &Router, scopes: &str) -> (String, String) {
    let (status, _, body) = send(
        app,
        Request::builder()
            .method("POST")
            .uri("/api/v1/apps")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "client_name": "TestClient",
                    "redirect_uris": "https://client.test/cb",
                    "scopes": scopes
                })
                .to_string(),
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "app register failed: {body}");
    let registered: Value = serde_json::from_str(&body).expect("json");
    (
        registered["client_id"]
            .as_str()
            .expect("client_id")
            .to_owned(),
        registered["client_secret"]
            .as_str()
            .expect("client_secret")
            .to_owned(),
    )
}

async fn start_consent(
    app: &Router,
    session_secret: &str,
    client_id: &str,
    scope: &str,
    challenge: &str,
) -> (StatusCode, String, String) {
    let (status, headers, html) = send(
        app,
        Request::builder()
            .method("GET")
            .uri(format!(
                "/oauth/authorize?client_id={client_id}&redirect_uri=https://client.test/cb&response_type=code&scope={scope}&code_challenge={challenge}&code_challenge_method=S256"
            ))
            .header(
                header::COOKIE,
                format!("{}={session_secret}", nodus_auth::SESSION_COOKIE),
            )
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    let csrf_token = extract_csrf_input(&html).unwrap_or_default();
    let csrf_nonce = parse_cookies(&headers)
        .get("nodus_csrf")
        .cloned()
        .unwrap_or_default();
    (status, csrf_nonce, csrf_token)
}

async fn submit_consent(
    app: &Router,
    cookie_header: &str,
    client_id: &str,
    scopes: &str,
    challenge: &str,
    csrf_token: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut pairs = vec![
        ("client_id", client_id),
        ("redirect_uri", "https://client.test/cb"),
        ("scopes", scopes),
        ("code_challenge", challenge),
        ("decision", "allow"),
    ];
    if let Some(token) = csrf_token {
        pairs.push(("csrf_token", token));
    }
    send(
        app,
        Request::builder()
            .method("POST")
            .uri("/oauth/authorize")
            .header(header::COOKIE, cookie_header)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form_body(&pairs))
            .expect("request"),
    )
    .await
}

fn extract_code_from_location(headers: &axum::http::HeaderMap) -> String {
    let location = headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("redirect location");
    url::Url::parse(location)
        .expect("valid redirect url")
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("code param")
}

#[tokio::test]
async fn admin_routes_require_both_admin_flag_and_admin_scopes() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (non_admin_id, _) = create_account(pool, "user", false).await;
        let (admin_id, _) = create_account(pool, "admin", true).await;
        let (target_id, _) = create_account(pool, "target", false).await;

        let non_admin_escalated =
            create_token_with_scopes(pool, &non_admin_id, &["admin:read", "admin:write"]).await;
        let admin_basic_scopes =
            create_token_with_scopes(pool, &admin_id, &["read", "write"]).await;
        let admin_read_only = create_token_with_scopes(pool, &admin_id, &["admin:read"]).await;
        let real_admin_token =
            create_token_with_scopes(pool, &admin_id, &["admin:read", "admin:write"]).await;

        // Non-admin with admin scopes is rejected on announcements.
        let (status, _) = send_bearer(
            &app,
            "GET",
            "/api/v1/admin/announcements",
            &non_admin_escalated,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send_bearer(
            &app,
            "POST",
            "/api/v1/admin/announcements",
            &non_admin_escalated,
            Some(&[("content", "spoofed"), ("published", "true")]),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Admin with only read/write scopes is rejected on all admin routes.
        let action_uri = format!("/api/v1/admin/accounts/{target_id}/action");
        for (method, uri, form) in [
            ("GET", "/api/v1/admin/alerts", None),
            ("GET", "/api/v1/admin/accounts", None),
            ("GET", "/api/v1/admin/domain_blocks", None),
            ("GET", "/api/v1/admin/audit", None),
            ("GET", "/api/v1/admin/announcements", None),
            (
                "POST",
                action_uri.as_str(),
                Some(&[("type", "silence")][..]),
            ),
            (
                "POST",
                "/api/v1/admin/domain_blocks",
                Some(&[("domain", "evil.test")][..]),
            ),
        ] {
            let (status, body) = send_bearer(&app, method, uri, &admin_basic_scopes, form).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{method} {uri} should require admin scope, got {status}: {body}"
            );
        }

        // Admin with admin:read can read, but cannot write.
        let (status, _) =
            send_bearer(&app, "GET", "/api/v1/admin/alerts", &admin_read_only, None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = send_bearer(
            &app,
            "POST",
            &action_uri,
            &admin_read_only,
            Some(&[("type", "silence")]),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Real admin creates announcement; non-admin with admin:write cannot update/delete it.
        let (status, body) = send_bearer(
            &app,
            "POST",
            "/api/v1/admin/announcements",
            &real_admin_token,
            Some(&[("content", "legit"), ("published", "true")]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "admin announcement failed: {body}");
        let ann_id = serde_json::from_str::<Value>(&body).expect("json")["id"]
            .as_str()
            .expect("announcement id")
            .to_owned();
        let ann_uri = format!("/api/v1/admin/announcements/{ann_id}");
        let (status, _) = send_bearer(
            &app,
            "PUT",
            &ann_uri,
            &non_admin_escalated,
            Some(&[("content", "hijacked"), ("published", "true")]),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send_bearer(&app, "DELETE", &ann_uri, &non_admin_escalated, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    })
    .await;
}

#[tokio::test]
async fn apps_register_rejects_unsafe_redirect_uris_and_invalid_scopes() {
    run_db_test(|_, app| async move {
        for bad_uri in [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:msgbox(1)",
            "file:///etc/passwd",
        ] {
            let (status, _, body) = send(
                &app,
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/apps")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "client_name": "EvilApp",
                            "redirect_uris": bad_uri,
                            "scopes": "read"
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "redirect_uri {bad_uri} should be rejected, got {status}: {body}"
            );
        }

        let (status, _, body) = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/v1/apps")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "client_name": "BadScopeApp",
                        "redirect_uris": "https://client.test/cb",
                        "scopes": "read superadmin_power"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "arbitrary scope should be rejected: {body}"
        );

        for good_uri in [
            "https://client.test/cb",
            "http://localhost:3000/cb",
            "urn:ietf:wg:oauth:2.0:oob",
        ] {
            let (status, _, body) = send(
                &app,
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/apps")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "client_name": "GoodApp",
                            "redirect_uris": good_uri,
                            "scopes": "read write"
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "good_uri {good_uri} failed: {body}");
        }
    })
    .await;
}

#[tokio::test]
async fn oauth_rejects_client_secret_bypass_scope_escalation_and_csrf() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (user_id, _) = create_account(pool, "oauth_user", false).await;
        let session_secret = create_browser_session(pool, &user_id).await;
        let (client_id, client_secret) = register_app(&app, "read admin:write").await;

        let verifier = "v".repeat(43);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

        let (status, _, _) =
            start_consent(&app, &session_secret, &client_id, "admin:write", &challenge).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, csrf_nonce, csrf_token) =
            start_consent(&app, &session_secret, &client_id, "read", &challenge).await;
        assert_eq!(status, StatusCode::OK);
        let cookie_header = format!(
            "{}={session_secret}; nodus_csrf={csrf_nonce}",
            nodus_auth::SESSION_COOKIE
        );

        let (status, _, _) =
            submit_consent(&app, &cookie_header, &client_id, "read", &challenge, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _, _) = submit_consent(
            &app,
            &cookie_header,
            &client_id,
            "read write",
            &challenge,
            Some(&csrf_token),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _, _) = submit_consent(
            &app,
            &cookie_header,
            &client_id,
            "admin:write",
            &challenge,
            Some(&csrf_token),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, headers, _) = submit_consent(
            &app,
            &cookie_header,
            &client_id,
            "read",
            &challenge,
            Some(&csrf_token),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let code = extract_code_from_location(&headers);

        let (status, _, body) = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(form_body(&[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("redirect_uri", "https://client.test/cb"),
                    ("client_id", &client_id),
                    ("code_verifier", &verifier),
                ]))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_client"), "body was {body}");

        let (status, _, body) = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(form_body(&[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("redirect_uri", "https://client.test/cb"),
                    ("client_id", &client_id),
                    ("client_secret", &client_secret),
                    ("code_verifier", &verifier),
                ]))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "token exchange failed: {body}");
    })
    .await;
}

#[tokio::test]
async fn oauth_token_rejects_admin_scope_if_account_demoted_before_exchange() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (demoted_id, _) = create_account(pool, "demoted", true).await;
        let demoted_session = create_browser_session(pool, &demoted_id).await;
        let (client_id, client_secret) = register_app(&app, "read admin:write").await;

        let verifier = "v".repeat(43);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let (status, csrf_nonce, csrf_token) = start_consent(
            &app,
            &demoted_session,
            &client_id,
            "admin:write",
            &challenge,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let cookie_header = format!(
            "{}={demoted_session}; nodus_csrf={csrf_nonce}",
            nodus_auth::SESSION_COOKIE
        );
        let (status, headers, _) = submit_consent(
            &app,
            &cookie_header,
            &client_id,
            "admin:write",
            &challenge,
            Some(&csrf_token),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let code = extract_code_from_location(&headers);

        accounts::set_admin(pool, &demoted_id, false)
            .await
            .expect("demote");

        let (status, _, body) = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(form_body(&[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("redirect_uri", "https://client.test/cb"),
                    ("client_id", &client_id),
                    ("client_secret", &client_secret),
                    ("code_verifier", &verifier),
                ]))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("access_denied"), "body was {body}");
    })
    .await;
}

#[tokio::test]
async fn miauth_prevents_admin_escalation_and_unsafe_callbacks() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (user_id, _) = create_account(pool, "miauth_u", false).await;
        let session_secret = create_browser_session(pool, &user_id).await;
        let auth_cookie = format!("{}={session_secret}", nodus_auth::SESSION_COOKIE);
        let miauth_session = Id::new().to_string();

        for (uri, cookie, expected) in [
            (
                format!("/miauth/{miauth_session}?name=Evil&permission=admin:write"),
                Some(auth_cookie.as_str()),
                StatusCode::FORBIDDEN,
            ),
            (
                format!("/miauth/{miauth_session}?name=Anon&permission=read"),
                None,
                StatusCode::UNAUTHORIZED,
            ),
            (
                format!(
                    "/miauth/{miauth_session}?name=BadCb&permission=read&callback=javascript:alert(1)"
                ),
                Some(auth_cookie.as_str()),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ] {
            let mut req = Request::builder().method("GET").uri(&uri);
            if let Some(c) = cookie {
                req = req.header(header::COOKIE, c);
            }
            let (status, _, _) = send(&app, req.body(Body::empty()).expect("request")).await;
            assert_eq!(status, expected, "GET {uri}");
        }

        // Non-admin cannot approve an existing admin:write MiAuth session.
        let (admin_id, _) = create_account(pool, "miauth_admin", true).await;
        let admin_secret = create_browser_session(pool, &admin_id).await;
        let admin_miauth = Id::new().to_string();
        let (status, _, _) = send(
            &app,
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/miauth/{admin_miauth}?name=AdminApp&permission=admin:write"
                ))
                .header(
                    header::COOKIE,
                    format!("{}={admin_secret}", nodus_auth::SESSION_COOKIE),
                )
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let csrf_nonce = opaque_token();
        let user_csrf = nodus_auth::domain::csrf_token(&csrf_nonce, Some(&session_secret));
        let (status, _, _) = send(
            &app,
            Request::builder()
                .method("POST")
                .uri(format!("/miauth/{admin_miauth}"))
                .header(header::COOKIE, format!("{auth_cookie}; nodus_csrf={csrf_nonce}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(form_body(&[("name", "AdminApp"), ("csrf_token", &user_csrf)]))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    })
    .await;
}

#[tokio::test]
async fn miauth_prevents_replay_overwrite_and_csrf() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (user_id, _) = create_account(pool, "miauth_u2", false).await;
        let session_secret = create_browser_session(pool, &user_id).await;
        let auth_cookie = format!("{}={session_secret}", nodus_auth::SESSION_COOKIE);
        let miauth_session = Id::new().to_string();

        let (status, headers, html) = send(
            &app,
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/miauth/{miauth_session}?name=LegitApp&permission=read,write"
                ))
                .header(header::COOKIE, &auth_cookie)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let csrf_token = extract_csrf_input(&html).expect("miauth form must have csrf_token");
        let csrf_nonce = parse_cookies(&headers)
            .get("nodus_csrf")
            .expect("miauth GET must set nodus_csrf cookie")
            .clone();
        let full_cookie = format!("{auth_cookie}; nodus_csrf={csrf_nonce}");

        let (status, _, _) = send(
            &app,
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/miauth/{miauth_session}?name=Overwritten&permission=read"
                ))
                .header(header::COOKIE, &full_cookie)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        let (status, _, _) = send(
            &app,
            Request::builder()
                .method("POST")
                .uri(format!("/miauth/{miauth_session}"))
                .header(header::COOKIE, &full_cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(form_body(&[("name", "LegitApp")]))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _, _) = send(
            &app,
            Request::builder()
                .method("POST")
                .uri(format!("/miauth/{miauth_session}"))
                .header(header::COOKIE, &full_cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(form_body(&[
                    ("name", "LegitApp"),
                    ("csrf_token", &csrf_token),
                ]))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let check_uri = format!("/api/miauth/{miauth_session}/check");
        let (status, _, body) = send(
            &app,
            Request::builder()
                .method("POST")
                .uri(&check_uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let first: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(first["ok"], true);
        assert!(first["token"].as_str().is_some());

        let (status, _, body) = send(
            &app,
            Request::builder()
                .method("POST")
                .uri(&check_uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let second: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(second["ok"], false);
        assert!(second["token"].is_null());
    })
    .await;
}

async fn send_cookie_req(app: &Router, method: &str, uri: &str, cookie: &str) -> StatusCode {
    send(
        app,
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .expect("request"),
    )
    .await
    .0
}

#[tokio::test]
async fn login_requires_csrf_and_logout_requires_post() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let (user_id, _) = create_account(pool, "login_u", false).await;
        let pw_hash = nodus_auth::hash_password("correct-horse-battery-staple").expect("hash");
        PgAuthStore::new(pool.clone())
            .create_credential(&user_id, "user@social.test", &pw_hash)
            .await
            .expect("create credential");

        let (status, _, _) = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(form_body(&[
                    ("email", "user@social.test"),
                    ("password", "correct-horse-battery-staple"),
                ]))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, headers, html) = send(
            &app,
            Request::builder()
                .method("GET")
                .uri("/auth/login")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let csrf_token = extract_csrf_input(&html).expect("login form must have csrf_token");
        let csrf_nonce = parse_cookies(&headers)
            .get("nodus_csrf")
            .expect("login GET must set nodus_csrf cookie")
            .clone();

        let (status, headers, _) = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header(header::COOKIE, format!("nodus_csrf={csrf_nonce}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(form_body(&[
                    ("email", "user@social.test"),
                    ("password", "correct-horse-battery-staple"),
                    ("csrf_token", &csrf_token),
                ]))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let session_cookie = parse_cookies(&headers)
            .get(nodus_auth::SESSION_COOKIE)
            .expect("session cookie")
            .clone();
        let auth_header = format!("{}={session_cookie}", nodus_auth::SESSION_COOKIE);

        assert_eq!(
            send_cookie_req(&app, "GET", "/auth/logout", &auth_header).await,
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            send_cookie_req(&app, "GET", "/auth/session", &auth_header).await,
            StatusCode::OK
        );
        assert_eq!(
            send_cookie_req(&app, "POST", "/auth/logout", &auth_header).await,
            StatusCode::SEE_OTHER
        );
        assert_eq!(
            send_cookie_req(&app, "GET", "/auth/session", &auth_header).await,
            StatusCode::UNAUTHORIZED
        );
    })
    .await;
}
