//! The endpoints a Mastodon client calls on every screen it has, exercised against a
//! real Postgres schema.
//!
//! The whole file is skipped when `DATABASE_URL` is unset (see the harness at the bottom),
//! which is what keeps `cargo test` usable on a machine without a database.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use base64::Engine as _;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

use nodus_server_api::{root_router, AppState, InstanceConfig};
use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount};
use nodus_server_store::social;
use nodus_server_store::statuses::{self, NewStatus};
use nodus_server_store::Store;

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

/// Runs `body` against a schema of its own, then drops the schema.
async fn run_db_test<F, Fut>(body: F)
where
    F: FnOnce(Store, Router) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some(url) = std::env::var("DATABASE_URL").ok() else {
        return;
    };
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

async fn create_account(pool: &PgPool, label: &str) -> String {
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

async fn create_token(pool: &PgPool, account_id: &str, scopes: &[&str]) -> String {
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

async fn create_status(
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

/// A request with no `Authorization` header at all — an empty bearer token is a bad
/// token, not an anonymous reader.
async fn send_anon(app: &Router, method: &str, uri: &str) -> (StatusCode, String) {
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

async fn send_form(
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

fn json_of(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or_else(|err| panic!("body was not JSON ({err}): {body}"))
}

#[tokio::test]
async fn notifications_round_trip() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let actor = create_account(&pool, "actor").await;
        let token = create_token(&pool, &reader, &["read", "write"]).await;
        let status = create_status(&pool, &actor, "hello", "public", &[], &[]).await;
        social::notify(&pool, &reader, "favourite", &actor, Some(&status))
            .await
            .expect("notify");

        let (status_code, body) = send(&app, &token, "GET", "/api/v1/notifications", None).await;
        assert_eq!(status_code, StatusCode::OK);
        let items = json_of(&body);
        let first = items
            .as_array()
            .and_then(|items| items.first())
            .expect("one notification");
        assert_eq!(first["type"], "favourite");
        assert_eq!(first["account"]["id"], actor);
        assert_eq!(first["status"]["id"], status);
        let id = first["id"].as_str().expect("id").to_owned();

        // Excluding the kind that exists leaves nothing behind.
        let (_, body) = send(
            &app,
            &token,
            "GET",
            "/api/v1/notifications?exclude_types[]=favourite",
            None,
        )
        .await;
        assert_eq!(json_of(&body).as_array().expect("array").len(), 0);

        let (status_code, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/notifications/{id}"),
            None,
        )
        .await;
        assert_eq!(status_code, StatusCode::OK);
        assert_eq!(json_of(&body)["id"], id);

        let (status_code, _) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/notifications/{id}"),
            Some(json!({})),
        )
        .await;
        assert_eq!(status_code, StatusCode::OK);
        let seen: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT seen_at FROM notification WHERE id = $1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .expect("seen_at");
        assert!(seen.is_some(), "mark seen must write seen_at");

        let (status_code, _) =
            send(&app, &token, "POST", "/api/v1/notifications/clear", None).await;
        assert_eq!(status_code, StatusCode::OK);
        let (_, body) = send(&app, &token, "GET", "/api/v1/notifications", None).await;
        assert_eq!(json_of(&body).as_array().expect("array").len(), 0);
    })
    .await;
}

#[tokio::test]
async fn favourites_and_bookmarks_list_what_the_reader_saved() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let author = create_account(&pool, "author").await;
        let token = create_token(&pool, &reader, &["read", "write"]).await;
        let status = create_status(&pool, &author, "save me", "public", &[], &[]).await;

        let (status_code, _) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/statuses/{status}/favourite"),
            Some(json!({})),
        )
        .await;
        assert_eq!(status_code, StatusCode::OK);
        let (status_code, _) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/statuses/{status}/bookmark"),
            Some(json!({})),
        )
        .await;
        assert_eq!(status_code, StatusCode::OK);

        let (status_code, body) = send(&app, &token, "GET", "/api/v1/favourites", None).await;
        assert_eq!(status_code, StatusCode::OK);
        let items = json_of(&body);
        assert_eq!(items.as_array().expect("array").len(), 1);
        assert_eq!(items[0]["id"], status);
        assert_eq!(items[0]["favourited"], true);

        let (status_code, body) = send(&app, &token, "GET", "/api/v1/bookmarks", None).await;
        assert_eq!(status_code, StatusCode::OK);
        let items = json_of(&body);
        assert_eq!(items.as_array().expect("array").len(), 1);
        assert_eq!(items[0]["id"], status);
        assert_eq!(items[0]["bookmarked"], true);
    })
    .await;
}

#[tokio::test]
async fn search_finds_accounts_statuses_and_tags() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "searcher").await;
        let author = create_account(&pool, "quincy").await;
        let token = create_token(&pool, &reader, &["read"]).await;
        let status = create_status(
            &pool,
            &author,
            "quokka spotting",
            "public",
            &[],
            &["quokkas"],
        )
        .await;

        let (status_code, body) = send(&app, &token, "GET", "/api/v2/search?q=quincy", None).await;
        assert_eq!(status_code, StatusCode::OK);
        let found = json_of(&body);
        assert!(
            found["accounts"]
                .as_array()
                .expect("accounts")
                .iter()
                .any(|account| account["id"] == author),
            "search must find the account: {found}"
        );

        let (_, body) = send(&app, &token, "GET", "/api/v2/search?q=quokka", None).await;
        let found = json_of(&body);
        assert!(
            found["statuses"]
                .as_array()
                .expect("statuses")
                .iter()
                .any(|row| row["id"] == status),
            "search must find the status: {found}"
        );
        assert!(
            found["hashtags"]
                .as_array()
                .expect("hashtags")
                .iter()
                .any(|tag| tag["name"] == "quokkas"),
            "search must find the tag: {found}"
        );

        let (_, body) = send(
            &app,
            &token,
            "GET",
            "/api/v2/search?q=quokka&type=accounts",
            None,
        )
        .await;
        let found = json_of(&body);
        assert!(
            found["statuses"].as_array().expect("statuses").is_empty(),
            "a typed search must not return other kinds: {found}"
        );
    })
    .await;
}

#[tokio::test]
async fn markers_move_forward_only() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let token = create_token(&pool, &reader, &["read", "write"]).await;
        // Fixed ids: an ordering test needs an order, and two fresh ULIDs sort
        // arbitrarily.
        let first = "01M7GK5K46EA1TNQRY7N0N61YW".to_owned();
        let second = "01M7GK5K46EA1TNQRY7N0N61YX".to_owned();

        let (status_code, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/markers",
            Some(json!({ "home": { "last_read_id": first } })),
        )
        .await;
        assert_eq!(status_code, StatusCode::OK);
        assert_eq!(json_of(&body)["home"]["last_read_id"], first);

        let (_, body) = send(&app, &token, "GET", "/api/v1/markers", None).await;
        assert_eq!(json_of(&body)["home"]["last_read_id"], first);

        // A later position moves the marker forward.
        let (_, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/markers",
            Some(json!({ "home": { "last_read_id": second } })),
        )
        .await;
        assert_eq!(json_of(&body)["home"]["last_read_id"], second);

        // An older one does not move it backwards.
        let (_, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/markers",
            Some(json!({ "home": { "last_read_id": first } })),
        )
        .await;
        assert_eq!(
            json_of(&body)["home"]["last_read_id"],
            second,
            "a stale marker must not go backwards"
        );
    })
    .await;
}

#[tokio::test]
async fn direct_messages_appear_as_conversations_until_read() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let sender = create_account(&pool, "sender").await;
        let token = create_token(&pool, &reader, &["read", "write"]).await;
        let dm = create_status(
            &pool,
            &sender,
            "psst",
            "direct",
            std::slice::from_ref(&reader),
            &[],
        )
        .await;

        let (status_code, body) = send(&app, &token, "GET", "/api/v1/conversations", None).await;
        assert_eq!(status_code, StatusCode::OK);
        let items = json_of(&body);
        let conversation = items
            .as_array()
            .and_then(|items| items.first())
            .expect("one conversation");
        assert_eq!(conversation["unread"], true);
        assert_eq!(conversation["last_status"]["id"], dm);
        let participants = conversation["accounts"].as_array().expect("accounts");
        assert!(
            participants.iter().any(|account| account["id"] == sender),
            "the sender must be a participant: {conversation}"
        );
        let id = conversation["id"].as_str().expect("id").to_owned();

        let (status_code, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/conversations/{id}/read"),
            Some(json!({})),
        )
        .await;
        assert_eq!(status_code, StatusCode::OK);
        assert_eq!(json_of(&body)["unread"], false);

        let (_, body) = send(&app, &token, "GET", "/api/v1/conversations", None).await;
        assert_eq!(json_of(&body)[0]["unread"], false);
    })
    .await;
}

#[tokio::test]
async fn a_locked_account_lists_and_answers_follow_requests() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let owner = create_account(&pool, "owner").await;
        let suitor = create_account(&pool, "suitor").await;
        let token = create_token(&pool, &owner, &["read", "write"]).await;
        sqlx::query("UPDATE account SET locked = true WHERE id = $1")
            .bind(&owner)
            .execute(&pool)
            .await
            .expect("lock the account");
        social::follow(&pool, &suitor, &owner, true, false)
            .await
            .expect("request follow");

        let (status_code, body) = send(&app, &token, "GET", "/api/v1/follow_requests", None).await;
        assert_eq!(status_code, StatusCode::OK);
        let items = json_of(&body);
        assert_eq!(items.as_array().expect("array").len(), 1);
        assert_eq!(items[0]["id"], suitor);

        let (status_code, _) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/follow_requests/{suitor}/authorize"),
            None,
        )
        .await;
        assert_eq!(status_code, StatusCode::OK);
        let state: String = sqlx::query_scalar(
            "SELECT state FROM follow WHERE account_id = $1 AND target_account_id = $2",
        )
        .bind(&suitor)
        .bind(&owner)
        .fetch_one(&pool)
        .await
        .expect("follow row");
        assert_eq!(state, "accepted");

        let (_, body) = send(&app, &token, "GET", "/api/v1/follow_requests", None).await;
        assert_eq!(json_of(&body).as_array().expect("array").len(), 0);
    })
    .await;
}

#[tokio::test]
async fn preferences_emoji_and_trends_answer_in_mastodon_shape() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let token = create_token(&pool, &reader, &["read"]).await;
        sqlx::query(
            "INSERT INTO custom_emoji (shortcode, host, url) VALUES ('blobcat', '', 'https://social.test/emoji/blobcat.png')",
        )
        .execute(&pool)
        .await
        .expect("insert emoji");
        // Two authors are needed for a tag to count as trending.
        let one = create_account(&pool, "one").await;
        let two = create_account(&pool, "two").await;
        create_status(&pool, &one, "hot take", "public", &[], &["hottake"]).await;
        create_status(&pool, &two, "hotter take", "public", &[], &["hottake"]).await;

        let (status_code, body) = send(&app, &token, "GET", "/api/v1/preferences", None).await;
        assert_eq!(status_code, StatusCode::OK);
        assert_eq!(json_of(&body)["posting:default:visibility"], "public");

        let (status_code, body) = send(&app, &token, "GET", "/api/v1/custom_emojis", None).await;
        assert_eq!(status_code, StatusCode::OK);
        let emojis = json_of(&body);
        assert_eq!(emojis[0]["shortcode"], "blobcat");

        let (status_code, body) = send(&app, &token, "GET", "/api/v1/trends/tags", None).await;
        assert_eq!(status_code, StatusCode::OK);
        let tags = json_of(&body);
        assert_eq!(tags[0]["name"], "hottake");
        assert_eq!(tags[0]["url"], "https://social.test/tags/hottake");

        let (status_code, body) = send(&app, &token, "GET", "/api/v1/trends/statuses", None).await;
        assert_eq!(status_code, StatusCode::OK);
        assert_eq!(json_of(&body).as_array().expect("array").len(), 2);
    })
    .await;
}

#[tokio::test]
async fn an_unknown_route_says_which_one() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let token = create_token(&pool, &reader, &["read"]).await;
        let (status_code, body) =
            send(&app, &token, "GET", "/api/v1/not-a-real-endpoint", None).await;
        assert_eq!(status_code, StatusCode::NOT_FOUND);
        let error = json_of(&body);
        let message = error["error"].as_str().expect("error message");
        assert!(
            message.contains("/api/v1/not-a-real-endpoint"),
            "the 404 must name the path, got {message}"
        );
    })
    .await;
}

async fn register_client(app: &Router, redirect_uris: &str) -> Value {
    let (status, body) = send(
        app,
        "",
        "POST",
        "/api/v1/apps",
        Some(json!({
            "client_name": "ParityClient",
            "redirect_uris": redirect_uris,
            "scopes": "read write"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "app register failed: {body}");
    json_of(&body)
}

async fn post_form(app: &Router, uri: &str, pairs: &[(&str, &str)]) -> (StatusCode, String) {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    let request = Request::builder()
        .method("POST")
        .uri(uri)
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

fn pkce_pair() -> (String, String) {
    let verifier = "v".repeat(43);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(<sha2::Sha256 as sha2::Digest>::digest(verifier.as_bytes()));
    (verifier, challenge)
}

#[tokio::test]
async fn an_app_may_register_a_urn_redirect() {
    run_db_test(|store, app| async move {
        let _ = store;
        // The OOB identifier Mastodon clients send, and the `ugc` variant.
        let registered = register_client(&app, "urn:ietf:wg:oauth:2.0:oob").await;
        assert_eq!(registered["redirect_uri"], "urn:ietf:wg:oauth:2.0:oob");
        let registered = register_client(&app, "urn:ietf:wg:oauth:2.0:ugc").await;
        assert_eq!(registered["redirect_uri"], "urn:ietf:wg:oauth:2.0:ugc");
        // An app's own scheme, as a mobile client registers it.
        let registered = register_client(&app, "org.joinmastodon.android:/oauth2redirect").await;
        assert_eq!(
            registered["redirect_uri"],
            "org.joinmastodon.android:/oauth2redirect"
        );
    })
    .await;
}

#[tokio::test]
async fn a_public_client_redeems_a_code_without_a_secret() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let reader = create_account(pool, "reader").await;
        let registered = register_client(&app, "urn:ietf:wg:oauth:2.0:ugc").await;
        let app_id = registered["id"].as_str().expect("id").to_owned();
        let client_id = registered["client_id"]
            .as_str()
            .expect("client_id")
            .to_owned();
        let redirect_uri = "urn:ietf:wg:oauth:2.0:ugc";
        let (verifier, challenge) = pkce_pair();
        let auth_store = nodus_auth::store::PgAuthStore::new(pool.clone());

        let code = nodus_auth::domain::opaque_token();
        nodus_auth::store::AuthStore::create_code(
            &auth_store,
            &nodus_auth::domain::token_hash(&code),
            &app_id,
            &reader,
            redirect_uri,
            &["read".to_owned()],
            &challenge,
            chrono::Utc::now() + chrono::Duration::minutes(5),
        )
        .await
        .expect("store code");

        // No client_secret: PKCE alone carries the proof, which is what a browser
        // bundle or a mobile app can actually do.
        let (status, body) = post_form(
            &app,
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", redirect_uri),
                ("client_id", &client_id),
                ("code_verifier", &verifier),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "token exchange failed: {body}");
        let issued = json_of(&body);
        assert_eq!(issued["token_type"], "Bearer");
        assert_ne!(issued["access_token"].as_str().expect("token"), "");

        // A secret that is presented still has to be the right one.
        let second = nodus_auth::domain::opaque_token();
        nodus_auth::store::AuthStore::create_code(
            &auth_store,
            &nodus_auth::domain::token_hash(&second),
            &app_id,
            &reader,
            redirect_uri,
            &["read".to_owned()],
            &challenge,
            chrono::Utc::now() + chrono::Duration::minutes(5),
        )
        .await
        .expect("store code");
        let (status, body) = post_form(
            &app,
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &second),
                ("redirect_uri", redirect_uri),
                ("client_id", &client_id),
                ("client_secret", "not-the-secret"),
                ("code_verifier", &verifier),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_client"), "body was {body}");
    })
    .await;
}

#[tokio::test]
async fn the_directory_lists_discoverable_accounts() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let token = create_token(&pool, &reader, &["read"]).await;

        let (status, body) = send(
            &app,
            &token,
            "GET",
            "/api/v1/directory?local=true&order=active&limit=10",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let page = json_of(&body);
        let page = page.as_array().expect("directory is a list");
        assert!(
            page.iter().any(|account| account["id"] == json!(reader)),
            "the account that exists was not suggested: {body}"
        );
        // A directory row is a full account, not just a handle.
        assert!(page[0]["username"].is_string(), "body was {body}");
        assert!(page[0]["acct"].is_string(), "body was {body}");
        assert!(page[0]["url"].is_string(), "body was {body}");
    })
    .await;
}

#[tokio::test]
async fn rules_and_languages_describe_the_instance() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let token = create_token(&pool, &reader, &["read", "write"]).await;

        let (status, body) = send(&app, &token, "GET", "/api/v1/instance/rules", None).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(json_of(&body), json!([]), "an empty rule list is a list");

        sqlx::query("INSERT INTO instance_rule (id, text, hint, ordinal) VALUES ($1, $2, $3, 1)")
            .bind(Id::new().to_string())
            .bind("Be kind")
            .bind("Seriously")
            .execute(&pool)
            .await
            .expect("insert rule");
        let (status, body) = send(&app, &token, "GET", "/api/v1/instance/rules", None).await;
        assert_eq!(status, StatusCode::OK);
        let rules = json_of(&body);
        assert_eq!(rules[0]["text"], json!("Be kind"));
        assert_eq!(rules[0]["hint"], json!("Seriously"));

        let (status, body) = send(&app, &token, "GET", "/api/v1/instance/languages", None).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(json_of(&body), json!([]), "no posts means no languages");

        // A language is reported only once something was written in it.
        let status_id = create_status(&pool, &reader, "hello", "public", &[], &[]).await;
        sqlx::query("UPDATE status SET language = 'en' WHERE id = $1")
            .bind(&status_id)
            .execute(&pool)
            .await
            .expect("set language");
        let (status, body) = send(&app, &token, "GET", "/api/v1/instance/languages", None).await;
        assert_eq!(status, StatusCode::OK);
        let languages = json_of(&body);
        assert_eq!(languages[0]["code"], json!("en"));
        assert_eq!(languages[0]["name"], json!("English"));
    })
    .await;
}

#[tokio::test]
async fn featured_tags_are_added_listed_and_removed() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let token = create_token(&pool, &reader, &["read", "write"]).await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/featured_tags",
            Some(json!({ "name": "#Rust" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let tag = json_of(&body);
        // The `#` belongs to the presentation, not the tag.
        assert_eq!(tag["name"], json!("rust"));
        let tag_id = tag["id"].as_str().expect("id").to_owned();

        let (status, body) = send(&app, &token, "GET", "/api/v1/featured_tags", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json_of(&body).as_array().expect("list").len(), 1);

        // Any reader sees another profile's tags, which is the point of the feature.
        let (status, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/accounts/{reader}/featured_tags"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(json_of(&body)[0]["name"], json!("rust"));

        // Featuring the same tag twice is not an error and does not duplicate it.
        let (status, _) = send(
            &app,
            &token,
            "POST",
            "/api/v1/featured_tags",
            Some(json!({ "name": "rust" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = send(
            &app,
            &token,
            "DELETE",
            &format!("/api/v1/featured_tags/{tag_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = send(&app, &token, "GET", "/api/v1/featured_tags", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json_of(&body), json!([]), "body was {body}");
    })
    .await;
}

#[tokio::test]
async fn a_scheduled_post_is_queued_published_or_cancelled() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let token = create_token(&pool, &reader, &["read", "write"]).await;

        let later = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/statuses",
            Some(json!({ "status": "queued", "scheduled_at": later })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let queued = json_of(&body);
        // A scheduled create answers with the schedule, not with a status.
        assert_eq!(queued["params"]["text"], json!("queued"));
        let queued_id = queued["id"].as_str().expect("id").to_owned();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM status WHERE content = 'queued'")
                .fetch_one(&pool)
                .await
                .expect("count"),
            0,
            "a queued post must not exist yet"
        );

        let (status, body) = send(&app, &token, "GET", "/api/v1/scheduled_statuses", None).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(json_of(&body).as_array().expect("list").len(), 1);

        // A second schedule is cancelled, which takes it out of the queue.
        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/statuses",
            Some(json!({ "status": "cancelled", "scheduled_at": later })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let cancelled_id = json_of(&body)["id"].as_str().expect("id").to_owned();
        let (status, _) = send(
            &app,
            &token,
            "DELETE",
            &format!("/api/v1/scheduled_statuses/{cancelled_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Cancelling twice is a 404, so a stale screen learns it is stale.
        let (status, _) = send(
            &app,
            &token,
            "DELETE",
            &format!("/api/v1/scheduled_statuses/{cancelled_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // A time in the past is refused at write time rather than published immediately.
        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/statuses",
            Some(json!({
                "status": "yesterday",
                "scheduled_at": (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339(),
            })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body was {body}");

        // Publishing is what the background loop does; driving it directly makes the test
        // deterministic instead of sleeping for half a minute.
        sqlx::query(
            "UPDATE scheduled_status SET scheduled_at = now() - interval '1 minute' WHERE id = $1",
        )
        .bind(&queued_id)
        .execute(&pool)
        .await
        .expect("make it due");
        let published = nodus_server_api::schedules::publish_due(&AppState::new(
            store.clone(),
            instance_config(),
        ))
        .await
        .expect("publish");
        assert_eq!(published, 1, "one post was due");
        let content = sqlx::query_scalar::<_, String>(
            "SELECT content FROM status WHERE content = 'queued' AND deleted_at IS NULL",
        )
        .fetch_one(&pool)
        .await
        .expect("the scheduled post exists");
        assert_eq!(content, "queued");
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scheduled_status")
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(
            left, 0,
            "the published row is deleted and the cancelled one already was"
        );
    })
    .await;
}

#[tokio::test]
async fn a_conversation_can_be_muted() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let other = create_account(&pool, "other").await;
        let token = create_token(&pool, &reader, &["read", "write"]).await;

        let root = create_status(
            &pool,
            &other,
            "a message",
            "direct",
            std::slice::from_ref(&reader),
            &[],
        )
        .await;

        let (status, body) = send(&app, &token, "GET", "/api/v1/conversations", None).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let conversations = json_of(&body);
        assert_eq!(conversations[0]["id"], json!(root));
        assert_eq!(conversations[0]["unread"], json!(true));
        assert_eq!(conversations[0]["muted"], json!(false));

        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/conversations/{root}/mute"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(json_of(&body)["muted"], json!(true));

        // A muted thread stays in the inbox but stops asking for attention.
        let (status, body) = send(&app, &token, "GET", "/api/v1/conversations", None).await;
        assert_eq!(status, StatusCode::OK);
        let conversations = json_of(&body);
        assert_eq!(conversations.as_array().expect("list").len(), 1);
        assert_eq!(conversations[0]["muted"], json!(true));
        assert_eq!(conversations[0]["unread"], json!(false));

        let (status, body) = send(
            &app,
            &token,
            "DELETE",
            &format!("/api/v1/conversations/{root}/mute"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(json_of(&body)["muted"], json!(false));
    })
    .await;
}

#[tokio::test]
async fn credentials_can_be_edited() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "editor").await;
        let token = create_token(&pool, &reader, &["read", "write"]).await;

        let (status, body) = send(
            &app,
            &token,
            "PATCH",
            "/api/v1/accounts/update_credentials",
            Some(json!({
                "display_name": "A Name",
                "note": "hello there",
                "locked": true,
                "discoverable": false,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let account = json_of(&body);
        assert_eq!(account["display_name"], json!("A Name"));
        assert_eq!(account["note"], json!("hello there"));
        assert_eq!(account["locked"], json!(true));
        assert_eq!(account["discoverable"], json!(false));

        // A partial update leaves what it did not mention alone, which is what a form
        // that only touches the display name relies on.
        let (status, body) = send(
            &app,
            &token,
            "PATCH",
            "/api/v1/accounts/update_credentials",
            Some(json!({ "display_name": "Renamed" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let account = json_of(&body);
        assert_eq!(account["display_name"], json!("Renamed"));
        assert_eq!(account["note"], json!("hello there"));
        assert_eq!(account["locked"], json!(true));

        // Form encoding works too, because that is what a Mastodon client sends.
        let (status, body) = send_form(
            &app,
            &token,
            "PATCH",
            "/api/v1/accounts/update_credentials",
            &[("note", "from a form")],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(json_of(&body)["note"], json!("from a form"));

        let (status, body) = send(
            &app,
            &token,
            "PATCH",
            "/api/v1/accounts/update_credentials",
            Some(json!({ "display_name": "x".repeat(31) })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body was {body}");

        // An avatar has to be an image the reader uploaded; a made-up id is refused
        // instead of being written as a broken reference.
        let (status, body) = send(
            &app,
            &token,
            "PATCH",
            "/api/v1/accounts/update_credentials",
            Some(json!({ "avatar": "01M7GK5K46EA1TNQRY7N0N61YW" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body was {body}");
    })
    .await;
}

/// A remote account keeps the pictures its own instance published, and search finds it
/// without going back out to the network.
#[tokio::test]
async fn a_remembered_remote_account_is_searchable_and_server_pictured() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        nodus_server_store::accounts::upsert_remote(
            pool,
            &nodus_server_store::accounts::RemoteAccount {
                uri: "https://remote.test/users/tomostrawberry",
                username: "Tomostrawberry",
                domain: "remote.test",
                display_name: "Tom O'Strawberry",
                note: "<p>from elsewhere</p>",
                avatar_url: Some("https://remote.test/avatars/tom.png"),
                header_url: Some("https://remote.test/headers/tom.png"),
                inbox_url: Some("https://remote.test/users/tomostrawberry/inbox"),
                shared_inbox_url: Some("https://remote.test/inbox"),
                public_key_pem: None,
                locked: false,
                bot: false,
            },
        )
        .await
        .expect("store the remote account");

        let (status, body) = send_anon(&app, "GET", "/api/v2/search?q=tomostrawberry").await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let found = json_of(&body)["accounts"]
            .as_array()
            .expect("accounts")
            .first()
            .cloned()
            .expect("the remote account");
        assert_eq!(found["acct"], json!("Tomostrawberry@remote.test"));
        assert_eq!(
            found["avatar"],
            json!("https://remote.test/avatars/tom.png")
        );
        assert_eq!(
            found["header"],
            json!("https://remote.test/headers/tom.png")
        );

        // A refresh keeps the picture when the new document omits it.
        let refreshed = nodus_server_store::accounts::upsert_remote(
            pool,
            &nodus_server_store::accounts::RemoteAccount {
                uri: "https://remote.test/users/tomostrawberry",
                username: "Tomostrawberry",
                domain: "remote.test",
                display_name: "Tom",
                note: "",
                avatar_url: None,
                header_url: None,
                inbox_url: None,
                shared_inbox_url: None,
                public_key_pem: None,
                locked: true,
                bot: false,
            },
        )
        .await
        .expect("refresh the remote account");
        assert_eq!(
            refreshed.avatar_url.as_deref(),
            Some("https://remote.test/avatars/tom.png")
        );
        assert_eq!(refreshed.display_name, "Tom");
        assert!(refreshed.locked);
    })
    .await;
}

/// The profile header asks for one relationship and draws every verb from it, so every key a
/// client destructures must be present — `followed_by` is required by the client model with no
/// default, and a missing one fails the whole read, which is exactly how a profile ends up with
/// dead buttons.
#[tokio::test]
async fn a_relationship_carries_every_key_a_client_destructures() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let reader = create_account(pool, "reader").await;
        let subject = create_account(pool, "subject").await;
        let token = create_token(pool, &reader, &["read", "write"]).await;

        let (status, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/accounts/relationships?id[]={subject}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let row = &json_of(&body)[0];
        for key in [
            "id",
            "following",
            "followed_by",
            "blocking",
            "blocked_by",
            "requested",
            "muting",
            "muting_notifications",
            "domain_blocking",
            "endorsed",
        ] {
            assert!(
                row.get(key).is_some(),
                "relationship is missing `{key}`: {body}"
            );
        }
        assert_eq!(row["following"], Value::Bool(false));
        assert_eq!(row["followed_by"], Value::Bool(false));

        // The subject follows the reader: the same row must now say so.
        nodus_server_store::social::follow(pool, &subject, &reader, true, false)
            .await
            .expect("subject follows reader");

        let (status, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/accounts/relationships?id[]={subject}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(
            json_of(&body)[0]["followed_by"],
            Value::Bool(true),
            "the subject follows the reader: {body}"
        );
    })
    .await;
}
