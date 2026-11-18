//! Moderating one remote account instead of the server it lives on.
//!
//! Silence is the narrow power: the account's posts leave the public timeline but a link
//! someone already has still resolves. Suspension is the wide one: the account is gone from
//! threads and media, and its inbound activities are dropped at the door. Both are written
//! down with a reason and an optional expiry, and lifting one restores the account.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::{Duration, Utc};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{EncodePublicKey as _, LineEnding};
use rsa::rand_core::OsRng;
use rsa::signature::{SignatureEncoding as _, Signer as _};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

use nodus_server_api::{root_router, AppState, InstanceConfig};
use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount, RemoteAccount};
use nodus_server_store::statuses::{self, NewRemoteStatus};
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
    F: FnOnce(Store, AppState) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some((admin, store, schema)) = connect_isolated_store().await else {
        return;
    };
    let state = AppState::new(store.clone(), instance_config());
    let handle = tokio::spawn(async move { body(store, state).await });
    let outcome = handle.await;

    let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
        .execute(admin.pool())
        .await;

    if let Err(err) = outcome {
        std::panic::resume_unwind(err.into_panic());
    }
}

async fn create_account(pool: &PgPool, label: &str, admin: bool) -> String {
    let username = format!("pgtest_{label}_{}", Id::new());
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
        sqlx::query("UPDATE account SET admin = true, approved = true WHERE id = $1")
            .bind(&row.id)
            .execute(pool)
            .await
            .expect("make the account staff");
    }
    row.id
}

async fn create_token(pool: &PgPool, account_id: &str, scopes: &[&str]) -> String {
    let app_id = Id::new().to_string();
    let client_id = format!("pgtest-client-{app_id}");
    let scopes: Vec<String> = scopes.iter().map(|scope| (*scope).to_owned()).collect();
    apps::register(
        pool,
        &app_id,
        &client_id,
        "unused",
        "pgtest",
        None,
        &["urn:ietf:wg:oauth:2.0:oob".to_owned()],
        &scopes,
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
    .bind(&scopes[..])
    .execute(pool)
    .await
    .expect("insert oauth token");

    token
}

async fn seed_remote(
    pool: &PgPool,
    uri: &str,
    username: &str,
    public_key_pem: Option<&str>,
) -> String {
    accounts::upsert_remote(
        pool,
        &RemoteAccount {
            uri,
            username,
            domain: "remote.test",
            display_name: username,
            note: "",
            avatar_url: None,
            header_url: None,
            inbox_url: Some(&format!("{uri}/inbox")),
            shared_inbox_url: None,
            public_key_pem,
            locked: false,
            bot: false,
        },
    )
    .await
    .expect("upsert remote actor")
    .id
}

async fn seed_remote_status(pool: &PgPool, account_id: &str, uri: &str, text: &str) -> String {
    let id = uri.to_owned();
    statuses::upsert_remote(
        pool,
        &NewRemoteStatus {
            id: &id,
            account_id,
            uri,
            content: text,
            content_html: &format!("<p>{text}</p>"),
            spoiler_text: "",
            sensitive: false,
            visibility: "public",
            in_reply_to_id: None,
            in_reply_to_account_id: None,
            created_at: Utc::now(),
        },
    )
    .await
    .expect("store remote status");
    id
}

/// A signed request with no body — the reads this file makes are all anonymous.
async fn get(state: &AppState, path: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .expect("request");
    exchange(state, request).await
}

async fn send(
    state: &AppState,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = match body {
        Some(value) => builder
            .header("content-type", "application/json")
            .body(Body::from(value.to_string()))
            .expect("request"),
        None => builder.body(Body::empty()).expect("request"),
    };
    exchange(state, request).await
}

async fn exchange(state: &AppState, request: Request<Body>) -> (StatusCode, Value) {
    let response = root_router(state.clone())
        .oneshot(request)
        .await
        .expect("router response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
        .await
        .expect("read body");
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

/// The path form of an actor URL: the wildcard segment carries it percent-encoded, the way
/// a console encodes it before it puts the URI in a URL.
fn actor_path(actor_uri: &str) -> String {
    let encoded: String = url::form_urlencoded::byte_serialize(actor_uri.as_bytes()).collect();
    format!("/api/v1/admin/federation/remote-accounts/{encoded}")
}

/// A remote status id is its URL, so it needs the same encoding in a path.
fn status_path(id: &str) -> String {
    let encoded: String = url::form_urlencoded::byte_serialize(id.as_bytes()).collect();
    format!("/api/v1/statuses/{encoded}")
}

fn timeline_ids(body: &Value) -> Vec<String> {
    body.as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row["id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn keypair() -> (RsaPrivateKey, String) {
    let private = RsaPrivateKey::new(&mut OsRng, 1024).expect("rsa key");
    let pem = RsaPublicKey::from(&private)
        .to_public_key_pem(LineEnding::LF)
        .expect("public key pem");
    (private, pem)
}

async fn post_signed_inbox(
    state: &AppState,
    private: &RsaPrivateKey,
    key_id: &str,
    activity: &Value,
) -> (StatusCode, Value) {
    let body_bytes = serde_json::to_vec(activity).expect("json bytes");
    let digest = format!("SHA-256={}", BASE64.encode(Sha256::digest(&body_bytes)));
    let date = Utc::now().to_rfc2822();
    let lines = [
        "(request-target): post /inbox".to_owned(),
        "host: social.test".to_owned(),
        format!("date: {date}"),
        format!("digest: {digest}"),
    ];
    let signature = SigningKey::<Sha256>::new(private.clone()).sign(lines.join("\n").as_bytes());
    let signature = format!(
        "keyId=\"{key_id}\",algorithm=\"rsa-sha256\",\
         headers=\"(request-target) host date digest\",signature=\"{}\"",
        BASE64.encode(signature.to_bytes())
    );
    let request = Request::builder()
        .method("POST")
        .uri("/inbox")
        .header("host", "social.test")
        .header("date", date)
        .header("digest", digest)
        .header("signature", signature)
        .body(Body::from(body_bytes))
        .expect("request");
    exchange(state, request).await
}

fn create_note(actor_uri: &str, note_uri: &str, text: &str) -> Value {
    json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{note_uri}/activity"),
        "type": "Create",
        "actor": actor_uri,
        "object": {
            "id": note_uri,
            "type": "Note",
            "attributedTo": actor_uri,
            "content": format!("<p>{text}</p>"),
            "published": "2026-01-01T00:00:00Z",
        }
    })
}

#[tokio::test]
async fn silence_hides_a_remote_post_from_the_public_timeline_but_not_its_url() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let staff = create_account(pool, "staff", true).await;
        let token = create_token(pool, &staff, &["read", "admin:read", "admin:write"]).await;
        let actor_uri = "https://remote.test/users/mallory";
        let account = seed_remote(pool, actor_uri, "mallory", None).await;
        let status = seed_remote_status(
            pool,
            &account,
            "https://remote.test/notes/one",
            "the post that will be silenced",
        )
        .await;

        let (_, before) = get(&state, "/api/v1/timelines/public?local=false").await;
        assert!(timeline_ids(&before).contains(&status), "body: {before}");

        let (code, body) = send(
            &state,
            "PUT",
            &actor_path(actor_uri),
            Some(&token),
            Some(json!({
                "action": "silence",
                "reason": "repeated harassment",
            })),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "body: {body}");
        assert_eq!(body["action"], "silence");
        assert_eq!(body["reason"], "repeated harassment");
        assert_eq!(body["domain"], "remote.test");
        assert_eq!(body["expired"], false);

        let (_, after) = get(&state, "/api/v1/timelines/public?local=false").await;
        assert!(
            !timeline_ids(&after).contains(&status),
            "a silenced account must leave the public timeline: {after}"
        );

        // Silence leaves the post reachable by the URL it was linked by.
        let (code, body) = get(&state, &status_path(&status)).await;
        assert_eq!(code, StatusCode::OK, "body: {body}");
        assert!(body["content"].is_string());

        // And it is still listed for staff, with what was decided and why.
        let (code, list) = send(
            &state,
            "GET",
            "/api/v1/admin/federation/remote-accounts?domain=remote.test",
            Some(&token),
            None,
        )
        .await;
        assert_eq!(code, StatusCode::OK, "body: {list}");
        let rows = list.as_array().expect("array");
        assert_eq!(rows.len(), 1, "body: {list}");
        assert_eq!(rows[0]["actor_uri"], actor_uri);
        assert_eq!(rows[0]["handle"], "mallory");
        assert!(rows[0]["created_by"].is_string());
    })
    .await;
}

#[tokio::test]
async fn suspend_drops_inbound_activities_and_hides_existing_posts() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let staff = create_account(pool, "staff", true).await;
        let token = create_token(pool, &staff, &["read", "admin:read", "admin:write"]).await;
        let actor_uri = "https://remote.test/users/mallory";
        let (private, pem) = keypair();
        let account = seed_remote(pool, actor_uri, "mallory", Some(&pem)).await;
        let existing = seed_remote_status(
            pool,
            &account,
            "https://remote.test/notes/before",
            "the post that already exists",
        )
        .await;

        let (code, body) = send(
            &state,
            "PUT",
            &actor_path(actor_uri),
            Some(&token),
            Some(json!({ "action": "suspend", "reason": "spam" })),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "body: {body}");

        // The peer is told, from the admin who decided, and the delivery is queued even
        // though the actor it names is the one being suspended.
        let tell: Option<String> = sqlx::query_scalar(
            "SELECT activity::text FROM federation_delivery \
              WHERE inbox_url = $1 AND activity->>'type' = 'Block' \
              AND activity->>'object' = $2",
        )
        .bind("https://remote.test/users/mallory/inbox")
        .bind(actor_uri)
        .fetch_optional(pool)
        .await
        .expect("read the queued Block");
        assert!(tell.is_some(), "a Block must be queued for the peer");

        // The existing post is gone from its URL and from the timeline.
        let (code, _) = get(&state, &status_path(&existing)).await;
        assert_eq!(code, StatusCode::NOT_FOUND);
        let (_, timeline) = get(&state, "/api/v1/timelines/public?local=false").await;
        assert!(!timeline_ids(&timeline).contains(&existing));

        // A new inbound Create from the same actor is acknowledged and dropped.
        let (code, _) = post_signed_inbox(
            &state,
            &private,
            &format!("{actor_uri}#main-key"),
            &create_note(actor_uri, "https://remote.test/notes/after", "spam after"),
        )
        .await;
        assert_eq!(code, StatusCode::ACCEPTED);
        assert!(
            statuses::by_uri(pool, "https://remote.test/notes/after")
                .await
                .expect("lookup")
                .is_none(),
            "a suspended actor's Create must not be stored"
        );
    })
    .await;
}

#[tokio::test]
async fn lifting_the_action_restores_the_account() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let staff = create_account(pool, "staff", true).await;
        let token = create_token(pool, &staff, &["read", "admin:read", "admin:write"]).await;
        let actor_uri = "https://remote.test/users/mallory";
        let account = seed_remote(pool, actor_uri, "mallory", None).await;
        let status = seed_remote_status(
            pool,
            &account,
            "https://remote.test/notes/again",
            "visible again",
        )
        .await;

        let (code, _) = send(
            &state,
            "PUT",
            &actor_path(actor_uri),
            Some(&token),
            Some(json!({ "action": "suspend" })),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED);
        let (_, hidden) = get(&state, "/api/v1/timelines/public?local=false").await;
        assert!(!timeline_ids(&hidden).contains(&status));

        let (code, body) = send(&state, "DELETE", &actor_path(actor_uri), Some(&token), None).await;
        assert_eq!(code, StatusCode::NO_CONTENT, "body: {body}");

        // Lifting is an Undo naming the same Block id, so the peer can match it.
        let undo: Option<String> = sqlx::query_scalar(
            "SELECT activity::text FROM federation_delivery \
              WHERE inbox_url = $1 AND activity->>'type' = 'Undo' \
              AND activity->'object'->>'type' = 'Block'",
        )
        .bind("https://remote.test/users/mallory/inbox")
        .fetch_optional(pool)
        .await
        .expect("read the queued Undo");
        assert!(undo.is_some(), "an Undo(Block) must be queued for the peer");

        let (_, restored) = get(&state, "/api/v1/timelines/public?local=false").await;
        assert!(
            timeline_ids(&restored).contains(&status),
            "lifting the action must put the post back: {restored}"
        );

        // The row is gone, so a second DELETE has nothing to lift.
        let (code, _) = send(&state, "DELETE", &actor_path(actor_uri), Some(&token), None).await;
        assert_eq!(code, StatusCode::NOT_FOUND);
    })
    .await;
}

#[tokio::test]
async fn an_expired_row_stops_applying_and_is_shown_as_expired() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let staff = create_account(pool, "staff", true).await;
        let token = create_token(pool, &staff, &["read", "admin:read", "admin:write"]).await;
        let actor_uri = "https://remote.test/users/mallory";
        let account = seed_remote(pool, actor_uri, "mallory", None).await;
        let status = seed_remote_status(
            pool,
            &account,
            "https://remote.test/notes/expired",
            "the post outlives the silence",
        )
        .await;

        let expires_at = Utc::now() - Duration::hours(1);
        let (code, body) = send(
            &state,
            "PUT",
            &actor_path(actor_uri),
            Some(&token),
            Some(json!({
                "action": "silence",
                "reason": "cooled off",
                "expires_at": expires_at.to_rfc3339(),
            })),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "body: {body}");
        assert_eq!(body["expired"], true);
        assert!(body["expires_at"].is_string());

        let (_, timeline) = get(&state, "/api/v1/timelines/public?local=false").await;
        assert!(
            timeline_ids(&timeline).contains(&status),
            "an expired row must not hide anything: {timeline}"
        );

        let (code, list) = send(
            &state,
            "GET",
            "/api/v1/admin/federation/remote-accounts",
            Some(&token),
            None,
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        let rows = list.as_array().expect("array");
        assert_eq!(rows.len(), 1, "the row is kept as the record: {list}");
        assert_eq!(rows[0]["expired"], true);
    })
    .await;
}

#[tokio::test]
async fn a_read_only_token_cannot_apply_an_action() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let staff = create_account(pool, "staff", true).await;
        let token = create_token(pool, &staff, &["read", "admin:read"]).await;
        let actor_uri = "https://remote.test/users/mallory";
        let _ = seed_remote(pool, actor_uri, "mallory", None).await;

        let (code, body) = send(
            &state,
            "PUT",
            &actor_path(actor_uri),
            Some(&token),
            Some(json!({ "action": "suspend" })),
        )
        .await;
        assert_eq!(
            code,
            StatusCode::FORBIDDEN,
            "a read-only token must not moderate: {body}"
        );

        let (code, _) = send(
            &state,
            "GET",
            "/api/v1/admin/federation/remote-accounts",
            Some(&token),
            None,
        )
        .await;
        assert_eq!(code, StatusCode::OK, "reading is what the token is for");
    })
    .await;
}
