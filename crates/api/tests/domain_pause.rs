//! A domain pause is the middle of the moderation scale: stronger than ignoring a bad week,
//! weaker than a permanent block. Delivery stops, ingestion continues hidden, media is not
//! pulled, and the pause expires or is lifted without the peer ever being told.

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

use nodus_server_api::activitypub::apply_actor_refresh;
use nodus_server_api::{root_router, AppState, InstanceConfig};
use nodus_server_core::Id;
use nodus_server_sdk::activitypub::Actor;
use nodus_server_store::accounts::{self, NewAccount, RemoteAccount};
use nodus_server_store::statuses::{self, NewRemoteStatus};
use nodus_server_store::remote_moderation::NewRemoteModeration;
use nodus_server_store::{apps, delivery, remote_moderation, Store};

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
    seed_remote_on(pool, "remote.test", uri, username, public_key_pem).await
}

async fn seed_remote_on(
    pool: &PgPool,
    domain: &str,
    uri: &str,
    username: &str,
    public_key_pem: Option<&str>,
) -> String {
    accounts::upsert_remote(
        pool,
        &RemoteAccount {
            uri,
            username,
            domain,
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
    statuses::upsert_remote(
        pool,
        &NewRemoteStatus {
            id: uri,
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
    uri.to_owned()
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

fn encode_path(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn status_path(id: &str) -> String {
    format!("/api/v1/statuses/{}", encode_path(id))
}

fn refresh_path(actor_uri: &str) -> String {
    format!(
        "/api/v1/admin/federation/actors/{}/refresh",
        encode_path(actor_uri)
    )
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
            "to": ["https://www.w3.org/ns/activitystreams#Public"],
            "cc": [],
            "published": "2026-01-01T00:00:00Z",
        }
    })
}

#[tokio::test]
async fn a_pause_stops_delivery_while_ingestion_continues_hidden() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let staff = create_account(pool, "staff", true).await;
        let token = create_token(pool, &staff, &["read", "admin:read", "admin:write"]).await;
        let (remote_key, remote_pem) = keypair();
        let actor_uri = "https://remote.test/users/mallory";
        seed_remote(pool, actor_uri, "mallory", Some(&remote_pem)).await;

        let (code, body) = send(
            &state,
            "POST",
            "/api/v1/admin/federation/domain-pauses",
            Some(&token),
            Some(json!({ "domain": "remote.test", "reason": "having a bad week" })),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "body: {body}");
        assert_eq!(body["domain"], "remote.test");
        assert_eq!(body["reason"], "having a bad week");
        assert_eq!(body["expired"], false);

        // New deliveries to the paused host are not queued.
        let queued = delivery::enqueue(
            pool,
            &staff,
            &json!({ "id": "https://social.test/activities/paused", "type": "Create" }),
            &["https://remote.test/inbox".to_owned()],
        )
        .await
        .expect("enqueue");
        assert_eq!(queued, 0, "a pause must stop delivery");

        // Ingestion still accepts the Create; only the public view hides it.
        let note_uri = "https://remote.test/notes/during-pause";
        let (code, body) = post_signed_inbox(
            &state,
            &remote_key,
            &format!("{actor_uri}#main-key"),
            &create_note(actor_uri, note_uri, "still here"),
        )
        .await;
        assert!(
            code.is_success(),
            "ingestion must continue during a pause: {code} {body}"
        );
        let stored = statuses::by_id(pool, &{
            let (id,): (String,) = sqlx::query_as("SELECT id FROM status WHERE uri = $1")
                .bind(note_uri)
                .fetch_one(pool)
                .await
                .expect("the paused domain's activity is still stored");
            id
        })
        .await
        .expect("query status")
        .expect("the paused domain's activity is still stored");
        assert_eq!(stored.content, "still here");
        let stored_id = stored.id.clone();

        let (_, timeline) = get(&state, "/api/v1/timelines/public?local=false").await;
        assert!(
            !timeline_ids(&timeline).contains(&stored_id),
            "a paused domain's status must leave the public timeline: {timeline}"
        );

        // The direct URL survives, exactly as remote-account silence keeps `by_id`.
        let (code, body) = get(&state, &status_path(&stored_id)).await;
        assert_eq!(code, StatusCode::OK, "body: {body}");
        assert_eq!(body["content"], "<p>still here</p>");
    })
    .await;
}

#[tokio::test]
async fn an_expired_pause_stops_applying_at_read_time_but_stays_listed() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let staff = create_account(pool, "staff", true).await;
        let token = create_token(pool, &staff, &["read", "admin:read", "admin:write"]).await;
        let actor_uri = "https://remote.test/users/expired";
        let account = seed_remote(pool, actor_uri, "expired", None).await;
        let status = seed_remote_status(
            pool,
            &account,
            "https://remote.test/notes/after-expiry",
            "visible again",
        )
        .await;

        let past = (Utc::now() - Duration::hours(1)).to_rfc3339();
        let (code, body) = send(
            &state,
            "POST",
            "/api/v1/admin/federation/domain-pauses",
            Some(&token),
            Some(json!({
                "domain": "remote.test",
                "reason": "temporary",
                "expires_at": past,
            })),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "body: {body}");
        assert_eq!(body["expired"], true);

        let (code, body) = send(
            &state,
            "GET",
            "/api/v1/admin/federation/domain-pauses",
            Some(&token),
            None,
        )
        .await;
        assert_eq!(code, StatusCode::OK, "body: {body}");
        let listed = body
            .as_array()
            .expect("array")
            .iter()
            .find(|row| row["domain"] == "remote.test")
            .expect("an expired pause is still listed");
        assert_eq!(listed["expired"], true);
        assert_eq!(listed["reason"], "temporary");

        // The pause stopped applying the moment it expired.
        let (_, timeline) = get(&state, "/api/v1/timelines/public?local=false").await;
        assert!(timeline_ids(&timeline).contains(&status));
        let queued = delivery::enqueue(
            pool,
            &staff,
            &json!({ "id": "https://social.test/activities/expired", "type": "Create" }),
            &["https://remote.test/inbox".to_owned()],
        )
        .await
        .expect("enqueue");
        assert_eq!(queued, 1, "an expired pause must not stop delivery");
    })
    .await;
}

#[tokio::test]
async fn lifting_a_pause_restores_delivery() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let staff = create_account(pool, "staff", true).await;
        let token = create_token(pool, &staff, &["read", "admin:read", "admin:write"]).await;
        seed_remote(pool, "https://remote.test/users/lift", "lift", None).await;
        let activity = json!({ "id": "https://social.test/activities/lift", "type": "Create" });
        let inboxes = ["https://remote.test/inbox".to_owned()];

        // Queued before the pause, so lifting has an already-owed row to release.
        assert_eq!(
            delivery::enqueue(pool, &staff, &activity, &inboxes)
                .await
                .expect("enqueue"),
            1
        );

        let (code, body) = send(
            &state,
            "POST",
            "/api/v1/admin/federation/domain-pauses",
            Some(&token),
            Some(json!({ "domain": "remote.test", "reason": "pause" })),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "body: {body}");

        let due = delivery::due(pool, 10).await.expect("due");
        assert!(
            due.iter()
                .all(|row| row.inbox_url != "https://remote.test/inbox"),
            "a queued delivery must not be sent while paused"
        );

        let (code, body) = send(
            &state,
            "DELETE",
            "/api/v1/admin/federation/domain-pauses/remote.test",
            Some(&token),
            None,
        )
        .await;
        assert_eq!(code, StatusCode::NO_CONTENT, "body: {body}");

        let due = delivery::due(pool, 10).await.expect("due");
        assert!(
            due.iter()
                .any(|row| row.inbox_url == "https://remote.test/inbox"),
            "lifting the pause must release the owed delivery"
        );
    })
    .await;
}

#[tokio::test]
async fn a_paused_domains_status_is_still_readable_by_id() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let staff = create_account(pool, "staff", true).await;
        let token = create_token(pool, &staff, &["read", "admin:read", "admin:write"]).await;
        let account =
            seed_remote(pool, "https://remote.test/users/readable", "readable", None).await;
        let status = seed_remote_status(
            pool,
            &account,
            "https://remote.test/notes/readable",
            "open the report",
        )
        .await;

        let (code, body) = send(
            &state,
            "POST",
            "/api/v1/admin/federation/domain-pauses",
            Some(&token),
            Some(json!({ "domain": "remote.test" })),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "body: {body}");

        let (code, body) = get(&state, &status_path(&status)).await;
        assert_eq!(code, StatusCode::OK, "body: {body}");
        assert_eq!(body["id"], status);

        // A moderator can change the reason and expiry in place.
        let (code, body) = send(
            &state,
            "PUT",
            "/api/v1/admin/federation/domain-pauses/remote.test",
            Some(&token),
            Some(json!({ "reason": "still paused", "expires_at": null })),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "body: {body}");
        assert_eq!(body["reason"], "still paused");
    })
    .await;
}

#[tokio::test]
async fn refresh_updates_a_changed_display_name_and_reports_the_field() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let actor_uri = "https://remote.test/users/refreshable";
        seed_remote(pool, actor_uri, "refreshable", None).await;
        let stored = accounts::by_uri(pool, actor_uri)
            .await
            .expect("query actor")
            .expect("seeded actor");

        let document = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": actor_uri,
            "type": "Person",
            "preferredUsername": "refreshable",
            "name": "A New Name",
            "movedTo": "https://remote.test/users/the-new-home",
        });
        let actor = Actor::from_json(&document).expect("parse actor document");
        let (changed, updated) = apply_actor_refresh(&state, &stored, &actor)
            .await
            .expect("apply refresh");

        assert!(
            changed.contains(&"display_name".to_owned()),
            "the changed field must be reported: {changed:?}"
        );
        assert!(
            changed.contains(&"moved_to".to_owned()),
            "a changed move target must be reported: {changed:?}"
        );
        assert_eq!(updated.display_name, "A New Name");
        assert_eq!(
            updated.moved_to.as_deref(),
            Some("https://remote.test/users/the-new-home")
        );

        let reloaded = accounts::by_uri(pool, actor_uri)
            .await
            .expect("query actor")
            .expect("actor");
        assert_eq!(reloaded.display_name, "A New Name");
    })
    .await;
}

#[tokio::test]
async fn an_unreachable_peer_answers_502_with_the_error() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let staff = create_account(pool, "staff", true).await;
        let token = create_token(pool, &staff, &["read", "admin:read", "admin:write"]).await;
        let actor_uri = "https://unreachable.invalid/users/ghost";
        seed_remote(pool, actor_uri, "ghost", None).await;

        let (code, body) = send(&state, "POST", &refresh_path(actor_uri), Some(&token), None).await;
        assert_eq!(
            code,
            StatusCode::BAD_GATEWAY,
            "an unreachable peer is a gateway problem, not a panic: {body}"
        );
        let message = body["error"].as_str().unwrap_or_default();
        assert!(
            message.contains("could not fetch the actor"),
            "the body must carry the fetch error: {body}"
        );
    })
    .await;
}

/// `/timelines/public` with no `local` parameter is the federated view, so the
/// moderation predicates that used to be reachable only with `?local=false` are
/// the page's only guards: a paused host and a silenced account must stay out of
/// a request that names neither.
#[tokio::test]
async fn the_default_public_page_is_federated_and_still_hides_paused_and_silenced() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let staff = create_account(pool, "staff", true).await;
        let token = create_token(pool, &staff, &["read", "admin:read", "admin:write"]).await;

        let open_actor = "https://open.test/users/ok";
        let open = seed_remote_on(pool, "open.test", open_actor, "ok", None).await;
        let open_status =
            seed_remote_status(pool, &open, "https://open.test/notes/ok", "open").await;

        let paused_actor = "https://paused.test/users/paused";
        let paused = seed_remote_on(pool, "paused.test", paused_actor, "paused", None).await;
        let paused_status =
            seed_remote_status(pool, &paused, "https://paused.test/notes/one", "paused").await;

        let silenced_actor = "https://quiet.test/users/eve";
        let silenced = seed_remote_on(pool, "quiet.test", silenced_actor, "eve", None).await;
        let silenced_status =
            seed_remote_status(pool, &silenced, "https://quiet.test/notes/one", "quiet").await;

        let (code, body) = send(
            &state,
            "POST",
            "/api/v1/admin/federation/domain-pauses",
            Some(&token),
            Some(json!({ "domain": "paused.test", "reason": "test" })),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "body: {body}");
        remote_moderation::upsert(
            pool,
            &NewRemoteModeration {
                actor_uri: silenced_actor,
                action: remote_moderation::SILENCE,
                reason: Some("test"),
                expires_at: None,
                created_by: Some(&staff),
            },
        )
        .await
        .expect("silence actor");

        let (code, timeline) = get(&state, "/api/v1/timelines/public").await;
        assert_eq!(code, StatusCode::OK, "body: {timeline}");
        let ids = timeline_ids(&timeline);
        assert!(
            ids.contains(&open_status),
            "the default page must carry a remote post: {timeline}"
        );
        assert!(
            !ids.contains(&paused_status),
            "a paused domain must not reach the default page: {timeline}"
        );
        assert!(
            !ids.contains(&silenced_status),
            "a silenced account must not reach the default page: {timeline}"
        );
    })
    .await;
}
