//! Reporting a remote account must reach the instance that hosts it.
//!
//! A local report ends in a local decision; a forwarded one is a signed `Flag` naming the
//! account and its posts, carrying the rule text and a moderator's note, and never the
//! person who pressed "report". These tests hold the payload to that promise: the peer has
//! to be able to parse it, and the reporter must not be findable in it.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use rsa::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _, LineEnding};
use rsa::rand_core::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

use nodus_server_api::{root_router, AppState, InstanceConfig};
use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount, RemoteAccount};
use nodus_server_store::moderation::{self, NewDomainBlock, NewReport};
use nodus_server_store::statuses::{self, NewRemoteStatus};
use nodus_server_store::{apps, delivery, forwarded, pauses, rules as store_rules, Store};

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

fn keypair() -> (RsaPrivateKey, String, String) {
    let private = RsaPrivateKey::new(&mut OsRng, 1024).expect("rsa key");
    let public = RsaPublicKey::from(&private)
        .to_public_key_pem(LineEnding::LF)
        .expect("public key pem");
    let secret = private
        .to_pkcs8_pem(LineEnding::LF)
        .expect("private key pem")
        .to_string();
    (private, public, secret)
}

/// A local account, optionally made staff, with an actor URI and a signing key so it can
/// act as the moderator that signs the forward.
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
    let (_, public, secret) = keypair();
    let uri = format!("https://social.test/users/{username}");
    accounts::set_actor_identity(
        pool,
        &row.id,
        &uri,
        &public,
        &secret,
        &format!("{uri}/inbox"),
        None,
    )
    .await
    .expect("give the account an actor identity");
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

async fn seed_remote(pool: &PgPool, uri: &str, username: &str) -> String {
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
            public_key_pem: None,
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

fn post_forward_path(id: &str) -> String {
    format!("/api/v1/admin/reports/{id}/forward")
}

/// Counts the queue rows a forward created and returns the parsed activity.
async fn queued_flags(pool: &PgPool) -> Vec<Value> {
    sqlx::query_scalar("SELECT activity FROM federation_delivery ORDER BY created_at, id")
        .fetch_all(pool)
        .await
        .expect("read queued activities")
}

async fn report(
    pool: &PgPool,
    reporter: Option<&str>,
    target: &str,
    statuses: &[String],
    comment: &str,
    rule_ids: &[String],
) -> String {
    moderation::create_report(
        pool,
        &NewReport {
            account_id: reporter,
            target_account_id: target,
            status_ids: statuses,
            category: "spam",
            comment,
            rule_ids,
            activity_uri: None,
        },
    )
    .await
    .expect("create report")
    .id
}

/// A staff report about a remote account goes out by itself: object names the account and
/// the reported post, and the activity is a `Flag` addressed to the peer.
#[tokio::test]
async fn staff_report_of_a_remote_account_queues_one_flag() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let moderator = create_account(pool, "mod", true).await;
        let token = create_token(pool, &moderator, &["read", "admin:read", "admin:write"]).await;
        let target = seed_remote(pool, "https://remote.test/users/mallory", "mallory").await;
        let post =
            seed_remote_status(pool, &target, "https://remote.test/notes/1", "buy my thing").await;

        let (status, body) = send(
            &state,
            "POST",
            "/api/v1/reports",
            Some(&token),
            Some(json!({
                "account_id": target,
                "status_ids": post,
                "category": "spam",
                "comment": "this is spam",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "report failed: {body}");

        let flags = queued_flags(pool).await;
        assert_eq!(flags.len(), 1, "one report, one Flag: {flags:?}");
        let flag = &flags[0];
        assert_eq!(flag["type"], "Flag");
        let object = flag["object"].as_array().expect("object is an array");
        assert_eq!(object[0], "https://remote.test/users/mallory");
        assert!(
            object
                .iter()
                .any(|item| item == "https://remote.test/notes/1"),
            "the reported post travels with the account: {object:?}"
        );
        let moderator_name = accounts::by_id(pool, &moderator)
            .await
            .expect("read the moderator")
            .expect("moderator exists")
            .username;
        assert!(
            flag["actor"]
                .as_str()
                .unwrap_or_default()
                .contains(&moderator_name),
            "signed and named by the moderator who filed it: {}",
            flag["actor"]
        );
        assert_eq!(flag["to"][0], "https://remote.test/users/mallory");
    })
    .await;
}

/// Forwarding twice is one delivery. The second answer is the first state, not a new Flag.
#[tokio::test]
async fn forwarding_twice_queues_once_and_replays_the_state() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let moderator = create_account(pool, "mod", true).await;
        let token = create_token(pool, &moderator, &["read", "admin:read", "admin:write"]).await;
        let reporter = create_account(pool, "reporter", false).await;
        let target = seed_remote(pool, "https://remote.test/users/mallory", "mallory").await;
        let id = report(pool, Some(&reporter), &target, &[], "spam", &[]).await;

        let (first, first_body) = send(
            &state,
            "POST",
            &post_forward_path(&id),
            Some(&token),
            Some(json!({ "note": "please review" })),
        )
        .await;
        assert_eq!(first, StatusCode::ACCEPTED, "first forward: {first_body}");
        assert_eq!(first_body["state"], "pending");

        let (second, second_body) = send(
            &state,
            "POST",
            &post_forward_path(&id),
            Some(&token),
            Some(json!({ "note": "again" })),
        )
        .await;
        assert_eq!(second, StatusCode::OK, "replay: {second_body}");
        assert_eq!(second_body["id"], first_body["id"]);
        assert_eq!(second_body["state"], first_body["state"]);
        assert_eq!(queued_flags(pool).await.len(), 1, "one Flag, not two");
        assert_eq!(
            forwarded::list(pool, None, None, 50, 0)
                .await
                .unwrap()
                .len(),
            1
        );
    })
    .await;
}

/// A local account is moderated here. Saying so is the whole answer.
#[tokio::test]
async fn a_local_account_cannot_be_forwarded() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let moderator = create_account(pool, "mod", true).await;
        let token = create_token(pool, &moderator, &["read", "admin:read", "admin:write"]).await;
        let local = create_account(pool, "local", false).await;
        let id = report(pool, Some(&moderator), &local, &[], "rude", &[]).await;

        let (status, body) = send(
            &state,
            "POST",
            &post_forward_path(&id),
            Some(&token),
            Some(json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body["error"].as_str().unwrap_or_default().contains("local"),
            "refusal names the reason: {body}"
        );
        assert!(queued_flags(pool).await.is_empty(), "nothing was queued");
    })
    .await;
}

/// A pause stops delivery; a block is final. The block is checked first, so a blocked
/// domain answers "blocked" even while a pause is also in force.
#[tokio::test]
async fn a_paused_or_blocked_domain_is_refused_with_its_reason() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let moderator = create_account(pool, "mod", true).await;
        let token = create_token(pool, &moderator, &["read", "admin:read", "admin:write"]).await;
        let target = seed_remote(pool, "https://remote.test/users/mallory", "mallory").await;
        let id = report(pool, Some(&moderator), &target, &[], "spam", &[]).await;

        pauses::upsert(
            pool,
            &pauses::NewDomainPause {
                domain: "remote.test",
                reason: "under review",
                expires_at: None,
                created_by: None,
            },
        )
        .await
        .expect("pause the domain");

        let (status, body) = send(
            &state,
            "POST",
            &post_forward_path(&id),
            Some(&token),
            Some(json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("paused"),
            "refusal names the pause: {body}"
        );

        moderation::create_block(
            pool,
            &NewDomainBlock {
                domain: "remote.test",
                severity: "suspend",
                reject_media: true,
                reject_reports: true,
                obfuscate: false,
                public_comment: "blocked",
            },
        )
        .await
        .expect("block the domain");

        let (status, body) = send(
            &state,
            "POST",
            &post_forward_path(&id),
            Some(&token),
            Some(json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("blocked"),
            "a block outranks the pause: {body}"
        );
        assert!(
            queued_flags(pool).await.is_empty(),
            "a refused forward queues nothing"
        );
    })
    .await;
}

/// The peer reads the rule text and the moderator's note, and cannot find the reporter.
#[tokio::test]
async fn forwarded_content_carries_rules_but_not_the_reporter() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let moderator = create_account(pool, "mod", true).await;
        let token = create_token(pool, &moderator, &["read", "admin:read", "admin:write"]).await;
        let reporter = create_account(pool, "reporter", false).await;
        let target = seed_remote(pool, "https://remote.test/users/mallory", "mallory").await;
        let rule = store_rules::create(pool, "No harassment of other members", None)
            .await
            .expect("create rule");
        let id = report(
            pool,
            Some(&reporter),
            &target,
            &[],
            "they keep at it",
            std::slice::from_ref(&rule.id),
        )
        .await;

        let (status, body) = send(
            &state,
            "POST",
            &post_forward_path(&id),
            Some(&token),
            Some(json!({ "note": "we warned them last week" })),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");

        let flags = queued_flags(pool).await;
        let content = flags[0]["content"].as_str().expect("content is text");
        assert!(content.contains("they keep at it"), "{content}");
        assert!(
            content.contains("No harassment of other members"),
            "{content}"
        );
        assert!(content.contains("we warned them last week"), "{content}");

        let reporter_row = accounts::by_id(pool, &reporter)
            .await
            .expect("read the reporter")
            .expect("reporter exists");
        let raw = flags[0].to_string();
        assert!(
            !raw.contains(&reporter_row.username),
            "the reporter's handle must not travel: {raw}"
        );
        assert!(
            !raw.contains(&reporter),
            "the reporter's id must not travel: {raw}"
        );
        assert!(
            !raw.contains(&reporter_row.uri.unwrap_or_default()),
            "the reporter's actor must not travel: {raw}"
        );
    })
    .await;
}

/// A 4xx is an answer, not a temporary problem: the row is closed and nothing retries.
#[tokio::test]
async fn a_refusing_peer_marks_the_forward_gave_up() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let moderator = create_account(pool, "mod", true).await;
        let token = create_token(pool, &moderator, &["read", "admin:read", "admin:write"]).await;
        let reporter = create_account(pool, "reporter", false).await;
        let target = seed_remote(pool, "https://remote.test/users/mallory", "mallory").await;
        let id = report(pool, Some(&reporter), &target, &[], "spam", &[]).await;

        let (status, body) = send(
            &state,
            "POST",
            &post_forward_path(&id),
            Some(&token),
            Some(json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");

        let delivery_id: String = sqlx::query_scalar("SELECT id FROM federation_delivery LIMIT 1")
            .fetch_one(pool)
            .await
            .expect("queued delivery");
        delivery::failed(pool, &delivery_id, 1, Some(400), "bad request", false)
            .await
            .expect("record the refusal");

        let row = forwarded::by_report(pool, &id)
            .await
            .expect("read the forward")
            .expect("forward exists");
        assert_eq!(row.state, "gave_up");
        assert_eq!(row.attempts, 1);
        assert!(row.last_error.unwrap_or_default().contains("bad request"));
        assert!(
            delivery::due(pool, 10)
                .await
                .expect("due deliveries")
                .is_empty(),
            "a give-up is not due again"
        );
    })
    .await;
}
