#![allow(clippy::too_many_lines)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::Utc;
use http_body_util::BodyExt;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{EncodePublicKey as _, LineEnding};
use rsa::rand_core::OsRng;
use rsa::signature::{SignatureEncoding as _, Signer as _};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::net::TcpListener;
use tower::ServiceExt;

use nodus_server_api::{root_router, AppState, InstanceConfig};
use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount, RemoteAccount};
use nodus_server_store::moderation::{self, NewDomainBlock};
use nodus_server_store::statuses::{self, NewRemoteStatus};
use nodus_server_store::{apps, social, Store};

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

async fn create_account(pool: &PgPool, label: &str) -> (String, String) {
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
    (row.id, username)
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

async fn seed_remote_actor(
    pool: &PgPool,
    uri: &str,
    username: &str,
    domain: &str,
    public_key_pem: Option<&str>,
) -> accounts::AccountRow {
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
}

async fn send(state: &AppState, request: Request<Body>) -> (StatusCode, String) {
    let response = root_router(state.clone())
        .oneshot(request)
        .await
        .expect("router response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn generate_keypair() -> (RsaPrivateKey, String) {
    let private = RsaPrivateKey::new(&mut OsRng, 1024).expect("rsa key");
    let pem = RsaPublicKey::from(&private)
        .to_public_key_pem(LineEnding::LF)
        .expect("public key pem");
    (private, pem)
}

fn sign_headers(
    private: &RsaPrivateKey,
    key_id: &str,
    headers_list: &str,
    lines: &[String],
) -> String {
    let sig = SigningKey::<Sha256>::new(private.clone()).sign(lines.join("\n").as_bytes());
    format!(
        "keyId=\"{key_id}\",algorithm=\"rsa-sha256\",headers=\"{headers_list}\",signature=\"{}\"",
        BASE64.encode(sig.to_bytes())
    )
}

async fn post_signed_inbox(
    state: &AppState,
    private: &RsaPrivateKey,
    key_id: &str,
    activity: &Value,
) -> (StatusCode, String) {
    let body_bytes = serde_json::to_vec(activity).expect("json bytes");
    let digest = format!("SHA-256={}", BASE64.encode(Sha256::digest(&body_bytes)));
    let date = Utc::now().to_rfc2822();
    let sig = sign_headers(
        private,
        key_id,
        "(request-target) host date digest",
        &[
            "(request-target): post /inbox".to_owned(),
            "host: social.test".to_owned(),
            format!("date: {date}"),
            format!("digest: {digest}"),
        ],
    );
    let request = Request::builder()
        .method("POST")
        .uri("/inbox")
        .header("host", "social.test")
        .header("date", date)
        .header("digest", digest)
        .header("signature", sig)
        .body(Body::from(body_bytes))
        .expect("request");
    send(state, request).await
}

#[tokio::test]
async fn rejects_actor_spoofing_when_key_id_differs_from_activity_actor() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let (local_id, local_username) = create_account(pool, "victimlocal").await;

        let (mallory_key, mallory_pem) = generate_keypair();
        let (_victim_key, victim_pem) = generate_keypair();

        let mallory_uri = "https://evil.test/users/mallory";
        let victim_uri = "https://victim.test/users/alice";

        let _ = seed_remote_actor(
            pool,
            mallory_uri,
            "mallory",
            "evil.test",
            Some(&mallory_pem),
        )
        .await;
        let victim =
            seed_remote_actor(pool, victim_uri, "alice", "victim.test", Some(&victim_pem)).await;

        let victim_note_uri = "https://victim.test/notes/1";
        statuses::upsert_remote(
            pool,
            &NewRemoteStatus {
                id: &Id::new().to_string(),
                account_id: &victim.id,
                uri: victim_note_uri,
                content: "original",
                content_html: "<p>original</p>",
                spoiler_text: "",
                sensitive: false,
                visibility: "public",
                in_reply_to_id: None,
                in_reply_to_account_id: None,
                created_at: Utc::now(),
            },
        )
        .await
        .expect("seed victim status");

        // Mallory signs with mallory's key, claiming actor is victim.
        let follow = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://evil.test/follows/spoof",
            "type": "Follow",
            "actor": victim_uri,
            "object": format!("https://social.test/users/{local_username}"),
        });
        let (status, resp) = post_signed_inbox(
            &state,
            &mallory_key,
            &format!("{mallory_uri}#main-key"),
            &follow,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "spoofed Follow must be rejected: {resp}"
        );
        assert!(
            !social::relationship(pool, &victim.id, &local_id)
                .await
                .expect("check follow")
                .following,
            "victim must not follow local user via spoofed Follow"
        );

        let forged_create = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://evil.test/creates/spoof",
            "type": "Create",
            "actor": victim_uri,
            "object": {
                "id": "https://victim.test/notes/forged",
                "type": "Note",
                "attributedTo": victim_uri,
                "content": "<p>forged</p>",
                "published": "2026-01-01T00:00:00Z",
            }
        });
        let (status, resp) = post_signed_inbox(
            &state,
            &mallory_key,
            &format!("{mallory_uri}#main-key"),
            &forged_create,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "spoofed Create must be rejected: {resp}"
        );
        assert!(
            statuses::by_uri(pool, "https://victim.test/notes/forged")
                .await
                .expect("lookup")
                .is_none(),
            "forged note must not be stored"
        );

        let forged_delete = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://evil.test/deletes/spoof",
            "type": "Delete",
            "actor": victim_uri,
            "object": victim_note_uri,
        });
        let (status, resp) = post_signed_inbox(
            &state,
            &mallory_key,
            &format!("{mallory_uri}#main-key"),
            &forged_delete,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "spoofed Delete must be rejected: {resp}"
        );
        assert!(
            statuses::by_uri(pool, victim_note_uri)
                .await
                .expect("lookup")
                .is_some(),
            "victim note must not be deleted"
        );
    })
    .await;
}

#[tokio::test]
async fn rejects_cross_origin_create_and_cross_actor_delete() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let (mallory_key, mallory_pem) = generate_keypair();
        let (_alice_key, alice_pem) = generate_keypair();

        let mallory_uri = "https://evil.test/users/mallory";
        let alice_same_origin_uri = "https://evil.test/users/alice";
        let victim_uri = "https://victim.test/users/bob";

        let mallory = seed_remote_actor(
            pool,
            mallory_uri,
            "mallory",
            "evil.test",
            Some(&mallory_pem),
        )
        .await;
        let alice = seed_remote_actor(
            pool,
            alice_same_origin_uri,
            "alice",
            "evil.test",
            Some(&alice_pem),
        )
        .await;
        let victim =
            seed_remote_actor(pool, victim_uri, "bob", "victim.test", Some(&alice_pem)).await;

        let alice_note_uri = "https://evil.test/notes/alice-1";
        statuses::upsert_remote(
            pool,
            &NewRemoteStatus {
                id: &Id::new().to_string(),
                account_id: &alice.id,
                uri: alice_note_uri,
                content: "alice original",
                content_html: "<p>alice original</p>",
                spoiler_text: "",
                sensitive: false,
                visibility: "public",
                in_reply_to_id: None,
                in_reply_to_account_id: None,
                created_at: Utc::now(),
            },
        )
        .await
        .expect("seed alice note");

        let victim_note_uri = "https://victim.test/notes/bob-1";
        statuses::upsert_remote(
            pool,
            &NewRemoteStatus {
                id: &Id::new().to_string(),
                account_id: &victim.id,
                uri: victim_note_uri,
                content: "bob original",
                content_html: "<p>bob original</p>",
                spoiler_text: "",
                sensitive: false,
                visibility: "public",
                in_reply_to_id: None,
                in_reply_to_account_id: None,
                created_at: Utc::now(),
            },
        )
        .await
        .expect("seed victim note");

        // 1. Mallory tries to overwrite victim's status via Create with victim's note ID.
        let cross_origin_create = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://evil.test/creates/1",
            "type": "Create",
            "actor": mallory_uri,
            "object": {
                "id": victim_note_uri,
                "type": "Note",
                "attributedTo": mallory_uri,
                "content": "<p>overwritten by mallory</p>",
                "published": "2026-01-01T00:00:00Z",
            }
        });
        let (status, resp) = post_signed_inbox(
            &state,
            &mallory_key,
            &format!("{mallory_uri}#main-key"),
            &cross_origin_create,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "cross-origin note id in Create must be forbidden: {resp}"
        );
        let stored_bob = statuses::by_uri(pool, victim_note_uri)
            .await
            .expect("lookup")
            .expect("victim note still exists");
        assert_eq!(stored_bob.content, "bob original");

        // 2. Mallory creates a note with attributedTo pointing to Alice on same origin.
        let spoofed_attr_create = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://evil.test/creates/2",
            "type": "Create",
            "actor": mallory_uri,
            "object": {
                "id": "https://evil.test/notes/spoof-attr",
                "type": "Note",
                "attributedTo": alice_same_origin_uri,
                "content": "<p>impersonating alice</p>",
                "published": "2026-01-01T00:00:00Z",
            }
        });
        let (status, resp) = post_signed_inbox(
            &state,
            &mallory_key,
            &format!("{mallory_uri}#main-key"),
            &spoofed_attr_create,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "mismatched attributedTo must be forbidden: {resp}"
        );
        assert!(statuses::by_uri(pool, "https://evil.test/notes/spoof-attr")
            .await
            .expect("lookup")
            .is_none());

        // 3. Mallory sends Delete for victim's note on another origin.
        let cross_origin_delete = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://evil.test/deletes/1",
            "type": "Delete",
            "actor": mallory_uri,
            "object": victim_note_uri,
        });
        let (status, resp) = post_signed_inbox(
            &state,
            &mallory_key,
            &format!("{mallory_uri}#main-key"),
            &cross_origin_delete,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "cross-origin Delete must be forbidden: {resp}"
        );
        assert!(
            statuses::by_uri(pool, victim_note_uri)
                .await
                .expect("lookup")
                .is_some(),
            "victim note must remain"
        );

        // 4. Mallory sends Delete for Alice's note on the SAME origin (evil.test).
        let same_origin_cross_actor_delete = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://evil.test/deletes/2",
            "type": "Delete",
            "actor": mallory_uri,
            "object": alice_note_uri,
        });
        let _ = post_signed_inbox(
            &state,
            &mallory_key,
            &format!("{mallory_uri}#main-key"),
            &same_origin_cross_actor_delete,
        )
        .await;
        assert!(
            statuses::by_uri(pool, alice_note_uri)
                .await
                .expect("lookup")
                .is_some(),
            "mallory must not delete alice's status on the same domain"
        );

        // 5. Store-level delete_remote is scoped to account_id.
        assert!(
            !statuses::delete_remote(pool, alice_note_uri, &mallory.id)
                .await
                .expect("delete_remote"),
            "store delete_remote must not delete another account's status"
        );
        assert!(
            statuses::delete_remote(pool, alice_note_uri, &alice.id)
                .await
                .expect("delete_remote"),
            "store delete_remote must delete the owning account's status"
        );
        assert!(statuses::by_uri(pool, alice_note_uri)
            .await
            .expect("lookup")
            .is_none());

        // 6. Undo with mismatched inner actor must be forbidden.
        let mismatched_undo = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://evil.test/undos/1",
            "type": "Undo",
            "actor": mallory_uri,
            "object": {
                "id": "https://victim.test/follows/1",
                "type": "Follow",
                "actor": victim_uri,
                "object": "https://social.test/users/anyone",
            }
        });
        let (status, resp) = post_signed_inbox(
            &state,
            &mallory_key,
            &format!("{mallory_uri}#main-key"),
            &mismatched_undo,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "Undo with mismatched inner actor must be forbidden: {resp}"
        );
    })
    .await;
}

#[tokio::test]
async fn rejects_a_cross_actor_profile_update_or_actor_delete() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let (mallory_key, mallory_pem) = generate_keypair();
        let (_alice_key, alice_pem) = generate_keypair();
        let mallory_uri = "https://evil.test/users/mallory";
        let alice_uri = "https://evil.test/users/alice";
        let mallory = seed_remote_actor(
            pool,
            mallory_uri,
            "mallory",
            "evil.test",
            Some(&mallory_pem),
        )
        .await;
        let alice =
            seed_remote_actor(pool, alice_uri, "alice", "evil.test", Some(&alice_pem)).await;
        let alice_note_uri = "https://evil.test/notes/alice-2";
        statuses::upsert_remote(
            pool,
            &NewRemoteStatus {
                id: &Id::new().to_string(),
                account_id: &alice.id,
                uri: alice_note_uri,
                content: "alice original",
                content_html: "<p>alice original</p>",
                spoiler_text: "",
                sensitive: false,
                visibility: "public",
                in_reply_to_id: None,
                in_reply_to_account_id: None,
                created_at: Utc::now(),
            },
        )
        .await
        .expect("seed alice note");

        // Mallory edits Alice's profile on the same domain.
        let stolen_update = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://evil.test/updates/1",
            "type": "Update",
            "actor": mallory_uri,
            "object": {
                "id": alice_uri,
                "type": "Person",
                "preferredUsername": "alice",
                "name": "owned by mallory",
                "inbox": "https://evil.test/users/alice/inbox",
            }
        });
        let (status, resp) = post_signed_inbox(
            &state,
            &mallory_key,
            &format!("{mallory_uri}#main-key"),
            &stolen_update,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a cross-actor profile update must be forbidden: {resp}"
        );
        let stored = accounts::by_id(pool, &alice.id)
            .await
            .expect("lookup")
            .expect("alice still exists");
        assert_eq!(stored.display_name, "alice");

        // Mallory names Alice's actor document in a Delete.
        let actor_delete = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://evil.test/deletes/3",
            "type": "Delete",
            "actor": mallory_uri,
            "object": { "id": alice_uri, "type": "Person" },
        });
        let _ = post_signed_inbox(
            &state,
            &mallory_key,
            &format!("{mallory_uri}#main-key"),
            &actor_delete,
        )
        .await;
        assert!(
            statuses::by_uri(pool, alice_note_uri)
                .await
                .expect("lookup")
                .is_some(),
            "naming another actor's document must not tombstone their posts"
        );

        // Mallory deletes her own actor document, which is allowed.
        let own_delete = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://evil.test/deletes/4",
            "type": "Delete",
            "actor": mallory_uri,
            "object": { "id": mallory_uri, "type": "Person" },
        });
        let (status, resp) = post_signed_inbox(
            &state,
            &mallory_key,
            &format!("{mallory_uri}#main-key"),
            &own_delete,
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{resp}");
        assert_eq!(
            accounts::by_id(pool, &mallory.id)
                .await
                .expect("lookup")
                .expect("mallory is kept")
                .display_name,
            "mallory"
        );
    })
    .await;
}

#[tokio::test]
async fn requires_digest_date_and_all_required_signed_headers() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let (_local_id, local_username) = create_account(pool, "reqheaders").await;
        let (bob_key, bob_pem) = generate_keypair();
        let bob_uri = "https://remote.test/users/bob";
        seed_remote_actor(pool, bob_uri, "bob", "remote.test", Some(&bob_pem)).await;

        let activity = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://remote.test/follows/1",
            "type": "Follow",
            "actor": bob_uri,
            "object": format!("https://social.test/users/{local_username}"),
        });
        let body_bytes = serde_json::to_vec(&activity).expect("json bytes");
        let digest = format!("SHA-256={}", BASE64.encode(Sha256::digest(&body_bytes)));
        let date = Utc::now().to_rfc2822();

        // 1. Omit Digest header completely and omit digest from signed headers.
        let sig_no_digest = sign_headers(
            &bob_key,
            &format!("{bob_uri}#main-key"),
            "(request-target) host date",
            &[
                "(request-target): post /inbox".to_owned(),
                "host: social.test".to_owned(),
                format!("date: {date}"),
            ],
        );
        let (status, resp) = send(
            &state,
            Request::builder()
                .method("POST")
                .uri("/inbox")
                .header("host", "social.test")
                .header("date", &date)
                .header("signature", sig_no_digest)
                .body(Body::from(body_bytes.clone()))
                .expect("request"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "missing Digest header must be rejected: {resp}"
        );

        // 2. Include valid Date & Digest headers, but sign only "(request-target)".
        let sig_only_target = sign_headers(
            &bob_key,
            &format!("{bob_uri}#main-key"),
            "(request-target)",
            &["(request-target): post /inbox".to_owned()],
        );
        let (status, resp) = send(
            &state,
            Request::builder()
                .method("POST")
                .uri("/inbox")
                .header("host", "social.test")
                .header("date", &date)
                .header("digest", &digest)
                .header("signature", sig_only_target)
                .body(Body::from(body_bytes.clone()))
                .expect("request"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "signature covering only (request-target) must be rejected: {resp}"
        );

        // 3. Omit any single required header from signature.headers even when headers exist.
        for (headers_list, lines) in [
            (
                "host date digest",
                vec![
                    "host: social.test".to_owned(),
                    format!("date: {date}"),
                    format!("digest: {digest}"),
                ],
            ),
            (
                "(request-target) date digest",
                vec![
                    "(request-target): post /inbox".to_owned(),
                    format!("date: {date}"),
                    format!("digest: {digest}"),
                ],
            ),
            (
                "(request-target) host digest",
                vec![
                    "(request-target): post /inbox".to_owned(),
                    "host: social.test".to_owned(),
                    format!("digest: {digest}"),
                ],
            ),
            (
                "(request-target) host date",
                vec![
                    "(request-target): post /inbox".to_owned(),
                    "host: social.test".to_owned(),
                    format!("date: {date}"),
                ],
            ),
        ] {
            let sig = sign_headers(
                &bob_key,
                &format!("{bob_uri}#main-key"),
                headers_list,
                &lines,
            );
            let (status, resp) = send(
                &state,
                Request::builder()
                    .method("POST")
                    .uri("/inbox")
                    .header("host", "social.test")
                    .header("date", &date)
                    .header("digest", &digest)
                    .header("signature", sig)
                    .body(Body::from(body_bytes.clone()))
                    .expect("request"),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "headers=\"{headers_list}\" must be rejected: {resp}"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn verify_signature_blocks_domain_and_ssrf_before_fetching() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let (mallory_key, _mallory_pem) = generate_keypair();

        // 1. Blocked domain must return 403 before any remote actor fetch.
        moderation::create_block(
            pool,
            &NewDomainBlock {
                domain: "blocked.test",
                severity: "suspend",
                reject_media: true,
                reject_reports: true,
                obfuscate: false,
                public_comment: "blocked",
            },
        )
        .await
        .expect("block domain");

        let blocked_actor = "https://blocked.test/users/mallory";
        let blocked_activity = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://blocked.test/follows/1",
            "type": "Follow",
            "actor": blocked_actor,
            "object": "https://social.test/users/alice",
        });
        let (status, resp) = post_signed_inbox(
            &state,
            &mallory_key,
            &format!("{blocked_actor}#main-key"),
            &blocked_activity,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "blocked domain must be rejected with 403 before fetch: {resp}"
        );

        // 2. Loopback SSRF target must never receive a TCP connection.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_bg = Arc::clone(&hits);
        let server = tokio::spawn(async move {
            while let Ok((_stream, _)) = listener.accept().await {
                hits_bg.fetch_add(1, Ordering::SeqCst);
            }
        });

        for ssrf_actor in [
            format!("https://127.0.0.1:{port}/users/mallory"),
            format!("http://127.0.0.1:{port}/users/mallory"),
            format!("https://localhost:{port}/users/mallory"),
            "https://169.254.169.254/latest/meta-data".to_owned(),
            "https://10.0.0.1/users/mallory".to_owned(),
            "https://[::1]/users/mallory".to_owned(),
        ] {
            let activity = json!({
                "@context": "https://www.w3.org/ns/activitystreams",
                "id": "https://evil.test/follows/ssrf",
                "type": "Follow",
                "actor": ssrf_actor,
                "object": "https://social.test/users/alice",
            });
            let (status, resp) = post_signed_inbox(
                &state,
                &mallory_key,
                &format!("{ssrf_actor}#main-key"),
                &activity,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "SSRF actor {ssrf_actor} must be rejected: {resp}"
            );
        }

        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "verify_signature must not connect to loopback listener"
        );
        server.abort();
    })
    .await;
}

#[tokio::test]
async fn hydrate_endpoints_require_auth_and_block_ssrf_and_blocked_domains() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let (user_id, _) = create_account(pool, "hydrator").await;
        let token = create_token(pool, &user_id, &["read"]).await;

        // 1. Unauthenticated requests must be rejected with 401.
        for uri in [
            "/api/v1/hydrate/account?acct=alice@remote.test",
            "/api/v1/hydrate/status?url=https://remote.test/notes/1",
        ] {
            let (status, resp) = send(
                &state,
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "unauthenticated {uri} must return 401: {resp}"
            );
        }

        // 2. Blocked domain must be rejected with 403 before fetching.
        moderation::create_block(
            pool,
            &NewDomainBlock {
                domain: "blocked.test",
                severity: "suspend",
                reject_media: true,
                reject_reports: true,
                obfuscate: false,
                public_comment: "blocked",
            },
        )
        .await
        .expect("block domain");

        for uri in [
            "/api/v1/hydrate/account?acct=alice@blocked.test",
            "/api/v1/hydrate/status?url=https://blocked.test/notes/1",
        ] {
            let (status, resp) = send(
                &state,
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "blocked domain on {uri} must return 403: {resp}"
            );
        }

        // 3. Private/loopback/link-local SSRF targets must be rejected before connecting.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_bg = Arc::clone(&hits);
        let server = tokio::spawn(async move {
            while let Ok((_stream, _)) = listener.accept().await {
                hits_bg.fetch_add(1, Ordering::SeqCst);
            }
        });

        let bad_hydrate_uris = [
            "/api/v1/hydrate/account?acct=alice@127.0.0.1",
            "/api/v1/hydrate/account?acct=alice@169.254.169.254",
            "/api/v1/hydrate/account?acct=alice@10.0.0.1",
            "/api/v1/hydrate/account?acct=alice@localhost",
            "/api/v1/hydrate/account?acct=alice@metadata.google.internal",
            &format!("/api/v1/hydrate/status?url=https://127.0.0.1:{port}/note"),
            &format!("/api/v1/hydrate/status?url=http://127.0.0.1:{port}/note"),
            "/api/v1/hydrate/status?url=https://169.254.169.254/latest/meta-data",
            "/api/v1/hydrate/status?url=https://10.0.0.1/note",
            "/api/v1/hydrate/status?url=https://192.168.1.1/note",
            "/api/v1/hydrate/status?url=https://[::1]/note",
            "/api/v1/hydrate/status?url=https://localhost/note",
            "/api/v1/hydrate/status?url=https://metadata.google.internal/computeMetadata/v1/",
        ];
        for uri in bad_hydrate_uris {
            let (status, resp) = send(
                &state,
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "SSRF target {uri} must return 422: {resp}"
            );
        }

        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "hydrate endpoints must not connect to loopback listener"
        );
        server.abort();
    })
    .await;
}
