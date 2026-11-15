use std::path::Path;

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
use tower::ServiceExt;

use nodus_auth::domain::{opaque_token, token_hash};
use nodus_auth::store::{AuthStore as _, PgAuthStore};
use nodus_server_api::{root_router, AppState, InstanceConfig};
use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount, RemoteAccount};
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

async fn create_token(pool: &PgPool, account_id: &str) -> String {
    let app_id = Id::new().to_string();
    let client_id = format!("pgtest-client-{app_id}");
    apps::register(
        pool,
        &app_id,
        &client_id,
        "unused",
        "pgtest",
        None,
        &["urn:ietf:wg:oauth:2.0:oob".to_owned()],
        &["read".to_owned(), "write".to_owned()],
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
    .bind(&["read".to_owned(), "write".to_owned()][..])
    .execute(pool)
    .await
    .expect("insert oauth token");

    token
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

#[test]
fn workspace_dependencies_resolve_and_api_has_no_raw_sql() {
    let api_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root_dir = api_dir.join("../..");
    let root_toml = std::fs::read_to_string(root_dir.join("Cargo.toml")).expect("root Cargo.toml");

    // 1. Every path dependency in [workspace.dependencies] must exist on disk, and nodus-auth
    //    must be declared there.
    let mut in_workspace_deps = false;
    let mut has_nodus_auth = false;
    for line in root_toml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_workspace_deps = trimmed == "[workspace.dependencies]";
            continue;
        }
        if !in_workspace_deps || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("nodus-auth ") || trimmed.starts_with("nodus-auth=") {
            has_nodus_auth = true;
        }
        if let Some(after_path) = trimmed.split("path = \"").nth(1) {
            if let Some(rel_path) = after_path.split('"').next() {
                let resolved = root_dir.join(rel_path);
                assert!(
                    resolved.exists(),
                    "workspace dependency path does not exist: {rel_path}"
                );
            }
        }
    }
    assert!(
        has_nodus_auth,
        "Cargo.toml [workspace.dependencies] must declare nodus-auth"
    );

    // 2. nodus-server-api must depend on nodus-server-federation and use workspace nodus-auth.
    let api_toml = std::fs::read_to_string(api_dir.join("Cargo.toml")).expect("api Cargo.toml");
    assert!(
        api_toml.contains("nodus-server-federation"),
        "crates/api/Cargo.toml must depend on nodus-server-federation"
    );
    assert!(
        api_toml.contains("nodus-auth = { workspace = true }"),
        "crates/api/Cargo.toml must use nodus-auth = {{ workspace = true }}"
    );

    // 3. The API crate must never issue raw SQL queries against store tables.
    for entry in std::fs::read_dir(api_dir.join("src")).expect("read api/src") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read api source");
        assert!(
            !source.contains("sqlx::query"),
            "API source {} contains raw sqlx::query",
            path.display()
        );
    }
}

async fn post_inbox(
    state: &AppState,
    date: Option<&str>,
    digest: Option<&str>,
    signature: &str,
    body: Vec<u8>,
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/inbox")
        .header("host", "social.test")
        .header("signature", signature);
    if let Some(date) = date {
        builder = builder.header("date", date);
    }
    if let Some(digest) = digest {
        builder = builder.header("digest", digest);
    }
    send(state, builder.body(Body::from(body)).expect("request")).await
}

#[tokio::test]
async fn inbox_signature_verification_uses_federation_policy() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let (_local_id, local_username) = create_account(pool, "aplocal", false).await;

        let private = RsaPrivateKey::new(&mut OsRng, 1024).expect("rsa key");
        let pem = RsaPublicKey::from(&private)
            .to_public_key_pem(LineEnding::LF)
            .expect("public key pem");

        let actor_uri = "https://remote.test/users/bob";
        accounts::upsert_remote(
            pool,
            &RemoteAccount {
                uri: actor_uri,
                username: "bob",
                domain: "remote.test",
                display_name: "Bob",
                note: "",
                avatar: None,
                inbox_url: Some("https://remote.test/users/bob/inbox"),
                shared_inbox_url: None,
                public_key_pem: Some(&pem),
                locked: false,
                bot: false,
            },
        )
        .await
        .expect("upsert remote actor");

        let activity = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://remote.test/follows/1",
            "type": "Follow",
            "actor": actor_uri,
            "object": format!("https://social.test/users/{local_username}"),
        });
        let body_bytes = serde_json::to_vec(&activity).expect("json bytes");
        let digest = format!("SHA-256={}", BASE64.encode(Sha256::digest(&body_bytes)));
        let date = Utc::now().to_rfc2822();

        let sign = |headers_list: &str, lines: &[String]| {
            let sig = SigningKey::<Sha256>::new(private.clone()).sign(lines.join("\n").as_bytes());
            format!(
                "keyId=\"{actor_uri}#main-key\",algorithm=\"rsa-sha256\",headers=\"{headers_list}\",signature=\"{}\"",
                BASE64.encode(sig.to_bytes())
            )
        };

        let valid_sig = sign(
            "(request-target) host date digest",
            &[
                "(request-target): post /inbox".to_owned(),
                "host: social.test".to_owned(),
                format!("date: {date}"),
                format!("digest: {digest}"),
            ],
        );
        let (status, resp) = post_inbox(
            &state,
            Some(&date),
            Some(&digest),
            &valid_sig,
            body_bytes.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "valid inbox post failed: {resp}");

        let no_date_sig = sign(
            "(request-target) host digest",
            &[
                "(request-target): post /inbox".to_owned(),
                "host: social.test".to_owned(),
                format!("digest: {digest}"),
            ],
        );
        let (status, resp) =
            post_inbox(&state, None, Some(&digest), &no_date_sig, body_bytes.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(resp.contains("date is missing or outside the accepted window"));

        let (status, resp) =
            post_inbox(&state, Some(&date), None, &valid_sig, body_bytes.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(resp.contains("no digest"));

        let (status, resp) = post_inbox(
            &state,
            Some(&date),
            Some(&digest),
            &valid_sig,
            br#"{"type":"Follow"}"#.to_vec(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(resp.contains("digest does not match"));
    })
    .await;
}

#[tokio::test]
async fn miauth_flow_persists_session_issues_token_and_authenticates() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let (account_id, username) = create_account(pool, "miauth", false).await;

        let auth_store = PgAuthStore::new(pool.clone());
        let session_secret = opaque_token();
        auth_store
            .create_session(
                &token_hash(&session_secret),
                &account_id,
                Utc::now() + chrono::Duration::hours(1),
            )
            .await
            .expect("create browser session");
        let cookie_header = format!("{}={session_secret}", nodus_auth::SESSION_COOKIE);
        let miauth_session = Id::new().to_string();

        // Unknown session returns 404 on approve and ok=false on check.
        let (status, _) = send(
            &state,
            Request::builder()
                .method("POST")
                .uri("/miauth/nonexistent-session")
                .header(header::COOKIE, &cookie_header)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("name=Missing"))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, body) = send(
            &state,
            Request::builder()
                .method("POST")
                .uri("/api/miauth/nonexistent-session/check")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let parsed: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(parsed["ok"], false);

        // Start session.
        let (status, html) = send(
            &state,
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/miauth/{miauth_session}?name=MyClient&permission=read,write"
                ))
                .header(header::COOKIE, &cookie_header)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("Authorize MyClient"), "html was {html}");

        // Approve session.
        let (status, html) = send(
            &state,
            Request::builder()
                .method("POST")
                .uri(format!("/miauth/{miauth_session}"))
                .header(header::COOKIE, &cookie_header)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("name=MyClient"))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("Approved MyClient"), "html was {html}");

        // Check session yields bearer token and user.
        let (status, body) = send(
            &state,
            Request::builder()
                .method("POST")
                .uri(format!("/api/miauth/{miauth_session}/check"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let parsed: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["user"]["username"], username);
        let token = parsed["token"].as_str().expect("miauth token");

        // Returned token authenticates against the API.
        let (status, body) = send(
            &state,
            Request::builder()
                .method("GET")
                .uri("/api/v1/accounts/verify_credentials")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "verify_credentials failed: {body}");
    })
    .await;
}

#[tokio::test]
async fn admin_account_action_returns_credential_email() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let (admin_id, _) = create_account(pool, "admin", true).await;
        let admin_token = create_token(pool, &admin_id).await;

        let (target_id, _) = create_account(pool, "target", false).await;
        PgAuthStore::new(pool.clone())
            .create_credential(&target_id, "target@social.test", "hash")
            .await
            .expect("create credential");

        let (no_cred_id, _) = create_account(pool, "nocred", false).await;

        let (status, body) = send(
            &state,
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/accounts/{target_id}/action"))
                .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("type=silence"))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "admin action failed: {body}");
        let parsed: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(parsed["email"], "target@social.test");
        assert_eq!(parsed["silenced"], true);

        let (status, body) = send(
            &state,
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/accounts/{no_cred_id}/action"))
                .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("type=silence"))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "admin action failed: {body}");
        let parsed: Value = serde_json::from_str(&body).expect("json");
        assert!(parsed["email"].is_null());
    })
    .await;
}

async fn create_status_api(
    state: &AppState,
    token: &str,
    status_text: &str,
    visibility: &str,
) -> String {
    let (status, body) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/api/v1/statuses")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "status": status_text, "visibility": visibility }).to_string(),
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create status failed: {body}");
    let parsed: Value = serde_json::from_str(&body).expect("json");
    parsed["id"].as_str().expect("status id").to_owned()
}

#[tokio::test]
async fn direct_status_visibility_respects_mentions() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let (author_id, _) = create_account(pool, "author", false).await;
        let (mentioned_id, mentioned_username) = create_account(pool, "mentioned", false).await;
        let (stranger_id, _) = create_account(pool, "stranger", false).await;

        let author_token = create_token(pool, &author_id).await;
        let mentioned_token = create_token(pool, &mentioned_id).await;
        let stranger_token = create_token(pool, &stranger_id).await;

        let dm_id = create_status_api(
            &state,
            &author_token,
            &format!("secret @{mentioned_username}"),
            "direct",
        )
        .await;

        let (status, _) = send(
            &state,
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/statuses/{dm_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {mentioned_token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = send(
            &state,
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/statuses/{dm_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {stranger_token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    })
    .await;
}

#[tokio::test]
async fn unreblog_removes_boost_and_updates_reblogs_count() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let (author_id, _) = create_account(pool, "author", false).await;
        let (booster_id, _) = create_account(pool, "booster", false).await;
        let author_token = create_token(pool, &author_id).await;
        let booster_token = create_token(pool, &booster_id).await;

        let pub_id = create_status_api(&state, &author_token, "public post", "public").await;

        let (status, _) = send(
            &state,
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/statuses/{pub_id}/reblog"))
                .header(header::AUTHORIZATION, format!("Bearer {booster_token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = send(
            &state,
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/statuses/{pub_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {booster_token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let after_reblog: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(after_reblog["reblogs_count"], 1);
        assert_eq!(after_reblog["reblogged"], true);

        let (status, body) = send(
            &state,
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/statuses/{pub_id}/reblog"))
                .header(header::AUTHORIZATION, format!("Bearer {booster_token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "unreblog failed: {body}");
        let after_unreblog: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(after_unreblog["reblogs_count"], 0);
        assert_eq!(after_unreblog["reblogged"], false);
    })
    .await;
}
