//! Secure mode (`NODUS_AUTHORIZED_FETCH`): a read of an `ActivityPub` document has to
//! be signed by the instance asking, unless it carries one of our own bearer tokens.
//!
//! The signatures here are built with the same `RsaSigner` the outbound client uses, so
//! a passing test is evidence that what a peer sends is what this instance checks —
//! not that a helper agrees with itself.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use nodus_federation::signature::crypto::RsaSigner;
use nodus_federation::{HttpSignature, Signer};
use nodus_server_api::{root_router, AppState, FederationKey, InstanceConfig};
use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount, RemoteAccount};
use nodus_server_store::Store;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::rand_core::OsRng;
use rsa::RsaPrivateKey;
use serde_json::Value;
use tower::ServiceExt;

const ACTOR_URL: &str = "https://social.test/actor";
const SIGNER: &str = "https://peer.test/users/signer";
const KEY_ID: &str = "https://peer.test/users/signer#main-key";
const INSTANCE_KEY_ID: &str = "https://social.test/actor#main-key";

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

/// A key pair, the PEM the server looks the signer up by, and a signer for it.
struct Key {
    pem: String,
    private_pem: String,
    signer: RsaSigner,
}

fn key() -> Key {
    let private = RsaPrivateKey::new(&mut OsRng, 2048).expect("generate key");
    let pem = rsa::RsaPublicKey::from(&private)
        .to_public_key_pem(LineEnding::LF)
        .expect("public pem");
    let private_pem = private.to_pkcs8_pem(LineEnding::LF).expect("private pem");
    Key {
        pem,
        private_pem: private_pem.to_string(),
        signer: RsaSigner::from_pkcs8_pem(&private_pem).expect("signer"),
    }
}

/// A signed GET, built the way the outbound client builds one: `(request-target)`,
/// `host`, `date`, and a `digest` only when the caller passes one.
struct Signed {
    date: String,
    digest: Option<String>,
    signature: String,
}

fn signed_get(key: &Key, target: &str, date: &str, digest: Option<&str>) -> Signed {
    signed_get_as(key, KEY_ID, target, date, digest)
}

/// The same signed GET but claiming `key_id`, which is what an operator's tool signs as.
fn signed_get_as(
    key: &Key,
    key_id: &str,
    target: &str,
    date: &str,
    digest: Option<&str>,
) -> Signed {
    let mut headers = vec!["(request-target)", "host", "date"];
    if digest.is_some() {
        headers.push("digest");
    }
    let mut signature = HttpSignature {
        key_id: key_id.to_owned(),
        algorithm: "rsa-sha256".to_owned(),
        headers: headers.iter().map(|name| (*name).to_owned()).collect(),
        signature: String::new(),
    };
    let signing = signature
        .signing_string(|name| match name {
            "(request-target)" => Some(format!("get {target}")),
            "host" => Some("social.test".to_owned()),
            "date" => Some(date.to_owned()),
            other => digest.filter(|_| other == "digest").map(str::to_owned),
        })
        .expect("signing string");
    signature.signature = key
        .signer
        .sign(key_id, "rsa-sha256", signing.as_bytes())
        .expect("sign");
    Signed {
        date: date.to_owned(),
        digest: digest.map(str::to_owned),
        signature: format!(
            "keyId=\"{key_id}\",algorithm=\"rsa-sha256\",headers=\"{}\",signature=\"{}\"",
            headers.join(" "),
            signature.signature
        ),
    }
}

fn http_date(at: chrono::DateTime<Utc>) -> String {
    at.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// `Digest: SHA-256=<base64>`, independent of the server's own helper: the test must not
/// agree with the code under test about what a digest is.
fn digest_of(body: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    format!("SHA-256={}", STANDARD.encode(Sha256::digest(body)))
}

async fn get(app: &Router, target: &str, headers: &[(&str, &str)]) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method("GET")
        .uri(target)
        .header(header::HOST, "social.test");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).expect("request"))
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

fn error_of(body: &str) -> String {
    let value: Value = serde_json::from_str(body).expect("JSON error body");
    value["error"]
        .as_str()
        .expect("an `error` naming the reason")
        .to_owned()
}

/// What one test gets: the running router, our own token, the peer signer, the local
/// account and its key, and the instance key when the test asked for one.
struct Fixture {
    store: Store,
    app: Router,
    token: String,
    peer: Key,
    local: Key,
    local_username: String,
    instance: Option<Key>,
    state: AppState,
}

/// Runs `body` with its own schema, the real root router, and secure mode set to
/// `secure`; the peer signer's key and the local account's key are already in the store,
/// so no test opens a socket. `instance_key` also configures the `FederationKey` this
/// instance signs as.
async fn with_secure_mode<F, Fut>(secure: bool, instance_key: bool, body: F)
where
    F: FnOnce(Fixture) -> Fut + Send + 'static,
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

    let peer = key();
    accounts::upsert_remote(
        store.pool(),
        &RemoteAccount {
            uri: SIGNER,
            username: "signer",
            domain: "peer.test",
            display_name: "Signer",
            note: "",
            avatar_url: None,
            header_url: None,
            inbox_url: None,
            shared_inbox_url: None,
            public_key_pem: Some(&peer.pem),
            locked: false,
            bot: false,
        },
    )
    .await
    .expect("seed the signing actor");

    // A local account with a token, standing in for the browser and the app — and, with
    // its own published key, for the local actor whose signature secure mode must verify.
    let local_username = format!("secure_{}", Id::new()).to_lowercase();
    let account = accounts::insert(
        store.pool(),
        &NewAccount {
            username: &local_username,
            display_name: &local_username,
            note: "",
            bot: false,
            locked: false,
        },
    )
    .await
    .expect("insert account");
    let token = create_token(store.pool(), &account.id).await;
    let local = key();
    let local_actor = format!("https://social.test/users/{local_username}");
    accounts::set_actor_identity(
        store.pool(),
        &account.id,
        &local_actor,
        &local.pem,
        &local.private_pem,
        &format!("{local_actor}/inbox"),
        Some("https://social.test/inbox"),
    )
    .await
    .expect("publish the local account's key");

    let instance = instance_key.then(key);
    let federation = instance
        .as_ref()
        .and_then(|key| FederationKey::from_pem(&instance_config(), &key.private_pem));
    assert!(!instance_key || federation.is_some(), "instance key parses");
    let state = AppState::with_federation(store.clone(), instance_config(), federation)
        .with_authorized_fetch(secure);
    let app = root_router(state.clone());

    let fixture = Fixture {
        store,
        app,
        token,
        peer,
        local,
        local_username,
        instance,
        state,
    };
    let outcome = tokio::spawn(async move { body(fixture).await }).await;
    let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
        .execute(admin.pool())
        .await;
    if let Err(err) = outcome {
        std::panic::resume_unwind(err.into_panic());
    }
}

async fn create_token(pool: &sqlx::PgPool, account_id: &str) -> String {
    use sha2::{Digest as _, Sha256};

    let app_id = Id::new().to_string();
    let client_id = format!("pgtest-client-{app_id}");
    let scopes = vec!["read".to_owned()];
    nodus_server_store::apps::register(
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
    .bind(&scopes)
    .execute(pool)
    .await
    .expect("insert oauth token");
    token
}

#[tokio::test]
async fn an_unsigned_read_is_refused_while_our_own_sessions_and_peers_get_through() {
    with_secure_mode(
        true,
        false,
        |Fixture {
             app,
             token,
             peer: key,
             ..
         }| async move {
            let (status, body) = get(&app, "/actor", &[]).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "unsigned: {body}");
            let error = error_of(&body);
            assert!(
                error.contains("HTTP signature"),
                "the body names the requirement: {error}"
            );

            let bearer = format!("Bearer {token}");
            let (status, body) = get(&app, "/actor", &[("authorization", &bearer)]).await;
            assert_eq!(status, StatusCode::OK, "our session: {body}");

            let date = http_date(Utc::now());
            let signed = signed_get(&key, "/actor", &date, None);
            let (status, body) = get(
                &app,
                "/actor",
                &[("date", &signed.date), ("signature", &signed.signature)],
            )
            .await;
            assert_eq!(status, StatusCode::OK, "signed: {body}");
            let document: Value = serde_json::from_str(&body).expect("actor document");
            assert_eq!(document["id"], ACTOR_URL);
        },
    )
    .await;
}

#[tokio::test]
async fn a_tampered_digest_or_a_stale_date_is_refused() {
    with_secure_mode(true, false, |Fixture { app, peer: key, .. }| async move {
        // Signed correctly, but over a digest of a body that is not the empty one.
        let date = http_date(Utc::now());
        let tampered = digest_of(b"a body that was never sent");
        let signed = signed_get(&key, "/actor", &date, Some(&tampered));
        let (status, body) = get(
            &app,
            "/actor",
            &[
                ("date", &signed.date),
                ("digest", signed.digest.as_deref().expect("digest")),
                ("signature", &signed.signature),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "tampered digest: {body}");
        assert!(error_of(&body).contains("digest"), "{body}");

        // A signature made two hours ago.
        let old = http_date(Utc::now() - Duration::hours(2));
        let signed = signed_get(&key, "/actor", &old, None);
        let (status, body) = get(
            &app,
            "/actor",
            &[("date", &signed.date), ("signature", &signed.signature)],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "stale date: {body}");
        assert!(error_of(&body).contains("hour"), "{body}");
    })
    .await;
}

#[tokio::test]
async fn unsigned_reads_stay_open_with_the_switch_off() {
    with_secure_mode(false, false, |Fixture { app, peer: key, .. }| async move {
        let (status, body) = get(&app, "/actor", &[]).await;
        assert_eq!(status, StatusCode::OK, "unsigned with the flag off: {body}");
        let document: Value = serde_json::from_str(&body).expect("actor document");
        assert_eq!(document["id"], ACTOR_URL);

        let date = http_date(Utc::now());
        let signed = signed_get(&key, "/actor", &date, None);
        let (status, body) = get(
            &app,
            "/actor",
            &[("date", &signed.date), ("signature", &signed.signature)],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "signed with the flag off: {body}");
    })
    .await;
}

#[tokio::test]
async fn a_bad_signature_is_not_a_rejection_with_the_switch_off() {
    with_secure_mode(
        false,
        false,
        |Fixture {
             app,
             token,
             peer: key,
             ..
         }| async move {
            let bearer = format!("Bearer {token}");
            let (status, body) = get(&app, "/actor", &[("authorization", &bearer)]).await;
            assert_eq!(status, StatusCode::OK, "session with the flag off: {body}");

            let date = http_date(Utc::now());
            let tampered = digest_of(b"a body that was never sent");
            let signed = signed_get(&key, "/actor", &date, Some(&tampered));
            let (status, body) = get(
                &app,
                "/actor",
                &[
                    ("date", &signed.date),
                    ("digest", signed.digest.as_deref().expect("digest")),
                    ("signature", &signed.signature),
                ],
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "a tampered digest is ignored with the flag off: {body}"
            );

            let old = http_date(Utc::now() - Duration::hours(2));
            let signed = signed_get(&key, "/actor", &old, None);
            let (status, body) = get(
                &app,
                "/actor",
                &[("date", &signed.date), ("signature", &signed.signature)],
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "a stale date is ignored with the flag off: {body}"
            );
        },
    )
    .await;
}

/// The hole secure mode left in itself: a request signed by our own instance key names a
/// `keyId` on our domain, and verifying it used to fetch `https://social.test/actor` —
/// unsigned — which secure mode refuses. The host is a reserved `.test` name with no
/// resolver entry, so a 200 can only come from local data: had the resolver dialled out,
/// DNS would fail and the middleware would answer 401.
#[tokio::test]
async fn a_request_signed_by_the_instance_key_verifies_without_a_request() {
    with_secure_mode(true, true, |Fixture { app, instance, .. }| async move {
        let instance = instance.expect("the instance key was configured");
        let date = http_date(Utc::now());
        let signed = signed_get_as(&instance, INSTANCE_KEY_ID, "/actor", &date, None);
        let (status, body) = get(
            &app,
            "/actor",
            &[("date", &signed.date), ("signature", &signed.signature)],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "instance-signed: {body}");
        let document: Value = serde_json::from_str(&body).expect("actor document");
        assert_eq!(document["id"], ACTOR_URL);
        assert_eq!(
            document["publicKey"]["id"], INSTANCE_KEY_ID,
            "the key the instance publishes is the one it signed with"
        );
    })
    .await;
}

/// A local account's `keyId` (`/users/<name>#main-key`) is answered from its account row,
/// never by reading the actor document over HTTP.
#[tokio::test]
async fn a_local_accounts_key_verifies_locally() {
    with_secure_mode(
        true,
        false,
        |Fixture {
             app,
             local,
             local_username,
             ..
         }| async move {
            let key_id = format!("https://social.test/users/{local_username}#main-key");
            let target = format!("/users/{local_username}");
            let date = http_date(Utc::now());
            let signed = signed_get_as(&local, &key_id, &target, &date, None);
            let (status, body) = get(
                &app,
                &target,
                &[("date", &signed.date), ("signature", &signed.signature)],
            )
            .await;
            assert_eq!(status, StatusCode::OK, "local-account-signed: {body}");
        },
    )
    .await;
}

/// Being on our own domain is not enough: the claimed `keyId` must be the key the actor
/// publishes, or the local shortcut would let an instance-key signature claim any id.
#[tokio::test]
async fn a_key_id_on_our_domain_that_is_not_the_published_key_is_refused() {
    with_secure_mode(true, true, |Fixture { app, instance, .. }| async move {
        let instance = instance.expect("the instance key was configured");
        let date = http_date(Utc::now());
        let wrong = signed_get_as(
            &instance,
            "https://social.test/actor#not-the-key",
            "/actor",
            &date,
            None,
        );
        let (status, body) = get(
            &app,
            "/actor",
            &[("date", &wrong.date), ("signature", &wrong.signature)],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "wrong keyId: {body}");
        assert!(
            error_of(&body).contains("public key"),
            "the refusal names the key mismatch, not a failed fetch: {body}"
        );

        // A keyId under /users/ that names no local account: refused, never fetched.
        let unknown = format!("https://social.test/users/secure_nobody#main-key");
        let wrong = signed_get_as(&instance, &unknown, "/users/secure_nobody", &date, None);
        let (status, body) = get(
            &app,
            "/users/secure_nobody",
            &[("date", &wrong.date), ("signature", &wrong.signature)],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "unknown local actor: {body}"
        );
        assert!(
            error_of(&body).contains("local account"),
            "the refusal comes from the local lookup: {body}"
        );
    })
    .await;
}

/// Outbound key resolution goes through `fediverse_client()`, the only client that
/// carries our signer; this pins that it does, so an instance which enforces secure mode
/// does not refuse the fetch the way we used to refuse ourselves.
#[tokio::test]
async fn the_client_that_resolves_peer_keys_is_the_signing_client() {
    with_secure_mode(true, true, |Fixture { state, store, .. }| async move {
        let signed = format!("{:?}", state.fediverse_client());
        assert!(
            signed.contains("Some(HttpSigner"),
            "signed client: {signed}"
        );
        let unsigned = format!(
            "{:?}",
            AppState::new(store, instance_config()).fediverse_client()
        );
        assert!(
            unsigned.contains("signer: None"),
            "unsigned client: {unsigned}"
        );
    })
    .await;
}
