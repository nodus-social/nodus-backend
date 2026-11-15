#![allow(clippy::too_many_lines)]

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

use nodus_server_api::{root_router, AppState, InstanceConfig};
use nodus_server_core::limits::{CLIENT_METADATA_MAX_BYTES, CLIENT_METADATA_MAX_KEYS};
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

fn json_request(
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(body) = body {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        builder.body(Body::from(body.to_string())).expect("request")
    } else {
        builder.body(Body::empty()).expect("request")
    }
}

#[tokio::test]
async fn metadata_endpoints_require_auth_and_enforce_scopes() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let alice = create_account(pool, "alice").await;
        let read_only = create_token_with_scopes(pool, &alice, &["read:accounts"]).await;
        let statuses_only = create_token_with_scopes(pool, &alice, &["read:statuses"]).await;
        let write_statuses = create_token_with_scopes(pool, &alice, &["write:statuses"]).await;
        let write_accounts = create_token_with_scopes(pool, &alice, &["write:accounts"]).await;

        for (method, uri, body) in [
            ("GET", "/api/v1/nodus/account/metadata", None),
            (
                "PATCH",
                "/api/v1/nodus/account/metadata",
                Some(json!({"metadata": {}})),
            ),
            (
                "PUT",
                "/api/v1/nodus/account/metadata",
                Some(json!({"metadata": {}})),
            ),
            ("DELETE", "/api/v1/nodus/account/metadata", None),
            (
                "GET",
                "/api/v1/nodus/account/metadata/nodus-top-banner",
                None,
            ),
            (
                "PUT",
                "/api/v1/nodus/account/metadata/nodus-top-banner",
                Some(json!({"value": "x"})),
            ),
            (
                "DELETE",
                "/api/v1/nodus/account/metadata/nodus-top-banner",
                None,
            ),
        ] {
            let (status, _) = send(&state, json_request(method, uri, None, body.clone())).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{method} {uri} without token must be 401"
            );
        }

        // read:statuses cannot read account metadata.
        let (status, _) = send(
            &state,
            json_request(
                "GET",
                "/api/v1/nodus/account/metadata",
                Some(&statuses_only),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // read:accounts can read, cannot write/clear.
        let (status, _) = send(
            &state,
            json_request(
                "GET",
                "/api/v1/nodus/account/metadata",
                Some(&read_only),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        for (method, uri, body) in [
            (
                "PATCH",
                "/api/v1/nodus/account/metadata",
                Some(json!({"metadata": {"k": "v"}})),
            ),
            (
                "PUT",
                "/api/v1/nodus/account/metadata",
                Some(json!({"metadata": {"k": "v"}})),
            ),
            ("DELETE", "/api/v1/nodus/account/metadata", None),
            (
                "PUT",
                "/api/v1/nodus/account/metadata/k",
                Some(json!({"value": "v"})),
            ),
            ("DELETE", "/api/v1/nodus/account/metadata/k", None),
        ] {
            let (status, _) = send(&state, json_request(method, uri, Some(&read_only), body)).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{method} {uri} with read:accounts must be 403"
            );
        }

        // write:statuses cannot write account metadata.
        let (status, _) = send(
            &state,
            json_request(
                "PUT",
                "/api/v1/nodus/account/metadata/nodus-top-banner",
                Some(&write_statuses),
                Some(json!({"value": "x"})),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // write:accounts can write, but cannot read unless read scope is also present.
        let (status, _) = send(
            &state,
            json_request(
                "PUT",
                "/api/v1/nodus/account/metadata/nodus-top-banner",
                Some(&write_accounts),
                Some(json!({"value": "x"})),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    })
    .await;
}

#[tokio::test]
async fn metadata_crud_multi_account_isolation_and_privacy() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let alice = create_account(pool, "alice").await;
        let bob = create_account(pool, "bob").await;
        // Standard web OAuth scope bundle.
        let alice_token =
            create_token_with_scopes(pool, &alice, &["read", "write", "follow"]).await;
        let bob_token = create_token_with_scopes(pool, &bob, &["read", "write", "follow"]).await;

        // Initial state is empty; specific key lookup returns 404.
        let (status, body) = send(
            &state,
            json_request(
                "GET",
                "/api/v1/nodus/account/metadata",
                Some(&alice_token),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap(),
            json!({ "metadata": {} })
        );

        let (status, _) = send(
            &state,
            json_request(
                "GET",
                "/api/v1/nodus/account/metadata/nodus-top-banner",
                Some(&alice_token),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Set a single key for split banner.
        let banner = json!({
            "mode": "split",
            "segments": [
                { "url": "/media/banner-a", "position": "left" },
                { "url": "/media/banner-b", "position": "right" }
            ]
        });
        let (status, body) = send(
            &state,
            json_request(
                "PUT",
                "/api/v1/nodus/account/metadata/nodus-top-banner",
                Some(&alice_token),
                Some(json!({ "value": banner })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap(),
            json!({ "key": "nodus-top-banner", "value": banner })
        );

        // Read single key back.
        let (status, body) = send(
            &state,
            json_request(
                "GET",
                "/api/v1/nodus/account/metadata/nodus-top-banner",
                Some(&alice_token),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap(),
            json!({ "key": "nodus-top-banner", "value": banner })
        );

        // Patch additional keys (left/right images, nav layout, third-party client key).
        let (status, body) = send(
            &state,
            json_request(
                "PATCH",
                "/api/v1/nodus/account/metadata",
                Some(&alice_token),
                Some(json!({
                    "metadata": {
                        "nodus-left-image": { "url": "/media/left" },
                        "nodus-right-image": { "url": "/media/right" },
                        "nodus-nav-layout": {
                            "left": ["home", "local"],
                            "right": ["notifications"],
                            "submenu": ["lists"]
                        },
                        "com.example.mobile:compact": true
                    }
                })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["metadata"]["nodus-top-banner"], banner);
        assert_eq!(parsed["metadata"]["nodus-left-image"]["url"], "/media/left");
        assert_eq!(parsed["metadata"]["com.example.mobile:compact"], true);

        // Filtered read by ?keys= and repeated ?key=
        let (status, body) = send(
            &state,
            json_request(
                "GET",
                "/api/v1/nodus/account/metadata?keys=nodus-top-banner,nodus-nav-layout,missing",
                Some(&alice_token),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let filtered: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(filtered["metadata"].as_object().unwrap().len(), 2);
        assert!(filtered["metadata"].get("nodus-top-banner").is_some());
        assert!(filtered["metadata"].get("nodus-nav-layout").is_some());
        assert!(filtered["metadata"].get("nodus-left-image").is_none());

        let (status, body) = send(
            &state,
            json_request(
                "GET",
                "/api/v1/nodus/account/metadata?key=nodus-right-image",
                Some(&alice_token),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let single_filtered: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            single_filtered,
            json!({ "metadata": { "nodus-right-image": { "url": "/media/right" } } })
        );

        // Bob cannot see Alice's metadata, and public AccountDto does not leak it.
        let (status, body) = send(
            &state,
            json_request(
                "GET",
                "/api/v1/nodus/account/metadata",
                Some(&bob_token),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap(),
            json!({ "metadata": {} })
        );

        let (status, public_account_body) = send(
            &state,
            json_request("GET", &format!("/api/v1/accounts/{alice}"), None, None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!public_account_body.contains("client_metadata"));
        assert!(!public_account_body.contains("nodus-top-banner"));

        // Clear a single key via DELETE /metadata/{key}.
        let (status, _) = send(
            &state,
            json_request(
                "DELETE",
                "/api/v1/nodus/account/metadata/nodus-left-image",
                Some(&alice_token),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = send(
            &state,
            json_request(
                "GET",
                "/api/v1/nodus/account/metadata/nodus-left-image",
                Some(&alice_token),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Clear selected keys via DELETE /metadata?keys=...
        let (status, body) = send(
            &state,
            json_request(
                "DELETE",
                "/api/v1/nodus/account/metadata?keys=nodus-right-image,com.example.mobile:compact",
                Some(&alice_token),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let remaining: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(remaining["metadata"].as_object().unwrap().len(), 2);

        // Full replacement via PUT /metadata.
        let (status, body) = send(
            &state,
            json_request(
                "PUT",
                "/api/v1/nodus/account/metadata",
                Some(&alice_token),
                Some(json!({ "metadata": { "fresh-key": 42 } })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap(),
            json!({ "metadata": { "fresh-key": 42 } })
        );

        // Clear all via DELETE /metadata.
        let (status, body) = send(
            &state,
            json_request(
                "DELETE",
                "/api/v1/nodus/account/metadata",
                Some(&alice_token),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap(),
            json!({ "metadata": {} })
        );
    })
    .await;
}

#[tokio::test]
async fn metadata_validates_keys_nulls_and_limits() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let alice = create_account(pool, "alice").await;
        let token = create_token_with_scopes(pool, &alice, &["read", "write"]).await;

        // Invalid keys rejected with 422.
        for bad_key in ["bad key", "a..b", "..", "x$y", &"a".repeat(129)] {
            let encoded =
                url::form_urlencoded::byte_serialize(bad_key.as_bytes()).collect::<String>();
            if !bad_key.contains("..") {
                let (status, _) = send(
                    &state,
                    json_request(
                        "PUT",
                        &format!("/api/v1/nodus/account/metadata/{encoded}"),
                        Some(&token),
                        Some(json!({ "value": 1 })),
                    ),
                )
                .await;
                assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "key={bad_key}");
            }
            let (status, _) = send(
                &state,
                json_request(
                    "PATCH",
                    "/api/v1/nodus/account/metadata",
                    Some(&token),
                    Some(json!({ "metadata": { bad_key: 1 } })),
                ),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "patch key={bad_key}"
            );
        }

        // Empty ?keys= rejected with 422.
        let (status, _) = send(
            &state,
            json_request(
                "GET",
                "/api/v1/nodus/account/metadata?keys=",
                Some(&token),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // PUT single key with null value rejected with 422.
        let (status, _) = send(
            &state,
            json_request(
                "PUT",
                "/api/v1/nodus/account/metadata/nodus-top-banner",
                Some(&token),
                Some(json!({ "value": null })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // Exceeding max keys returns 422.
        let mut too_many = serde_json::Map::new();
        for i in 0..=CLIENT_METADATA_MAX_KEYS {
            too_many.insert(format!("k-{i}"), json!(i));
        }
        let (status, _) = send(
            &state,
            json_request(
                "PATCH",
                "/api/v1/nodus/account/metadata",
                Some(&token),
                Some(json!({ "metadata": too_many })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // Exceeding max bytes returns 422.
        let big = "a".repeat(CLIENT_METADATA_MAX_BYTES);
        let (status, _) = send(
            &state,
            json_request(
                "PUT",
                "/api/v1/nodus/account/metadata/big-key",
                Some(&token),
                Some(json!({ "value": big })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    })
    .await;
}
