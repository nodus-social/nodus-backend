use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

use nodus_server_api::{root_router, AppState, InstanceConfig};
use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount};
use nodus_server_store::{apps, events, Store};

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
    let app = root_router(AppState::new(store.clone(), instance_config()));
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
    .bind(digest)
    .bind(&owned_scopes)
    .execute(pool)
    .await
    .expect("insert oauth_token");
    token
}

async fn send_form(
    app: &Router,
    method: &str,
    uri: &str,
    token: &str,
    fields: &[(&str, &str)],
) -> (StatusCode, String) {
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields.iter().copied())
        .finish();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(encoded))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn send_json(
    app: &Router,
    method: &str,
    uri: &str,
    token: &str,
    payload: &Value,
) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn lists_create_and_update_validate_replies_policy() {
    run_db_test(|store, app| async move {
        let (user_id, _) = create_account(store.pool(), "listuser", false).await;
        let token = create_token_with_scopes(store.pool(), &user_id, &["read", "write"]).await;

        for invalid in ["everyone", "invalid", ""] {
            let (status, body) = send_form(
                &app,
                "POST",
                "/api/v1/lists",
                &token,
                &[("title", "Friends"), ("replies_policy", invalid)],
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "POST /api/v1/lists with replies_policy={invalid:?} got {status}: {body}"
            );
        }

        let (status, body) = send_form(
            &app,
            "POST",
            "/api/v1/lists",
            &token,
            &[("title", "Friends"), ("replies_policy", "followed")],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create list failed: {body}");
        let created: Value = serde_json::from_str(&body).expect("json");
        let list_id = created["id"].as_str().expect("list id");
        assert_eq!(created["replies_policy"], "followed");

        let list_uri = format!("/api/v1/lists/{list_id}");
        for invalid in ["bogus", "all", ""] {
            let (status, body) = send_form(
                &app,
                "PUT",
                &list_uri,
                &token,
                &[("title", "Friends"), ("replies_policy", invalid)],
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "PUT {list_uri} with replies_policy={invalid:?} got {status}: {body}"
            );
        }

        let (status, body) = send_form(
            &app,
            "PUT",
            &list_uri,
            &token,
            &[("title", "Friends Updated"), ("replies_policy", "none")],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "update list failed: {body}");
        let updated: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(updated["replies_policy"], "none");
        assert_eq!(updated["title"], "Friends Updated");
    })
    .await;
}

#[tokio::test]
async fn filters_update_validates_filter_action() {
    run_db_test(|store, app| async move {
        let (user_id, _) = create_account(store.pool(), "filteruser", false).await;
        let token = create_token_with_scopes(store.pool(), &user_id, &["read", "write"]).await;

        let (status, body) = send_json(
            &app,
            "POST",
            "/api/v2/filters",
            &token,
            &json!({
                "title": "Spoilers",
                "filter_action": "warn",
                "context": ["home"],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create filter failed: {body}");
        let created: Value = serde_json::from_str(&body).expect("json");
        let filter_id = created["id"].as_str().expect("filter id");

        let filter_uri = format!("/api/v2/filters/{filter_id}");
        for invalid in ["delete", "block", ""] {
            let (status, body) = send_json(
                &app,
                "PUT",
                &filter_uri,
                &token,
                &json!({
                    "title": "Spoilers",
                    "filter_action": invalid,
                    "context": ["home"],
                }),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "PUT {filter_uri} with filter_action={invalid:?} got {status}: {body}"
            );
        }

        let (status, body) = send_json(
            &app,
            "PUT",
            &filter_uri,
            &token,
            &json!({
                "title": "Spoilers",
                "filter_action": "hide",
                "context": ["home", "public"],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "update filter failed: {body}");
        let updated: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(updated["filter_action"], "hide");
    })
    .await;
}

#[tokio::test]
async fn admin_create_domain_block_validates_severity() {
    run_db_test(|store, app| async move {
        let (admin_id, _) = create_account(store.pool(), "admin", true).await;
        let token =
            create_token_with_scopes(store.pool(), &admin_id, &["admin:read", "admin:write"]).await;

        for invalid in ["noop", "ban", ""] {
            let (status, body) = send_form(
                &app,
                "POST",
                "/api/v1/admin/domain_blocks",
                &token,
                &[("domain", "bad.example"), ("severity", invalid)],
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "POST /api/v1/admin/domain_blocks with severity={invalid:?} got {status}: {body}"
            );
        }

        let (status, body) = send_form(
            &app,
            "POST",
            "/api/v1/admin/domain_blocks",
            &token,
            &[("domain", "noisy.example"), ("severity", "silence")],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create domain block failed: {body}");
        let created: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(created["severity"], "silence");
    })
    .await;
}

#[tokio::test]
async fn create_report_rejects_missing_target_account_without_500() {
    run_db_test(|store, app| async move {
        let (reporter_id, _) = create_account(store.pool(), "reporter", false).await;
        let (target_id, _) = create_account(store.pool(), "target", false).await;
        let token = create_token_with_scopes(store.pool(), &reporter_id, &["write:reports"]).await;

        let (status, body) = send_form(
            &app,
            "POST",
            "/api/v1/reports",
            &token,
            &[
                ("account_id", "01NONEXISTENTACCOUNTID0000"),
                ("comment", "spam"),
            ],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "POST /api/v1/reports with nonexistent account_id got {status}: {body}"
        );

        let (status, body) = send_form(
            &app,
            "POST",
            "/api/v1/reports",
            &token,
            &[("account_id", ""), ("comment", "spam")],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "POST /api/v1/reports with empty account_id got {status}: {body}"
        );

        let (status, body) = send_form(
            &app,
            "POST",
            "/api/v1/reports",
            &token,
            &[("account_id", &target_id), ("comment", "spam")],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "valid report failed: {body}");
    })
    .await;
}

#[tokio::test]
async fn event_log_chain_hash_includes_collection_and_survives_jsonb_roundtrip() {
    run_db_test(|store, _app| async move {
        let pool = store.pool();
        let collection = "timeline:local";
        let payload = json!({
            "z": 1,
            "aa": 2,
            "nested": {
                "long_key": true,
                "b": "x",
                "aa": [3, { "yy": "val", "a": 1 }]
            }
        });

        let first = events::append(pool, collection, "status.create", &payload)
            .await
            .expect("append first event");
        let second = events::append(pool, collection, "status.update", &payload)
            .await
            .expect("append second event");

        assert_eq!(second.previous_hash.as_deref(), Some(first.hash.as_str()));

        let stored = events::after(pool, collection, &first.hash, 10)
            .await
            .expect("fetch after first");
        assert_eq!(stored.len(), 1);
        let roundtripped = &stored[0];

        assert_eq!(
            events::chain_hash(
                &first.collection,
                first.previous_hash.as_deref(),
                &first.id,
                &first.kind,
                &first.payload,
            ),
            first.hash
        );
        assert_eq!(
            events::chain_hash(
                &roundtripped.collection,
                roundtripped.previous_hash.as_deref(),
                &roundtripped.id,
                &roundtripped.kind,
                &roundtripped.payload,
            ),
            roundtripped.hash
        );
        assert_ne!(
            events::chain_hash(
                "timeline:other",
                first.previous_hash.as_deref(),
                &first.id,
                &first.kind,
                &first.payload,
            ),
            first.hash,
            "collection must be included in chain_hash"
        );

        let raw_jsonb_text: String =
            sqlx::query_scalar("SELECT payload::text FROM event_log WHERE id = $1")
                .bind(&first.id)
                .fetch_one(pool)
                .await
                .expect("fetch raw jsonb text");
        let parsed_from_jsonb: Value =
            serde_json::from_str(&raw_jsonb_text).expect("parse jsonb text");
        assert_eq!(
            events::chain_hash(
                collection,
                first.previous_hash.as_deref(),
                &first.id,
                &first.kind,
                &parsed_from_jsonb,
            ),
            first.hash
        );
    })
    .await;
}
