use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

use nodus_server_api::{root_router, AppState, InstanceConfig};
use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount};
use nodus_server_store::{apps, external_ids, social, statuses, Store};

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

async fn run_isolated_db_test<F, Fut>(body: F)
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
    let token_hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    sqlx::query(
        "INSERT INTO oauth_token (id, app_id, account_id, token_hash, scopes) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Id::new().to_string())
    .bind(&app_id)
    .bind(account_id)
    .bind(&token_hash)
    .bind(&["read".to_owned(), "write".to_owned()][..])
    .execute(pool)
    .await
    .expect("insert oauth token");

    token
}

async fn send_request(
    state: &AppState,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let body = match body {
        Some(json_body) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(json_body.to_string())
        }
        None => Body::empty(),
    };
    let response = root_router(state.clone())
        .oneshot(builder.body(body).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

#[tokio::test]
async fn misskey_create_note_fans_out_records_mentions_tags_and_counters() {
    run_isolated_db_test(|store, state| async move {
        let pool = store.pool();
        let (alice_id, _) = create_account(pool, "alice").await;
        let (bob_id, bob_name) = create_account(pool, "bob").await;
        let (follower_id, _) = create_account(pool, "follower").await;

        let alice_token = create_token(pool, &alice_id).await;
        let follower_token = create_token(pool, &follower_id).await;
        social::follow(pool, &follower_id, &alice_id, true, false)
            .await
            .expect("follower follows alice");

        let (status, note) = send_request(
            &state,
            "POST",
            "/api/notes/create",
            None,
            Some(json!({
                "i": alice_token,
                "text": format!("Hello @{bob_name} #RustLang"),
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create note failed: {note}");
        let note_ext_id = note["id"].as_str().expect("note id").to_owned();

        let (tl_status, tl) = send_request(
            &state,
            "POST",
            "/api/notes/timeline",
            None,
            Some(json!({ "i": follower_token })),
        )
        .await;
        assert_eq!(tl_status, StatusCode::OK);
        let items = tl.as_array().expect("timeline array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], note_ext_id);

        let alice_row = accounts::by_id(pool, &alice_id).await.unwrap().unwrap();
        assert_eq!(alice_row.statuses_count, 1);
        assert!(alice_row.last_status_at.is_some());

        let local_id = external_ids::resolve(pool, "status", &note_ext_id)
            .await
            .unwrap()
            .unwrap();
        let mentions: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM status_mention WHERE status_id = $1 AND account_id = $2",
        )
        .bind(&local_id)
        .bind(&bob_id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(mentions, 1);

        let tags: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM status_tag WHERE status_id = $1 AND tag = 'rustlang'",
        )
        .bind(&local_id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(tags, 1);

        let bob_notifs = social::notifications(pool, &bob_id, None, 20, &[])
            .await
            .unwrap();
        assert_eq!(bob_notifs.len(), 1);
        assert_eq!(bob_notifs[0].kind, "mention");
        assert_eq!(bob_notifs[0].status_id.as_deref(), Some(local_id.as_str()));
    })
    .await;
}

#[tokio::test]
async fn misskey_reply_and_delete_update_counters_and_dedupe_notifications() {
    run_isolated_db_test(|store, state| async move {
        let pool = store.pool();
        let (alice_id, alice_name) = create_account(pool, "alice").await;
        let (bob_id, _) = create_account(pool, "bob").await;
        let alice_token = create_token(pool, &alice_id).await;
        let bob_token = create_token(pool, &bob_id).await;

        let (_, root) = send_request(
            &state,
            "POST",
            "/api/notes/create",
            None,
            Some(json!({ "i": alice_token, "text": "root note" })),
        )
        .await;
        let root_ext_id = root["id"].as_str().unwrap().to_owned();
        let root_local_id = external_ids::resolve(pool, "status", &root_ext_id)
            .await
            .unwrap()
            .unwrap();

        let (reply_status, reply) = send_request(
            &state,
            "POST",
            "/api/notes/create",
            None,
            Some(json!({
                "i": bob_token,
                "replyId": root_ext_id,
                "text": format!("@{alice_name} nice note!"),
            })),
        )
        .await;
        assert_eq!(reply_status, StatusCode::OK);
        assert_eq!(
            statuses::by_id(pool, &root_local_id)
                .await
                .unwrap()
                .unwrap()
                .replies_count,
            1
        );
        let alice_mentions = social::notifications(pool, &alice_id, None, 20, &[])
            .await
            .unwrap();
        assert_eq!(alice_mentions.len(), 1);

        let (del_reply, _) = send_request(
            &state,
            "POST",
            "/api/notes/delete",
            None,
            Some(json!({ "i": bob_token, "noteId": reply["id"].as_str().unwrap() })),
        )
        .await;
        assert_eq!(del_reply, StatusCode::OK);
        assert_eq!(
            statuses::by_id(pool, &root_local_id)
                .await
                .unwrap()
                .unwrap()
                .replies_count,
            0
        );
        assert_eq!(
            accounts::by_id(pool, &bob_id)
                .await
                .unwrap()
                .unwrap()
                .statuses_count,
            0
        );
    })
    .await;
}

#[tokio::test]
async fn misskey_renote_and_delete_update_reblogs_and_statuses_count() {
    run_isolated_db_test(|store, state| async move {
        let pool = store.pool();
        let (alice_id, _) = create_account(pool, "alice").await;
        let (bob_id, _) = create_account(pool, "bob").await;
        let alice_token = create_token(pool, &alice_id).await;
        let bob_token = create_token(pool, &bob_id).await;

        let (_, root) = send_request(
            &state,
            "POST",
            "/api/notes/create",
            None,
            Some(json!({ "i": alice_token, "text": "root note" })),
        )
        .await;
        let root_ext_id = root["id"].as_str().unwrap().to_owned();
        let root_local_id = external_ids::resolve(pool, "status", &root_ext_id)
            .await
            .unwrap()
            .unwrap();

        let (renote_status, renote) = send_request(
            &state,
            "POST",
            "/api/notes/create",
            None,
            Some(json!({ "i": bob_token, "renoteId": root_ext_id })),
        )
        .await;
        assert_eq!(renote_status, StatusCode::OK);
        assert_eq!(
            statuses::by_id(pool, &root_local_id)
                .await
                .unwrap()
                .unwrap()
                .reblogs_count,
            1
        );

        let (del_renote, _) = send_request(
            &state,
            "POST",
            "/api/notes/delete",
            None,
            Some(json!({ "i": bob_token, "noteId": renote["id"].as_str().unwrap() })),
        )
        .await;
        assert_eq!(del_renote, StatusCode::OK);
        assert_eq!(
            statuses::by_id(pool, &root_local_id)
                .await
                .unwrap()
                .unwrap()
                .reblogs_count,
            0
        );
        assert_eq!(
            accounts::by_id(pool, &bob_id)
                .await
                .unwrap()
                .unwrap()
                .statuses_count,
            0
        );
    })
    .await;
}

#[tokio::test]
async fn mastodon_reply_mention_dedupes_notification_and_context_hides_deleted_parent() {
    run_isolated_db_test(|store, state| async move {
        let pool = store.pool();
        let (alice_id, alice_name) = create_account(pool, "alice").await;
        let (bob_id, _) = create_account(pool, "bob").await;
        let (carol_id, carol_name) = create_account(pool, "carol").await;

        let alice_token = create_token(pool, &alice_id).await;
        let bob_token = create_token(pool, &bob_id).await;

        let (status, root) = send_request(
            &state,
            "POST",
            "/api/v1/statuses",
            Some(&alice_token),
            Some(json!({ "status": "root post" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let root_id = root["id"].as_str().unwrap().to_owned();

        let (status, reply) = send_request(
            &state,
            "POST",
            "/api/v1/statuses",
            Some(&bob_token),
            Some(json!({
                "status": format!("@{alice_name} @{carol_name} hello"),
                "in_reply_to_id": root_id,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let reply_id = reply["id"].as_str().unwrap().to_owned();

        let alice_notifs = social::notifications(pool, &alice_id, None, 20, &[])
            .await
            .unwrap();
        assert_eq!(alice_notifs.len(), 1);
        let carol_notifs = social::notifications(pool, &carol_id, None, 20, &[])
            .await
            .unwrap();
        assert_eq!(carol_notifs.len(), 1);

        let (del_status, _) = send_request(
            &state,
            "DELETE",
            &format!("/api/v1/statuses/{root_id}"),
            Some(&alice_token),
            None,
        )
        .await;
        assert_eq!(del_status, StatusCode::OK);

        let (ctx_status, ctx) = send_request(
            &state,
            "GET",
            &format!("/api/v1/statuses/{reply_id}/context"),
            Some(&bob_token),
            None,
        )
        .await;
        assert_eq!(ctx_status, StatusCode::OK);
        assert_eq!(ctx["ancestors"].as_array().unwrap().len(), 0);
    })
    .await;
}

#[tokio::test]
async fn mastodon_reblog_is_idempotent_and_unreblog_decrements_count() {
    run_isolated_db_test(|store, state| async move {
        let pool = store.pool();
        let (alice_id, _) = create_account(pool, "alice").await;
        let (bob_id, _) = create_account(pool, "bob").await;
        let alice_token = create_token(pool, &alice_id).await;
        let bob_token = create_token(pool, &bob_id).await;

        let (_, root) = send_request(
            &state,
            "POST",
            "/api/v1/statuses",
            Some(&alice_token),
            Some(json!({ "status": "boost me" })),
        )
        .await;
        let root_id = root["id"].as_str().unwrap().to_owned();

        let (s1, boost1) = send_request(
            &state,
            "POST",
            &format!("/api/v1/statuses/{root_id}/reblog"),
            Some(&bob_token),
            None,
        )
        .await;
        assert_eq!(s1, StatusCode::OK);
        let (s2, boost2) = send_request(
            &state,
            "POST",
            &format!("/api/v1/statuses/{root_id}/reblog"),
            Some(&bob_token),
            None,
        )
        .await;
        assert_eq!(s2, StatusCode::OK);
        assert_eq!(boost1["id"], boost2["id"]);

        let (_, fetched_root) = send_request(
            &state,
            "GET",
            &format!("/api/v1/statuses/{root_id}"),
            Some(&alice_token),
            None,
        )
        .await;
        assert_eq!(fetched_root["reblogs_count"], 1);

        let alice_reblogs =
            social::notifications(pool, &alice_id, None, 20, &["reblog".to_owned()])
                .await
                .unwrap();
        assert_eq!(alice_reblogs.len(), 1);

        let (unreblog_status, unboosted) = send_request(
            &state,
            "DELETE",
            &format!("/api/v1/statuses/{root_id}/reblog"),
            Some(&bob_token),
            None,
        )
        .await;
        assert_eq!(unreblog_status, StatusCode::OK);
        assert_eq!(unboosted["reblogs_count"], 0);
    })
    .await;
}
