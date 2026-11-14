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
use nodus_server_store::statuses::{self, NewStatus};
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

async fn run_serialized_db_test<F, Fut>(body: F)
where
    F: FnOnce(Store, AppState) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Vec<String>> + Send + 'static,
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

async fn create_token(pool: &PgPool, account_id: &str) -> (String, String) {
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

    (token, app_id)
}

async fn create_status(pool: &PgPool, account_id: &str, text: &str) -> String {
    let id = Id::new().to_string();
    statuses::create(
        pool,
        &NewStatus {
            id: &id,
            account_id,
            content: text,
            content_html: text,
            content_source: Some(text),
            content_format: "html",
            spoiler_text: "",
            visibility: "public",
            sensitive: false,
            in_reply_to_id: None,
            in_reply_to_account_id: None,
            reblog_of_id: None,
            language: None,
        },
        &[],
        &[],
        &[],
    )
    .await
    .expect("create status");
    id
}

async fn send_get(
    state: &AppState,
    uri: &str,
    bearer: Option<&str>,
) -> (StatusCode, Option<String>, Value) {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = root_router(state.clone())
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let link = response
        .headers()
        .get(header::LINK)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let json = serde_json::from_slice(&bytes).expect("json body");
    (status, link, json)
}

async fn send_post_json(state: &AppState, uri: &str, body: &Value) -> (StatusCode, Value) {
    let response = root_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
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
    let json = serde_json::from_slice(&bytes).expect("json body");
    (status, json)
}

fn next_link_target(link_header: &str) -> String {
    let start = link_header.find('<').expect("link opening angle bracket") + 1;
    let end = link_header.find('>').expect("link closing angle bracket");
    link_header[start..end].to_owned()
}

fn ids_from_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("json array")
        .iter()
        .map(|item| item["id"].as_str().expect("item id").to_owned())
        .collect()
}

#[tokio::test]
async fn mastodon_timelines_honor_since_id_min_id_and_max_id() {
    run_serialized_db_test(|store, state| async move {
        let pool = store.pool();
        let author = create_account(pool, "author").await;
        let viewer = create_account(pool, "viewer").await;
        let (token, app_id) = create_token(pool, &viewer).await;
        social::follow(pool, &viewer, &author, true, false)
            .await
            .expect("follow");

        let s1 = create_status(pool, &author, "pgtest:1").await;
        let s2 = create_status(pool, &author, "pgtest:2").await;
        let s3 = create_status(pool, &author, "pgtest:3").await;
        let s4 = create_status(pool, &author, "pgtest:4").await;
        let s5 = create_status(pool, &author, "pgtest:5").await;

        let account_statuses_path = format!("/api/v1/accounts/{author}/statuses");
        let endpoints = [
            ("/api/v1/timelines/public", None),
            ("/api/v1/timelines/home", Some(token.as_str())),
            (account_statuses_path.as_str(), None),
        ];

        for (path, auth) in endpoints {
            // since_id returns the newest `limit` items strictly newer than since_id.
            let (status, _, body) =
                send_get(&state, &format!("{path}?since_id={s2}&limit=2"), auth).await;
            assert_eq!(status, StatusCode::OK, "path {path}");
            assert_eq!(
                ids_from_array(&body),
                vec![s5.clone(), s4.clone()],
                "since_id on {path}"
            );

            // since_id with a larger limit must still exclude since_id and older items.
            let (status, _, body) =
                send_get(&state, &format!("{path}?since_id={s3}&limit=10"), auth).await;
            assert_eq!(status, StatusCode::OK, "path {path}");
            assert_eq!(
                ids_from_array(&body),
                vec![s5.clone(), s4.clone()],
                "since_id filter on {path}"
            );

            // since_id + max_id returns items strictly in (since_id, max_id) newest first.
            let (status, _, body) = send_get(
                &state,
                &format!("{path}?since_id={s1}&max_id={s5}&limit=2"),
                auth,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "path {path}");
            assert_eq!(
                ids_from_array(&body),
                vec![s4.clone(), s3.clone()],
                "since_id + max_id on {path}"
            );

            // min_id returns the oldest `limit` items strictly newer than min_id, oldest first.
            let (status, _, body) =
                send_get(&state, &format!("{path}?min_id={s1}&limit=2"), auth).await;
            assert_eq!(status, StatusCode::OK, "path {path}");
            assert_eq!(
                ids_from_array(&body),
                vec![s2.clone(), s3.clone()],
                "min_id on {path}"
            );
        }

        vec![author, viewer, app_id, s1, s2, s3, s4, s5]
    })
    .await;
}

#[tokio::test]
async fn follow_list_paginates_with_follow_cursor_and_supports_since_and_min_id() {
    run_serialized_db_test(|store, state| async move {
        let pool = store.pool();
        // Create accounts in ascending ID order: old < mid < new.
        let target = create_account(pool, "target").await;
        let f_old = create_account(pool, "fold").await;
        let f_mid = create_account(pool, "fmid").await;
        let f_new = create_account(pool, "fnew").await;

        // Follow in scrambled order relative to account IDs: f_new first, then f_old, then f_mid.
        social::follow(pool, &f_new, &target, true, false)
            .await
            .expect("follow 1");
        social::follow(pool, &f_old, &target, true, false)
            .await
            .expect("follow 2");
        social::follow(pool, &f_mid, &target, true, false)
            .await
            .expect("follow 3");

        // Same scrambled order for `following`.
        social::follow(pool, &target, &f_new, true, false)
            .await
            .expect("following 1");
        social::follow(pool, &target, &f_old, true, false)
            .await
            .expect("following 2");
        social::follow(pool, &target, &f_mid, true, false)
            .await
            .expect("following 3");

        let e1: String = sqlx::query_scalar(
            "SELECT id FROM follow WHERE account_id = $1 AND target_account_id = $2",
        )
        .bind(&f_new)
        .bind(&target)
        .fetch_one(pool)
        .await
        .expect("follow id 1");

        for kind in ["followers", "following"] {
            let base = format!("/api/v1/accounts/{target}/{kind}");
            let (status, link1, body1) = send_get(&state, &format!("{base}?limit=2"), None).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                ids_from_array(&body1),
                vec![f_mid.clone(), f_old.clone()],
                "page 1 for {kind}"
            );
            let next_url = next_link_target(link1.as_deref().expect("Link header on page 1"));

            // Page 2 using the advertised Link header must return the remaining account, not [].
            let (status, link2, body2) = send_get(&state, &next_url, None).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                ids_from_array(&body2),
                vec![f_new.clone()],
                "page 2 for {kind}"
            );
            assert!(
                link2.is_none(),
                "last page for {kind} should have no Link header"
            );
        }

        // Also check min_id and since_id on followers.
        let (status, _, body) = send_get(
            &state,
            &format!("/api/v1/accounts/{target}/followers?min_id={e1}&limit=2"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ids_from_array(&body), vec![f_old.clone(), f_mid.clone()]);

        let (status, _, body) = send_get(
            &state,
            &format!("/api/v1/accounts/{target}/followers?since_id={e1}&limit=1"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ids_from_array(&body), vec![f_mid.clone()]);

        vec![target, f_old, f_mid, f_new]
    })
    .await;
}

#[tokio::test]
async fn misskey_timelines_honor_since_id_and_until_id() {
    run_serialized_db_test(|store, state| async move {
        let pool = store.pool();
        let author = create_account(pool, "mkauthor").await;
        let (token, app_id) = create_token(pool, &author).await;

        let s1 = create_status(pool, &author, "pgtest:mk1").await;
        let s2 = create_status(pool, &author, "pgtest:mk2").await;
        let s3 = create_status(pool, &author, "pgtest:mk3").await;
        let s4 = create_status(pool, &author, "pgtest:mk4").await;

        // Fetch local timeline to obtain the Misskey aid IDs (newest first: n4, n3, n2, n1).
        let (status, all) =
            send_post_json(&state, "/api/notes/local-timeline", &json!({ "limit": 10 })).await;
        assert_eq!(status, StatusCode::OK);
        let note_ids = ids_from_array(&all);
        assert_eq!(note_ids.len(), 4);
        let (n4, n3, n2, n1) = (&note_ids[0], &note_ids[1], &note_ids[2], &note_ids[3]);

        // sinceId returns strictly newer notes.
        for path in ["/api/notes/local-timeline", "/api/notes/global-timeline"] {
            let (status, body) =
                send_post_json(&state, path, &json!({ "sinceId": n2, "limit": 10 })).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                ids_from_array(&body),
                vec![n4.clone(), n3.clone()],
                "sinceId on {path}"
            );

            // sinceId + untilId returns strictly between (n1, n4).
            let (status, body) = send_post_json(
                &state,
                path,
                &json!({ "sinceId": n1, "untilId": n4, "limit": 10 }),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                ids_from_array(&body),
                vec![n3.clone(), n2.clone()],
                "sinceId + untilId on {path}"
            );
        }

        // Home timeline with sinceId.
        let (status, body) = send_post_json(
            &state,
            "/api/notes/timeline",
            &json!({ "i": token, "sinceId": n2, "limit": 10 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ids_from_array(&body), vec![n4.clone(), n3.clone()]);

        vec![author, app_id, s1, s2, s3, s4]
    })
    .await;
}

#[tokio::test]
async fn activitypub_outbox_paginates_with_max_id() {
    run_serialized_db_test(|store, state| async move {
        let pool = store.pool();
        let author_id = create_account(pool, "apauthor").await;
        let author = accounts::by_id(pool, &author_id)
            .await
            .expect("lookup")
            .expect("account");
        let actor = format!("https://social.test/users/{}", author.username);
        accounts::set_actor_identity(
            pool,
            &author.id,
            &actor,
            "PUBLIC_KEY",
            "PRIVATE_KEY",
            &format!("{actor}/inbox"),
            Some("https://social.test/inbox"),
        )
        .await
        .expect("set actor identity");

        let mut status_ids = Vec::with_capacity(23);
        for idx in 0..23 {
            status_ids.push(create_status(pool, &author.id, &format!("pgtest:ap:{idx}")).await);
        }

        let (status, _, page1) = send_get(
            &state,
            &format!("/users/{}/outbox?page=true", author.username),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let items1 = page1["orderedItems"].as_array().expect("orderedItems 1");
        assert_eq!(items1.len(), 20);
        let next_url = page1["next"]
            .as_str()
            .expect("page 1 next URL")
            .strip_prefix("https://social.test")
            .expect("local next URL");

        let (status, _, page2) = send_get(&state, next_url, None).await;
        assert_eq!(status, StatusCode::OK);
        let items2 = page2["orderedItems"].as_array().expect("orderedItems 2");
        assert_eq!(items2.len(), 3);
        assert!(page2.get("next").is_none(), "last outbox page has no next");

        // Ensure page 2 returned the oldest 3 statuses with no overlap from page 1.
        let page1_ids: Vec<&str> = items1
            .iter()
            .map(|item| item["object"]["id"].as_str().expect("note id"))
            .collect();
        let page2_ids: Vec<&str> = items2
            .iter()
            .map(|item| item["object"]["id"].as_str().expect("note id"))
            .collect();
        for id in &page2_ids {
            assert!(
                !page1_ids.contains(id),
                "duplicate status {id} across pages"
            );
        }
        assert_eq!(
            page2_ids,
            vec![
                format!("https://social.test/statuses/{}", status_ids[2]),
                format!("https://social.test/statuses/{}", status_ids[1]),
                format!("https://social.test/statuses/{}", status_ids[0]),
            ]
        );

        let (status, _, _) = send_get(
            &state,
            &format!(
                "/users/{}/outbox?page=true&max_id=not-an-id",
                author.username
            ),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let mut cleanup = vec![author_id];
        cleanup.extend(status_ids);
        cleanup
    })
    .await;
}
