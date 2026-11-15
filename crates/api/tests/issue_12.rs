use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

use nodus_server_api::{root_router, AppState, InstanceConfig};
use nodus_server_core::limits::BIG_ACCOUNT_THRESHOLD;
use nodus_server_core::Id;
use nodus_server_store::accounts::{self, NewAccount};
use nodus_server_store::{apps, events, external_ids, social, Store};

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

async fn create_account(pool: &PgPool, label: &str, locked: bool) -> (String, String) {
    let suffix = Id::new().to_string();
    let username = format!("pgtest_{label}_{suffix}");
    let row = accounts::insert(
        pool,
        &NewAccount {
            username: &username,
            display_name: &username,
            note: "",
            bot: false,
            locked,
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

async fn create_status_api(state: &AppState, token: &str, text: &str, visibility: &str) -> String {
    let (status, body) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/api/v1/statuses")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "status": text, "visibility": visibility }).to_string(),
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create status failed: {body}");
    let parsed: Value = serde_json::from_str(&body).expect("json");
    parsed["id"].as_str().expect("status id").to_owned()
}

async fn get_home_timeline_ids(state: &AppState, token: &str) -> Vec<String> {
    let (status, body) = send(
        state,
        Request::builder()
            .method("GET")
            .uri("/api/v1/timelines/home")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "home timeline failed: {body}");
    let items: Vec<Value> = serde_json::from_str(&body).expect("json");
    items
        .into_iter()
        .map(|item| item["id"].as_str().expect("id").to_owned())
        .collect()
}

#[tokio::test]
async fn direct_messages_are_not_fanned_out_or_returned_in_home_timeline() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let (author_id, _) = create_account(pool, "author", false).await;
        let (follower_id, _) = create_account(pool, "follower", false).await;
        let (recipient_id, recipient_username) = create_account(pool, "recipient", false).await;

        social::follow(pool, &follower_id, &author_id, true, false)
            .await
            .expect("follow");

        let author_token = create_token(pool, &author_id).await;
        let follower_token = create_token(pool, &follower_id).await;
        let _recipient_token = create_token(pool, &recipient_id).await;

        let dm_id = create_status_api(
            &state,
            &author_token,
            &format!("secret dm @{recipient_username}"),
            "direct",
        )
        .await;

        let entry_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM timeline_entry WHERE status_id = $1")
                .bind(&dm_id)
                .fetch_one(pool)
                .await
                .expect("count timeline_entry");
        assert_eq!(
            entry_count, 0,
            "direct messages must never be fanned out into timeline_entry"
        );

        let follower_home = get_home_timeline_ids(&state, &follower_token).await;
        assert!(
            !follower_home.contains(&dm_id),
            "follower must not see author's DM in home timeline"
        );

        let author_home = get_home_timeline_ids(&state, &author_token).await;
        assert!(
            !author_home.contains(&dm_id),
            "author home timeline must exclude direct messages"
        );

        // Defense in depth: even if a timeline_entry row exists for a DM, home_page excludes it.
        sqlx::query(
            "INSERT INTO timeline_entry (account_id, status_id, kind) VALUES ($1, $2, 'home')",
        )
        .bind(&follower_id)
        .bind(&dm_id)
        .execute(pool)
        .await
        .expect("insert stale timeline_entry");

        let follower_home_after = get_home_timeline_ids(&state, &follower_token).await;
        assert!(
            !follower_home_after.contains(&dm_id),
            "home_page must filter direct messages even if timeline_entry exists"
        );

        // Big accounts must not fan out timeline_entry rows to followers either.
        sqlx::query("UPDATE account SET followers_count = $2 WHERE id = $1")
            .bind(&author_id)
            .bind(BIG_ACCOUNT_THRESHOLD)
            .execute(pool)
            .await
            .expect("promote big account");

        let pub_id =
            create_status_api(&state, &author_token, "big account public post", "public").await;
        let follower_entries_for_big: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM timeline_entry WHERE status_id = $1 AND account_id = $2",
        )
        .bind(&pub_id)
        .bind(&follower_id)
        .fetch_one(pool)
        .await
        .expect("count big follower timeline_entry");
        assert_eq!(
            follower_entries_for_big, 0,
            "big account posts must not fan out timeline_entry rows to followers"
        );

        let follower_home_big = get_home_timeline_ids(&state, &follower_token).await;
        assert!(
            follower_home_big.contains(&pub_id),
            "accepted follower must still read big account's public post via big-account branch"
        );
    })
    .await;
}

#[tokio::test]
async fn pending_follower_cannot_read_private_posts_of_big_account() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let (big_id, _) = create_account(pool, "lockedbig", true).await;
        let (pending_id, _) = create_account(pool, "pending", false).await;
        let (accepted_id, _) = create_account(pool, "accepted", false).await;

        let pending_outcome = social::follow(pool, &pending_id, &big_id, true, false)
            .await
            .expect("pending follow");
        assert_eq!(pending_outcome, social::FollowOutcome::Requested);

        let accepted_outcome = social::follow(pool, &accepted_id, &big_id, true, false)
            .await
            .expect("request follow");
        assert_eq!(accepted_outcome, social::FollowOutcome::Requested);
        assert!(social::accept_follow(pool, &big_id, &accepted_id)
            .await
            .expect("accept follow"));

        sqlx::query("UPDATE account SET followers_count = $2 WHERE id = $1")
            .bind(&big_id)
            .bind(BIG_ACCOUNT_THRESHOLD)
            .execute(pool)
            .await
            .expect("set big followers_count");

        let big_token = create_token(pool, &big_id).await;
        let pending_token = create_token(pool, &pending_id).await;
        let accepted_token = create_token(pool, &accepted_id).await;

        let private_id =
            create_status_api(&state, &big_token, "followers only secret", "private").await;

        let pending_home = get_home_timeline_ids(&state, &pending_token).await;
        assert!(
            !pending_home.contains(&private_id),
            "pending follower must not see locked big account's private post"
        );

        let accepted_home = get_home_timeline_ids(&state, &accepted_token).await;
        assert!(
            accepted_home.contains(&private_id),
            "accepted follower must see locked big account's private post"
        );
    })
    .await;
}

#[tokio::test]
async fn private_and_direct_statuses_cannot_be_reblogged() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let (author_id, _) = create_account(pool, "author", false).await;
        let (follower_id, follower_username) = create_account(pool, "follower", false).await;
        let (stranger_id, _) = create_account(pool, "stranger", false).await;

        social::follow(pool, &follower_id, &author_id, true, false)
            .await
            .expect("follow");

        let author_token = create_token(pool, &author_id).await;
        let follower_token = create_token(pool, &follower_id).await;
        let stranger_token = create_token(pool, &stranger_id).await;

        let public_id = create_status_api(&state, &author_token, "public", "public").await;
        let unlisted_id = create_status_api(&state, &author_token, "unlisted", "unlisted").await;
        let private_id = create_status_api(&state, &author_token, "private", "private").await;
        let direct_id = create_status_api(
            &state,
            &author_token,
            &format!("dm @{follower_username}"),
            "direct",
        )
        .await;

        for (id, expected) in [
            (&public_id, StatusCode::OK),
            (&unlisted_id, StatusCode::OK),
            (&private_id, StatusCode::UNPROCESSABLE_ENTITY),
            (&direct_id, StatusCode::UNPROCESSABLE_ENTITY),
        ] {
            let (status, body) = send(
                &state,
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/statuses/{id}/reblog"))
                    .header(header::AUTHORIZATION, format!("Bearer {follower_token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await;
            assert_eq!(status, expected, "reblog {id} returned {status}: {body}");
        }

        let (status, _) = send(
            &state,
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/statuses/{private_id}/reblog"))
                .header(header::AUTHORIZATION, format!("Bearer {author_token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, _) = send(
            &state,
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/statuses/{private_id}/reblog"))
                .header(header::AUTHORIZATION, format!("Bearer {stranger_token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    })
    .await;
}

async fn assert_nodus_collection_status(
    state: &AppState,
    token: &str,
    method: &str,
    uri: &str,
    body: Option<Value>,
    expected: StatusCode,
) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if body.is_some() {
        req = req.header(header::CONTENT_TYPE, "application/json");
    }
    let body = body.map_or_else(Body::empty, |val| Body::from(val.to_string()));
    let (status, resp) = send(state, req.body(body).expect("request")).await;
    assert_eq!(status, expected, "{method} {uri} returned {status}: {resp}");
}

async fn batch_status_call(state: &AppState, token: &str, ids: &[(&str, &str)]) -> Vec<Value> {
    let calls: Vec<Value> = ids
        .iter()
        .map(|(call_id, status_id)| {
            json!({ "id": call_id, "method": "status", "params": { "id": status_id } })
        })
        .collect();
    let (status, body) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/api/v1/nodus/batch")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(Value::Array(calls).to_string()))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "batch failed: {body}");
    let parsed: Value = serde_json::from_str(&body).expect("json");
    parsed["results"].as_array().expect("results").clone()
}

#[tokio::test]
async fn nodus_endpoints_enforce_collection_authorization() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let (victim_id, _) = create_account(pool, "victim", true).await;
        let (attacker_id, _) = create_account(pool, "attacker", false).await;

        let victim_token = create_token(pool, &victim_id).await;
        let attacker_token = create_token(pool, &attacker_id).await;

        let private_id =
            create_status_api(&state, &victim_token, "victim private", "private").await;
        let victim_event = events::append(
            pool,
            &format!("timeline:{victim_id}"),
            "status",
            &json!({ "status_id": private_id }),
        )
        .await
        .expect("append victim event");

        let victim_col = format!("timeline:{victim_id}");
        for (method, uri, body, expected) in [
            (
                "GET",
                format!("/api/v1/nodus/sync/snapshot?collection={victim_col}"),
                None,
                StatusCode::FORBIDDEN,
            ),
            (
                "GET",
                format!("/api/v1/nodus/sync/root?collection={victim_col}"),
                None,
                StatusCode::FORBIDDEN,
            ),
            (
                "POST",
                "/api/v1/nodus/sync/diff".to_owned(),
                Some(json!({ "collection": victim_col, "since": victim_event.hash })),
                StatusCode::FORBIDDEN,
            ),
            (
                "GET",
                format!("/api/v1/nodus/events?collection={victim_col}"),
                None,
                StatusCode::FORBIDDEN,
            ),
            (
                "GET",
                "/api/v1/nodus/sync/root?collection=secret:stuff".to_owned(),
                None,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "GET",
                "/api/v1/nodus/events?collection=secret:stuff".to_owned(),
                None,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "POST",
                "/api/v1/nodus/sync/diff".to_owned(),
                Some(json!({ "collection": "secret:stuff", "since": "abc" })),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "GET",
                format!("/api/v1/nodus/sync/snapshot?collection=timeline:{attacker_id}"),
                None,
                StatusCode::OK,
            ),
            (
                "GET",
                "/api/v1/nodus/sync/snapshot?collection=timeline:local".to_owned(),
                None,
                StatusCode::OK,
            ),
        ] {
            assert_nodus_collection_status(&state, &attacker_token, method, &uri, body, expected)
                .await;
        }
    })
    .await;
}

#[tokio::test]
async fn nodus_batch_status_enforces_can_view() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let (victim_id, _) = create_account(pool, "victim", true).await;
        let (attacker_id, _) = create_account(pool, "attacker", false).await;
        let (follower_id, _) = create_account(pool, "follower", false).await;
        let (recipient_id, recipient_username) = create_account(pool, "recipient", false).await;

        social::follow(pool, &follower_id, &victim_id, true, false)
            .await
            .expect("follow");
        social::accept_follow(pool, &victim_id, &follower_id)
            .await
            .expect("accept");

        let victim_token = create_token(pool, &victim_id).await;
        let attacker_token = create_token(pool, &attacker_id).await;
        let follower_token = create_token(pool, &follower_id).await;
        let recipient_token = create_token(pool, &recipient_id).await;

        let private_id =
            create_status_api(&state, &victim_token, "victim private", "private").await;
        let direct_id = create_status_api(
            &state,
            &victim_token,
            &format!("victim dm @{recipient_username}"),
            "direct",
        )
        .await;

        let attacker_results = batch_status_call(
            &state,
            &attacker_token,
            &[("p", &private_id), ("d", &direct_id)],
        )
        .await;
        assert!(attacker_results[0]["value"].is_null());
        assert_eq!(attacker_results[0]["error"], "status not found");
        assert!(attacker_results[1]["value"].is_null());
        assert_eq!(attacker_results[1]["error"], "status not found");

        let follower_results =
            batch_status_call(&state, &follower_token, &[("p", &private_id)]).await;
        assert_eq!(follower_results[0]["value"]["id"], private_id);

        let recipient_results =
            batch_status_call(&state, &recipient_token, &[("d", &direct_id)]).await;
        assert_eq!(recipient_results[0]["value"]["id"], direct_id);
    })
    .await;
}

async fn post_misskey(state: &AppState, path: &str, payload: Value) -> (StatusCode, String) {
    send(
        state,
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(payload.to_string()))
            .expect("request"),
    )
    .await
}

async fn assert_misskey_invisible(state: &AppState, label: &str, token: &str, target_mk_id: &str) {
    for (op, path, payload) in [
        (
            "show_note",
            "/api/notes/show",
            json!({ "i": token, "noteId": target_mk_id }),
        ),
        (
            "favorite_note",
            "/api/notes/favorites/create",
            json!({ "i": token, "noteId": target_mk_id }),
        ),
        (
            "unfavorite_note",
            "/api/notes/favorites/delete",
            json!({ "i": token, "noteId": target_mk_id }),
        ),
        (
            "create_reaction",
            "/api/notes/reactions/create",
            json!({ "i": token, "noteId": target_mk_id, "reaction": "👍" }),
        ),
        (
            "delete_reaction",
            "/api/notes/reactions/delete",
            json!({ "i": token, "noteId": target_mk_id }),
        ),
        (
            "renote_invisible",
            "/api/notes/create",
            json!({ "i": token, "renoteId": target_mk_id }),
        ),
        (
            "reply_invisible",
            "/api/notes/create",
            json!({ "i": token, "text": "reply", "replyId": target_mk_id }),
        ),
    ] {
        let (status, _) = post_misskey(state, path, payload).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{op} {label}");
    }
}

async fn assert_reactions_invisible(
    state: &AppState,
    label: &str,
    token_opt: Option<&str>,
    status_id: &str,
) {
    let mut list_req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/statuses/{status_id}/reactions"));
    if let Some(tok) = token_opt {
        list_req = list_req.header(header::AUTHORIZATION, format!("Bearer {tok}"));
    }
    let (status, _) = send(state, list_req.body(Body::empty()).expect("request")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "reactions list {label}");

    if let Some(tok) = token_opt {
        let (status, _) = send(
            state,
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/statuses/{status_id}/reaction"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "reaction": "👍" }).to_string()))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "reactions set {label}");

        let (status, _) = send(
            state,
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/statuses/{status_id}/reaction"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "reactions remove {label}");
    }
}

async fn create_misskey_note(
    state: &AppState,
    token: &str,
    text: &str,
    visibility: &str,
) -> String {
    let (status, body) = post_misskey(
        state,
        "/api/notes/create",
        json!({ "i": token, "text": text, "visibility": visibility }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mk create_note failed: {body}");
    let parsed: Value = serde_json::from_str(&body).expect("json");
    parsed["id"].as_str().expect("id").to_owned()
}

#[tokio::test]
async fn misskey_create_note_publishes_only_public_to_local_stream() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let (author_id, _) = create_account(pool, "author", false).await;
        let author_token = create_token(pool, &author_id).await;

        let pub_mk_id = create_misskey_note(&state, &author_token, "mk public", "public").await;
        let _ = create_misskey_note(&state, &author_token, "mk home", "home").await;
        let _ = create_misskey_note(&state, &author_token, "mk followers", "followers").await;
        let _ = create_misskey_note(&state, &author_token, "mk specified", "specified").await;

        assert_eq!(
            events::count(pool, "timeline:local")
                .await
                .expect("count timeline:local"),
            1,
            "only public notes may be published to timeline:local"
        );
        let pub_local_id = external_ids::resolve(pool, "status", &pub_mk_id)
            .await
            .expect("resolve")
            .expect("mapped");
        let logged_status_id: String = sqlx::query_scalar(
            "SELECT payload->>'status_id' FROM event_log WHERE collection = 'timeline:local'",
        )
        .fetch_one(pool)
        .await
        .expect("fetch logged status_id");
        assert_eq!(logged_status_id, pub_local_id);
    })
    .await;
}

#[tokio::test]
async fn misskey_note_endpoints_enforce_can_view() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let (author_id, _) = create_account(pool, "author", false).await;
        let (follower_id, _) = create_account(pool, "follower", false).await;
        let (stranger_id, _) = create_account(pool, "stranger", false).await;
        let (recipient_id, recipient_username) = create_account(pool, "recipient", false).await;

        social::follow(pool, &follower_id, &author_id, true, false)
            .await
            .expect("follow");

        let author_token = create_token(pool, &author_id).await;
        let follower_token = create_token(pool, &follower_id).await;
        let stranger_token = create_token(pool, &stranger_id).await;
        let recipient_token = create_token(pool, &recipient_id).await;

        let priv_mk_id =
            create_misskey_note(&state, &author_token, "mk followers", "followers").await;
        let spec_mk_id =
            create_misskey_note(&state, &author_token, "mk specified", "specified").await;

        let dm_id = create_status_api(
            &state,
            &author_token,
            &format!("mastodon dm @{recipient_username}"),
            "direct",
        )
        .await;
        let dm_mk_id = Id::new().to_string();
        external_ids::get_or_create(pool, "status", &dm_id, &dm_mk_id)
            .await
            .expect("map dm external id");

        for (label, token, target_mk_id) in [
            ("stranger-priv", &stranger_token, &priv_mk_id),
            ("stranger-spec", &stranger_token, &spec_mk_id),
            ("follower-spec", &follower_token, &spec_mk_id),
            ("follower-dm", &follower_token, &dm_mk_id),
            ("stranger-dm", &stranger_token, &dm_mk_id),
        ] {
            assert_misskey_invisible(&state, label, token, target_mk_id).await;
        }

        let (status, _) = post_misskey(
            &state,
            "/api/notes/show",
            json!({ "i": follower_token, "noteId": priv_mk_id }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = post_misskey(
            &state,
            "/api/notes/create",
            json!({ "i": follower_token, "renoteId": priv_mk_id, "visibility": "public" }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, _) = post_misskey(
            &state,
            "/api/notes/show",
            json!({ "i": recipient_token, "noteId": dm_mk_id }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    })
    .await;
}

#[tokio::test]
async fn reactions_endpoints_enforce_can_view() {
    run_db_test(|store, state| async move {
        let pool = store.pool();
        let (author_id, _) = create_account(pool, "author", false).await;
        let (follower_id, _) = create_account(pool, "follower", false).await;
        let (stranger_id, _) = create_account(pool, "stranger", false).await;
        let (recipient_id, recipient_username) = create_account(pool, "recipient", false).await;

        social::follow(pool, &follower_id, &author_id, true, false)
            .await
            .expect("follow");

        let author_token = create_token(pool, &author_id).await;
        let follower_token = create_token(pool, &follower_id).await;
        let stranger_token = create_token(pool, &stranger_id).await;
        let recipient_token = create_token(pool, &recipient_id).await;

        let priv_id = create_status_api(&state, &author_token, "private status", "private").await;
        let dm_id = create_status_api(
            &state,
            &author_token,
            &format!("mastodon dm @{recipient_username}"),
            "direct",
        )
        .await;

        for (label, token_opt, status_id) in [
            ("stranger-priv", Some(stranger_token.as_str()), &priv_id),
            ("anon-priv", None, &priv_id),
            ("follower-dm", Some(follower_token.as_str()), &dm_id),
            ("stranger-dm", Some(stranger_token.as_str()), &dm_id),
            ("anon-dm", None, &dm_id),
        ] {
            assert_reactions_invisible(&state, label, token_opt, status_id).await;
        }

        let (status, _) = send(
            &state,
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/statuses/{dm_id}/reaction"))
                .header(header::AUTHORIZATION, format!("Bearer {recipient_token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "reaction": "👍" }).to_string()))
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = send(
            &state,
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/statuses/{dm_id}/reactions"))
                .header(header::AUTHORIZATION, format!("Bearer {recipient_token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let counts: Vec<Value> = serde_json::from_str(&body).expect("json");
        assert_eq!(counts.len(), 1);
        assert_eq!(counts[0]["reaction"], "👍");

        let (status, _) = send(
            &state,
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/statuses/{dm_id}/reaction"))
                .header(header::AUTHORIZATION, format!("Bearer {recipient_token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    })
    .await;
}
