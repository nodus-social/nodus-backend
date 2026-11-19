//! What happened to a delivery: the queue used to fail silently, and these tests hold the
//! record it now keeps.
//!
//! The outbound HTTP is a local stub, never the network: the point is what the worker
//! stores about an answer, not that a real peer answers.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use serde_json::json;
use sqlx::PgPool;

use nodus_server_api::state::AppState;
use nodus_server_store::accounts;

mod support;

use support::{create_account, create_token, instance_config, run_db_test, send};

const TEST_PRIVATE_KEY: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCSI2vMOd4jjzdv\n\
OqnyqNI0mDuWtbI8FQMUnkjrchOqeGJwym94955BGCA/Tlu1jDIVfO40Rfx1Iere\n\
jGB3d8+Myt+db/dOHXEOkDN6DnM7v54vIKcT1CUQ77mNEueMeMWRQsyEiGqdliqZ\n\
sO4QFJUsSC6Jbx17qrdOSkYOmP/JVtaPBBobEV/1w/rNqlhWgwdB0DNWx1RuOKUb\n\
zpTSay0BfBOus4XF98syMWLkqci3n86tTG7mehc/y2/dTLnjmVpbR675TRp7CXjy\n\
SkWuXqW3ADbU+KQHGfpOuCH25TP1SZAjPs175le0PXxsF+K2Uo95I/QNmW6lf5Ww\n\
e/isyn99AgMBAAECggEAFcGJi4Pp8D1NXBUjC+naMX5LEMAdYsMgtvHBmrEHAHqf\n\
nSRmErTlLdJbqqZjEioRorql88j03Aif9gshVBKAJvkPmq6lO084GkTu2khLG3qx\n\
dVlVG6dE8A/gUyzx+oBYWVcqf2iXsWeTvAG9JKO2eZCIF78fvTNzIAgABK2pFt4f\n\
EU/eunCSDX1wPj0uVvIcf0XdS9bwt3VsQsdgAH6OBP8mM0kPCAsm1sT/Pc9L8WZY\n\
J45zpePfVDMdmQzsXWW1uPy7lxG2nd9x54JsT3RPO5blSQaKXR8wrVNnpL15ukvO\n\
Q7Bulv06gA7SZm35lt1ieOkM6PeqU9hmn5ptik87+QKBgQDJWMPt9X6pS+L+fxPo\n\
UyeXykxPSzLPvlBFBBIUICYC12C1gXAmZd9yuNN+xDDVWJEHhrIwfHwTN81x8EuU\n\
Upa8Jymrt9qrxWDRxBJppfyew0+bLp8YpBqNb/W/fJ7Vi/CRTD4rM4ZXVoV14MAm\n\
u3UlXhaqGjepYbFDyX/8p2mVlwKBgQC5zlJdB5eZNHdfveOLxSSGMCMXRT8AVG/O\n\
5rcGTltiSqWc+vUNGPvqONwCqiziEhWBtXs3QC5DNikCxE2+UYLcFzDETlbxWmHe\n\
FNQJHRhU3YYUKArYWCEV9G4dw5c9sHvO1jJx2B02MPBWuzEcW6jHrorIj0IgwzNp\n\
x3h2+P2+CwKBgClvggrDfch7XICBSGiETF6ZfDDJSfCkusIpP0sy/n+RMU7JD3pn\n\
dp+WV7f7ygztyBLjbmI6DBKsZjQvfm5MvMaFzLaRBIha+zzP+/YP+bf2e7h01Lru\n\
cqRuyQUaMVnDDcPpC9Y6KUhp/tcuZHzUERyai1GASboq558KpbMqBLmLAoGBAKGF\n\
LO44Kl4BUQCGpuca8pw//lE9Xf4gaK24vEQcG66/a2aidiHzpRJAaWlbm/bOd6mx\n\
JLKr9UtyKoaANYELhLFk63zLCSN4SXlwK77cbwlfJS4ifQMC4YgfWxY+sBvtbkMo\n\
yuNSVlqEgnky8wdO2tLy9SxR9M9cQTZkM2FhI9tvAoGAPP0iUPwESK6xNJxhrdEy\n\
1Xqp25TxWYcvTpnZ3UNZyIDrXqXRmx9OgTUmkPV4beIRQ3kG1m2d28GZFTeiMZ21\n\
m4EnFoyE8MFXyjHeuoWo05BewL0DayNAhzjQbbFW4gilW7ivHJ7lwlyMt79Ko3FX\n\
1/Lbpa+LJdioyMZEswXoDMA=\n\
-----END PRIVATE KEY-----";
const TEST_PUBLIC_KEY: &str = "\
-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkiNrzDneI483bzqp8qjS\n\
NJg7lrWyPBUDFJ5I63ITqnhicMpvePeeQRggP05btYwyFXzuNEX8dSHq3oxgd3fP\n\
jMrfnW/3Th1xDpAzeg5zO7+eLyCnE9QlEO+5jRLnjHjFkULMhIhqnZYqmbDuEBSV\n\
LEguiW8de6q3TkpGDpj/yVbWjwQaGxFf9cP6zapYVoMHQdAzVsdUbjilG86U0mst\n\
AXwTrrOFxffLMjFi5KnIt5/OrUxu5noXP8tv3Uy545laW0eu+U0aewl48kpFrl6l\n\
twA21PikBxn6Trgh9uUz9UmQIz7Ne+ZXtD18bBfitlKPeSP0DZlupX+VsHv4rMp/\n\
fQIDAQAB\n\
-----END PUBLIC KEY-----";

#[derive(Clone)]
struct Stub {
    hits: Arc<AtomicUsize>,
    status: StatusCode,
}

async fn answer(State(stub): State<Stub>) -> StatusCode {
    stub.hits.fetch_add(1, Ordering::SeqCst);
    stub.status
}

/// A local inbox that answers `status` to every POST, and counts how many it got.
async fn inbox(status: StatusCode) -> (String, Arc<AtomicUsize>) {
    let stub = Stub {
        hits: Arc::new(AtomicUsize::new(0)),
        status,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let router = Router::new()
        .route("/inbox", post(answer))
        .with_state(stub.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (format!("http://{address}/inbox"), stub.hits)
}

async fn signing_account(pool: &PgPool, label: &str) -> String {
    let id = create_account(pool, label).await;
    let username: String = sqlx::query_scalar("SELECT username FROM account WHERE id = $1")
        .bind(&id)
        .fetch_one(pool)
        .await
        .expect("username");
    accounts::set_actor_identity(
        pool,
        &id,
        &format!("https://social.test/users/{username}"),
        TEST_PUBLIC_KEY,
        TEST_PRIVATE_KEY,
        "https://social.test/inbox",
        None,
    )
    .await
    .expect("actor identity");
    id
}

async fn admin_token(pool: &PgPool) -> String {
    let id = create_account(pool, "admin").await;
    accounts::set_staff_role(pool, &id, "admin")
        .await
        .expect("staff role");
    create_token(pool, &id, &["admin:read", "admin:write"]).await
}

async fn enqueue_to(pool: &PgPool, author: &str, inbox: &str) -> String {
    let activity = json!({
        "id": format!("https://social.test/users/activities/{}", nodus_server_core::Id::new()),
        "type": "Create",
        "actor": "https://social.test/users/author",
        "object": { "type": "Note", "content": "hello" },
    });
    nodus_server_store::delivery::enqueue(pool, author, &activity, &[inbox.to_owned()])
        .await
        .expect("enqueue");
    sqlx::query_scalar("SELECT id FROM federation_delivery ORDER BY created_at DESC LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("queued id")
}

async fn force_due(pool: &PgPool) {
    sqlx::query("UPDATE federation_delivery SET next_attempt_at = now()")
        .execute(pool)
        .await
        .expect("make due");
}

type Row = (
    String,
    i32,
    Option<i32>,
    Option<String>,
    Option<chrono::DateTime<chrono::Utc>>,
);

async fn row_of(pool: &PgPool, id: &str) -> Row {
    sqlx::query_as(
        "SELECT state, attempts, last_status_code, last_error, delivered_at \
           FROM federation_delivery WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("delivery row")
}

/// Inserts a row in a chosen state, so a list/retry test does not have to drive the worker.
async fn seed(
    pool: &PgPool,
    account: &str,
    state: &str,
    host: &str,
    attempts: i32,
    age_secs: i32,
) -> String {
    let id = nodus_server_core::Id::new().to_string();
    let activity_id = format!("https://social.test/activities/{id}");
    sqlx::query(
        "INSERT INTO federation_delivery \
             (id, account_id, activity_id, inbox_url, activity, host, activity_kind, state, \
              attempts, last_status_code, next_attempt_at, created_at, delivered_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'Create', $7, $8, \
                 CASE WHEN $7 IN ('failed', 'gave_up') THEN 500 ELSE NULL END, now(), \
                 now() - make_interval(secs => $9), \
                 CASE WHEN $7 = 'delivered' THEN now() ELSE NULL END)",
    )
    .bind(&id)
    .bind(account)
    .bind(&activity_id)
    .bind(format!("https://{host}/inbox"))
    .bind(json!({ "id": activity_id, "type": "Create" }))
    .bind(host)
    .bind(state)
    .bind(attempts)
    .bind(age_secs)
    .execute(pool)
    .await
    .expect("seed delivery");
    id
}

#[tokio::test]
async fn a_server_error_is_retried_and_the_attempt_count_climbs() {
    run_db_test(|store, _app| async move {
        let pool = store.pool().clone();
        let author = signing_account(&pool, "author").await;
        let (inbox_url, hits) = inbox(StatusCode::INTERNAL_SERVER_ERROR).await;
        let id = enqueue_to(&pool, &author, &inbox_url).await;
        let state = AppState::new(store.clone(), instance_config());

        for expected in 1..=2 {
            assert!(nodus_server_api::outbox::deliver_once(&state)
                .await
                .expect("delivery"));
            let (delivery_state, attempts, status, error, delivered_at) = row_of(&pool, &id).await;
            assert_eq!(delivery_state, "failed", "a 500 is worth retrying");
            assert_eq!(attempts, expected);
            assert_eq!(status, Some(500), "error: {error:?}");
            assert!(error.expect("kept error").contains("500"));
            assert!(delivered_at.is_none(), "a failure is not a delivery");
            force_due(&pool).await;
        }
        assert_eq!(hits.load(Ordering::SeqCst), 2, "the peer saw both tries");
    })
    .await;
}

#[tokio::test]
async fn a_refused_signature_gives_up_at_once_and_keeps_the_error() {
    run_db_test(|store, _app| async move {
        let pool = store.pool().clone();
        let author = signing_account(&pool, "author").await;
        let (inbox_url, hits) = inbox(StatusCode::UNAUTHORIZED).await;
        let id = enqueue_to(&pool, &author, &inbox_url).await;
        let state = AppState::new(store.clone(), instance_config());

        assert!(nodus_server_api::outbox::deliver_once(&state)
            .await
            .expect("delivery"));
        let (delivery_state, attempts, status, error, _) = row_of(&pool, &id).await;
        assert_eq!(delivery_state, "gave_up", "a 401 will be a 401 again");
        assert_eq!(attempts, 1);
        assert_eq!(status, Some(401));
        assert!(error.expect("kept error").contains("401"));

        // Nothing about the backoff can bring it back: only an operator can.
        force_due(&pool).await;
        assert!(
            !nodus_server_api::outbox::deliver_once(&state)
                .await
                .expect("delivery"),
            "a given-up delivery is not due"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    })
    .await;
}

#[tokio::test]
async fn retrying_one_delivery_resets_its_attempts_and_leaves_an_audit_row() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let author = signing_account(&pool, "author").await;
        let token = admin_token(&pool).await;
        let (inbox_url, _) = inbox(StatusCode::UNAUTHORIZED).await;
        let id = enqueue_to(&pool, &author, &inbox_url).await;
        let state = AppState::new(store.clone(), instance_config());
        nodus_server_api::outbox::deliver_once(&state)
            .await
            .expect("delivery");

        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/admin/federation/deliveries/{id}/retry"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (delivery_state, attempts, _, _, delivered_at) = row_of(&pool, &id).await;
        assert_eq!(delivery_state, "pending");
        assert_eq!(attempts, 0, "a manual retry gets a fresh budget");
        assert!(delivered_at.is_none());

        let action: String = sqlx::query_scalar(
            "SELECT action FROM audit_log \
              WHERE target_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .expect("audit row");
        assert_eq!(action, "retry_federation_delivery");
    })
    .await;
}

#[tokio::test]
async fn retry_failed_requeues_only_failures_and_reports_the_exact_count() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let author = signing_account(&pool, "author").await;
        let token = admin_token(&pool).await;
        let failed_a = seed(&pool, &author, "failed", "a.test", 3, 40).await;
        let gave_up_a = seed(&pool, &author, "gave_up", "a.test", 8, 30).await;
        let failed_b = seed(&pool, &author, "failed", "b.test", 2, 20).await;
        let pending_b = seed(&pool, &author, "pending", "b.test", 0, 10).await;
        let delivered_a = seed(&pool, &author, "delivered", "a.test", 1, 5).await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/admin/federation/deliveries/retry-failed",
            Some(json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let answered: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(answered["requeued"], 3, "{body}");
        for id in [&failed_a, &gave_up_a, &failed_b] {
            let (delivery_state, attempts, _, _, _) = row_of(&pool, id).await;
            assert_eq!(delivery_state, "pending");
            assert_eq!(attempts, 0);
        }
        assert_eq!(row_of(&pool, &pending_b).await.0, "pending");
        assert_eq!(row_of(&pool, &delivered_a).await.0, "delivered");

        // The same operation narrowed to one host re-queues only that host's failures.
        let other = seed(&pool, &author, "gave_up", "b.test", 8, 1).await;
        let (status, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/admin/federation/deliveries/retry-failed",
            Some(json!({ "host": "b.test" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let answered: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(answered["requeued"], 1, "{body}");
        assert_eq!(row_of(&pool, &other).await.0, "pending");
    })
    .await;
}

#[tokio::test]
async fn the_list_filters_by_state_and_host_newest_first_with_counts() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let author = signing_account(&pool, "author").await;
        let token = admin_token(&pool).await;
        let older = seed(&pool, &author, "failed", "a.test", 2, 60).await;
        let newer = seed(&pool, &author, "failed", "a.test", 1, 5).await;
        seed(&pool, &author, "failed", "b.test", 3, 30).await;
        seed(&pool, &author, "gave_up", "a.test", 8, 20).await;
        seed(&pool, &author, "delivered", "b.test", 1, 10).await;

        let (status, body) = send(
            &app,
            &token,
            "GET",
            "/api/v1/admin/federation/deliveries?state=failed&host=a.test",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let document: serde_json::Value = serde_json::from_str(&body).expect("json");
        let rows = document["deliveries"].as_array().expect("deliveries");
        assert_eq!(rows.len(), 2, "{body}");
        assert_eq!(rows[0]["id"], newer.as_str(), "newest first");
        assert_eq!(rows[1]["id"], older.as_str());
        assert_eq!(rows[0]["state"], "failed");
        assert_eq!(rows[0]["host"], "a.test");
        assert_eq!(rows[0]["last_status_code"], 500);
        assert_eq!(document["counts"]["failed"], 3);
        assert_eq!(document["counts"]["gave_up"], 1);
        assert_eq!(document["counts"]["delivered"], 1);
        assert_eq!(document["counts"]["pending"], 0);
    })
    .await;
}

#[tokio::test]
async fn the_delivery_routes_are_behind_the_admin_scopes() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let account = create_account(&pool, "reader").await;
        let token = create_token(&pool, &account, &["read"]).await;
        for (method, path) in [
            ("GET", "/api/v1/admin/federation/deliveries"),
            (
                "POST",
                "/api/v1/admin/federation/deliveries/01j00000000000000000000000/retry",
            ),
            ("POST", "/api/v1/admin/federation/deliveries/retry-failed"),
        ] {
            let (status, body) = send(&app, &token, method, path, None).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {body}");
        }
    })
    .await;
}
