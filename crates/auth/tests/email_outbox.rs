//! Registration and the transactional mail outbox, against a real Postgres.
//!
//! The sender is replaced by a fake transport, so these tests see exactly what the worker
//! would see without opening a socket. Each test owns a schema and the file is skipped
//! when `DATABASE_URL` is unset, like `registration.rs`.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use nodus_auth::outbox::{deliver_due, MAX_ATTEMPTS};
use nodus_auth::store::PgAuthStore;
use nodus_auth::{AppState, EmailConfirmation};
use nodus_mail::{Error, Message, SendFuture, Transport};
use sqlx::PgPool;
use tower::ServiceExt;

mod support;

use support::{config, run_db_test};

fn app(pool: &PgPool, mail: bool) -> axum::Router {
    let state = AppState::new(PgAuthStore::new(pool.clone()), config());
    let state = if mail {
        state.with_email_confirmation(EmailConfirmation {
            base_url: "https://social.test".to_owned(),
        })
    } else {
        state
    };
    nodus_auth::router(state)
}

/// Registers and returns the `nodus_csrf` cookie and CSRF token a browser would hold.
async fn register(app: &axum::Router) -> (StatusCode, String) {
    let request = Request::builder()
        .uri("/auth/register")
        .body(Body::empty())
        .expect("build request");
    let response = app.clone().oneshot(request).await.expect("send request");
    let cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| value.strip_prefix("nodus_csrf="))
        .map(|value| value.split(';').next().unwrap_or_default().to_owned())
        .expect("csrf cookie");
    let body = response
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    let page = String::from_utf8_lossy(&body);
    let token = page
        .split("name=\"csrf_token\"")
        .nth(1)
        .and_then(|rest| rest.split("value=\"").nth(1))
        .and_then(|rest| rest.split('"').next())
        .expect("csrf field")
        .to_owned();
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("csrf_token", &token)
        .append_pair("username", "Ada_Lovelace")
        .append_pair("email", "ada@example.test")
        .append_pair("password", "correct horse battery")
        .append_pair("password_confirmation", "correct horse battery")
        .finish();
    let request = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header(header::COOKIE, format!("nodus_csrf={cookie}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form))
        .expect("build request");
    let response = app.clone().oneshot(request).await.expect("send request");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

struct Recording(Arc<Mutex<Vec<Message>>>);

impl Transport for Recording {
    fn send<'a>(&'a self, message: &'a Message) -> SendFuture<'a> {
        Box::pin(async move {
            self.0.lock().expect("lock").push(message.clone());
            Ok(())
        })
    }
}

struct AlwaysFails;

impl Transport for AlwaysFails {
    fn send<'a>(&'a self, _message: &'a Message) -> SendFuture<'a> {
        Box::pin(async { Err(Error::Transport("connection refused".into())) })
    }
}

type Row = (String, Option<String>, Option<String>, i32);

async fn queue_state(pool: &PgPool) -> (i64, i64, Vec<Row>) {
    let outbox: i64 = sqlx::query_scalar("SELECT count(*) FROM email_outbox")
        .fetch_one(pool)
        .await
        .expect("count outbox");
    let confirmations: i64 = sqlx::query_scalar("SELECT count(*) FROM email_confirmation")
        .fetch_one(pool)
        .await
        .expect("count confirmations");
    let rows: Vec<Row> =
        sqlx::query_as("SELECT body_text, sent_at::text, last_error, attempts FROM email_outbox")
            .fetch_all(pool)
            .await
            .expect("read outbox");
    (outbox, confirmations, rows)
}

#[tokio::test]
async fn without_a_sender_registration_queues_nothing_and_still_answers() {
    run_db_test(|pool| async move {
        let app = app(&pool, false);
        let (status, body) = register(&app).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
        let (outbox, confirmations, _) = queue_state(&pool).await;
        assert_eq!((outbox, confirmations), (0, 0));
    })
    .await;
}

#[tokio::test]
async fn registration_queues_one_mail_in_the_account_transaction() {
    run_db_test(|pool| async move {
        let app = app(&pool, true);
        let (status, body) = register(&app).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
        let (outbox, confirmations, rows) = queue_state(&pool).await;
        assert_eq!((outbox, confirmations), (1, 1));
        let (text, sent_at, last_error, attempts) = &rows[0];
        assert!(sent_at.is_none() && last_error.is_none() && *attempts == 0);
        assert!(text.contains("https://social.test/auth/confirm/"), "{text}");
        assert!(text.contains("ada_lovelace"), "{text}");

        let token = text
            .split("/auth/confirm/")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .expect("confirmation link");
        let request = Request::builder()
            .uri(format!("/auth/confirm/{token}"))
            .body(Body::empty())
            .expect("build request");
        let response = app.clone().oneshot(request).await.expect("send request");
        assert_eq!(response.status(), StatusCode::OK);
        let confirmed: Option<String> =
            sqlx::query_scalar("SELECT confirmed_at::text FROM account_credential")
                .fetch_one(&pool)
                .await
                .expect("read confirmed_at");
        assert!(confirmed.is_some());

        let delivered = Arc::new(Mutex::new(Vec::new()));
        let report = deliver_due(&pool, &Recording(delivered.clone()))
            .await
            .expect("deliver");
        assert_eq!(report.sent, 1);
        assert_eq!(delivered.lock().expect("lock").len(), 1);
        let sent: Option<String> = sqlx::query_scalar("SELECT sent_at::text FROM email_outbox")
            .fetch_one(&pool)
            .await
            .expect("read sent_at");
        assert!(sent.is_some());
    })
    .await;
}

#[tokio::test]
async fn a_failing_transport_leaves_the_row_failed_and_the_account_untouched() {
    run_db_test(|pool| async move {
        let app = app(&pool, true);
        let (status, _) = register(&app).await;
        assert_eq!(status, StatusCode::SEE_OTHER);

        for expected in 1..=MAX_ATTEMPTS {
            let report = deliver_due(&pool, &AlwaysFails).await.expect("deliver");
            assert_eq!(report.failed, 1);
            let attempts: i32 = sqlx::query_scalar("SELECT attempts FROM email_outbox")
                .fetch_one(&pool)
                .await
                .expect("read attempts");
            assert_eq!(attempts, expected);
        }
        let (_, sent, last_error, attempts) = &queue_state(&pool).await.2[0];
        assert!(sent.is_none() && last_error.is_some() && *attempts == MAX_ATTEMPTS);

        // Exhausted rows are not retried again.
        let report = deliver_due(&pool, &AlwaysFails).await.expect("deliver");
        assert_eq!(report.failed, 0);

        let (account, confirmed): (i64, Option<String>) =
            sqlx::query_as("SELECT count(*), max(confirmed_at::text) FROM account_credential")
                .fetch_one(&pool)
                .await
                .expect("read credential");
        assert_eq!(account, 1);
        assert!(confirmed.is_none());
    })
    .await;
}
