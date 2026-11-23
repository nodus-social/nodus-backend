//! Password reset against a real Postgres.
//!
//! The request endpoint is tested by comparing whole response bodies, not just statuses:
//! a difference of one sentence is the enumeration oracle the endpoint exists to avoid.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

#[path = "support/password_reset.rs"]
mod fixtures;
mod support;

use fixtures::{
    app, create_account, create_session, csrf, post_form, post_form_full, queued_token,
    request_reset,
};
use support::run_db_test;

#[tokio::test]
async fn unknown_address_answers_with_the_same_bytes() {
    run_db_test(|pool| async move {
        let app = app(&pool);
        create_account(&pool, "ada", "ada@example.test", "correct horse").await;
        let known = request_reset(&app, "ada@example.test").await;
        let unknown = request_reset(&app, "nobody@example.test").await;
        assert_eq!(known.0, StatusCode::OK);
        assert_eq!(known, unknown, "the answer must not reveal the lookup");
        let queued: i64 = sqlx::query_scalar("SELECT count(*) FROM email_outbox")
            .fetch_one(&pool)
            .await
            .expect("count outbox");
        assert_eq!(queued, 1);
        let links: i64 = sqlx::query_scalar("SELECT count(*) FROM password_reset")
            .fetch_one(&pool)
            .await
            .expect("count reset links");
        assert_eq!(links, 1, "only the existing address gets a link");
    })
    .await;
}

#[tokio::test]
async fn a_token_works_once() {
    run_db_test(|pool| async move {
        let app = app(&pool);
        create_account(&pool, "ada", "ada@example.test", "correct horse").await;
        request_reset(&app, "ada@example.test").await;
        let token = queued_token(&pool).await;
        let before: String = sqlx::query_scalar("SELECT password_hash FROM account_credential")
            .fetch_one(&pool)
            .await
            .expect("read old hash");
        let uri = format!("/auth/password/reset/{token}");
        let (cookie, csrf) = csrf(&app, &uri).await;
        let (status, _) = post_form(
            &app,
            &uri,
            &cookie,
            &[
                ("csrf_token", &csrf),
                ("password", "a new correct horse"),
                ("password_confirmation", "a new correct horse"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let after: String = sqlx::query_scalar("SELECT password_hash FROM account_credential")
            .fetch_one(&pool)
            .await
            .expect("read new hash");
        assert_ne!(before, after, "the stored password must change");

        let request = Request::builder()
            .uri(&uri)
            .body(Body::empty())
            .expect("build request");
        let response = app.clone().oneshot(request).await.expect("send request");
        assert_eq!(response.status(), StatusCode::GONE);
        let (status, _) = post_form(
            &app,
            &uri,
            &cookie,
            &[
                ("csrf_token", &csrf),
                ("password", "another correct horse"),
                ("password_confirmation", "another correct horse"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::GONE);
    })
    .await;
}

#[tokio::test]
async fn an_expired_token_is_gone() {
    run_db_test(|pool| async move {
        let app = app(&pool);
        create_account(&pool, "ada", "ada@example.test", "correct horse").await;
        request_reset(&app, "ada@example.test").await;
        let token = queued_token(&pool).await;
        sqlx::query("UPDATE password_reset SET expires_at = now() - interval '1 minute'")
            .execute(&pool)
            .await
            .expect("expire token");
        let uri = format!("/auth/password/reset/{token}");
        let request = Request::builder()
            .uri(&uri)
            .body(Body::empty())
            .expect("build request");
        let response = app.clone().oneshot(request).await.expect("send request");
        assert_eq!(response.status(), StatusCode::GONE);
    })
    .await;
}

#[tokio::test]
async fn a_weak_password_is_refused_by_the_registration_rule_and_keeps_the_token() {
    run_db_test(|pool| async move {
        let app = app(&pool);
        let account_id = create_account(&pool, "ada", "ada@example.test", "correct horse").await;
        request_reset(&app, "ada@example.test").await;
        let token = queued_token(&pool).await;
        let uri = format!("/auth/password/reset/{token}");
        let (cookie, csrf) = csrf(&app, &uri).await;
        let (status, page) = post_form(
            &app,
            &uri,
            &cookie,
            &[
                ("csrf_token", &csrf),
                ("password", "short"),
                ("password_confirmation", "short"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            String::from_utf8_lossy(&page).contains("at least 8 characters"),
            "registration's sentence should be used verbatim"
        );
        let used: Option<String> =
            sqlx::query_scalar("SELECT used_at::text FROM password_reset WHERE token_hash = $1")
                .bind(nodus_auth::domain::token_hash(&token))
                .fetch_one(&pool)
                .await
                .expect("read token");
        assert!(used.is_none(), "a refused password must not burn the link");

        // The same untouched token still accepts a password the rule allows.
        let (status, _) = post_form(
            &app,
            &uri,
            &cookie,
            &[
                ("csrf_token", &csrf),
                ("password", "a new correct horse"),
                ("password_confirmation", "a new correct horse"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let _ = account_id;
    })
    .await;
}

#[tokio::test]
async fn a_reset_leaves_only_the_session_it_creates() {
    run_db_test(|pool| async move {
        let app = app(&pool);
        let account_id = create_account(&pool, "ada", "ada@example.test", "correct horse").await;
        create_session(&pool, &account_id, "stolen-session-one").await;
        create_session(&pool, &account_id, "stolen-session-two").await;
        request_reset(&app, "ada@example.test").await;
        let token = queued_token(&pool).await;
        let uri = format!("/auth/password/reset/{token}");
        let (cookie, csrf) = csrf(&app, &uri).await;
        let (status, _, session) = post_form_full(
            &app,
            &uri,
            &cookie,
            &[
                ("csrf_token", &csrf),
                ("password", "a new correct horse"),
                ("password_confirmation", "a new correct horse"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);

        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT id, token_hash FROM auth_session WHERE account_id = $1")
                .bind(&account_id)
                .fetch_all(&pool)
                .await
                .expect("read sessions");
        assert_eq!(rows.len(), 1, "the two stolen sessions must be gone");

        let request = Request::builder()
            .uri("/auth/session")
            .header(header::COOKIE, "nodus_auth=stolen-session-one")
            .body(Body::empty())
            .expect("build request");
        let response = app.clone().oneshot(request).await.expect("send request");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let session = session.expect("the reset must sign the reader in");
        assert_eq!(
            rows[0].1,
            nodus_auth::domain::token_hash(&session),
            "the surviving row must be the reset's own session"
        );
        let request = Request::builder()
            .uri("/auth/session")
            .header(header::COOKIE, format!("nodus_auth={session}"))
            .body(Body::empty())
            .expect("build request");
        let response = app.clone().oneshot(request).await.expect("send request");
        assert_eq!(response.status(), StatusCode::OK);
    })
    .await;
}

#[tokio::test]
async fn a_second_request_inside_the_window_is_refused() {
    run_db_test(|pool| async move {
        let app = app(&pool);
        create_account(&pool, "ada", "ada@example.test", "correct horse").await;
        let first = request_reset(&app, "ada@example.test").await;
        assert_eq!(first.0, StatusCode::OK);
        let second = request_reset(&app, "ada@example.test").await;
        assert_eq!(
            second.0,
            StatusCode::TOO_MANY_REQUESTS,
            "{}",
            String::from_utf8_lossy(&second.1)
        );
        assert_ne!(first.1, second.1);
        let queued: i64 = sqlx::query_scalar("SELECT count(*) FROM email_outbox")
            .fetch_one(&pool)
            .await
            .expect("count outbox");
        assert_eq!(queued, 1, "a refused request must not queue mail");
    })
    .await;
}
