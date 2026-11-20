//! Tag pages and tag subscriptions.
//!
//! The important answers are the refusal (an unknown tag is a 404, an anonymous caller is
//! a 401) and the idempotence: following twice must not write a second row, and both
//! calls must answer 200 with the tag object.

use axum::http::StatusCode;

mod support;

use support::{
    create_account, create_status, create_token, json_of, run_db_test, send, send_anon,
};

fn path(name: &str, action: &str) -> String {
    if action.is_empty() {
        format!("/api/v1/tags/{name}")
    } else {
        format!("/api/v1/tags/{name}/{action}")
    }
}

#[tokio::test]
async fn a_tag_can_be_read_followed_and_unfollowed_idempotently() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let alice = create_account(pool, "tag_author").await;
        let bob = create_account(pool, "tag_reader").await;
        let token = create_token(pool, &bob, &["read:statuses", "write:follows"]).await;
        create_status(pool, &alice, "#Rust is good", "public", &[], &["rust"]).await;

        let (status, body) = send(&app, &token, "GET", &path("rust", ""), None).await;
        assert_eq!(status, StatusCode::OK, "tag: {body}");
        let tag = json_of(&body);
        assert_eq!(tag["name"], "rust");
        assert_eq!(tag["following"], false);
        assert!(tag["url"].as_str().is_some_and(|url| url.ends_with("/tags/rust")));

        let (status, body) = send(&app, &token, "POST", &path("rust", "follow"), None).await;
        assert_eq!(status, StatusCode::OK, "first follow: {body}");
        assert_eq!(json_of(&body)["following"], true);

        let (status, body) = send(&app, &token, "POST", &path("rust", "follow"), None).await;
        assert_eq!(status, StatusCode::OK, "second follow: {body}");
        assert_eq!(json_of(&body)["following"], true);

        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM tag_follow")
            .fetch_one(pool)
            .await
            .expect("count tag_follow");
        assert_eq!(rows, 1, "a repeat follow is not a duplicate row");

        let (status, body) = send(&app, &token, "GET", &path("rust", ""), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json_of(&body)["following"], true);

        let (status, body) = send(&app, &token, "POST", &path("rust", "unfollow"), None).await;
        assert_eq!(status, StatusCode::OK, "unfollow: {body}");
        assert_eq!(json_of(&body)["following"], false);

        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM tag_follow")
            .fetch_one(pool)
            .await
            .expect("count tag_follow");
        assert_eq!(rows, 0);
    })
    .await;
}

#[tokio::test]
async fn an_unknown_tag_is_a_404_and_an_anonymous_caller_is_a_401() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let alice = create_account(pool, "tag_unknown").await;
        let token = create_token(pool, &alice, &["read:statuses", "write:follows"]).await;

        for (method, action) in [("GET", ""), ("POST", "follow"), ("POST", "unfollow")] {
            let (status, _) = send(&app, &token, method, &path("neverused", action), None).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {action}");

            let (status, _) = send_anon(&app, method, &path("neverused", action)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {action}");
        }
    })
    .await;
}
