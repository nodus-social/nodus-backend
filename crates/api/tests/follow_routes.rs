//! Both spellings of the follow routes, against a real schema.
//!
//! Mastodon clients post to `POST …/follow` and `POST …/unfollow`; older clients and
//! this instance's own REST surface also use `DELETE …/follow`. The two unfollow
//! spellings must remove the same edge, and repeating the action must stay a 200.

mod support;

use serde_json::Value;

use support::{create_account, create_status, create_token, expect_ok, run_db_test, send};

fn status_ids(page: &str) -> Vec<String> {
    serde_json::from_str::<Vec<Value>>(page)
        .expect("timeline page")
        .into_iter()
        .filter_map(|status| status["id"].as_str().map(str::to_owned))
        .collect()
}

async fn following(app: &axum::Router, token: &str, target: &str) -> bool {
    let (status, body) = send(
        app,
        token,
        "GET",
        &format!("/api/v1/accounts/relationships?id[]={target}"),
        None,
    )
    .await;
    let body = expect_ok(status, &body, "GET …/accounts/relationships");
    let relationships: Value = serde_json::from_str(&body).expect("relationship list");
    relationships[0]["following"]
        .as_bool()
        .expect("following is a boolean")
}

#[tokio::test]
async fn post_unfollow_removes_the_edge_and_repeats_cleanly() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let target = create_account(&pool, "target").await;
        let token = create_token(&pool, &reader, &["read", "write", "follow"]).await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/accounts/{target}/follow"),
            None,
        )
        .await;
        expect_ok(status, &body, "POST …/follow");
        assert!(following(&app, &token, &target).await, "the follow took");

        let post = create_status(&pool, &target, "hello", "public", &[], &[]).await;
        let (status, page) = send(&app, &token, "GET", "/api/v1/timelines/home", None).await;
        let page = expect_ok(status, &page, "GET /timelines/home");
        assert!(
            status_ids(&page).contains(&post),
            "a followed account's post is on the home timeline"
        );

        // The spelling the pinned client uses: `POST …/unfollow`, not `DELETE …/follow`.
        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/accounts/{target}/unfollow"),
            None,
        )
        .await;
        let body = expect_ok(status, &body, "POST …/unfollow");
        let relationship: Value = serde_json::from_str(&body).expect("relationship");
        assert_eq!(
            relationship["following"], false,
            "POST …/unfollow reports the edge as gone"
        );
        assert!(
            !following(&app, &token, &target).await,
            "POST …/unfollow removed the edge"
        );

        // Fan-out happens on create, so the proof is that the next post does not reach
        // this reader. Entries fanned out before the unfollow are not purged yet; the
        // follow-up change purges them from the home ZSET and `timeline_entry` on the
        // unfollow write rather than filtering on every read.
        let later = create_status(&pool, &target, "after the unfollow", "public", &[], &[]).await;
        let (status, page) = send(&app, &token, "GET", "/api/v1/timelines/home", None).await;
        let page = expect_ok(status, &page, "GET /timelines/home after unfollow");
        assert!(
            !status_ids(&page).contains(&later),
            "an unfollowed account's new post is not fanned out to the reader"
        );

        // Unfollowing someone you do not follow is a no-op the API still answers, not a 500.
        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/accounts/{target}/unfollow"),
            None,
        )
        .await;
        let body = expect_ok(status, &body, "second POST …/unfollow");
        let relationship: Value = serde_json::from_str(&body).expect("relationship");
        assert_eq!(
            relationship["following"], false,
            "a repeated unfollow is idempotent"
        );
    })
    .await;
}

#[tokio::test]
async fn delete_follow_keeps_the_legacy_spelling_working() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let target = create_account(&pool, "target").await;
        let token = create_token(&pool, &reader, &["read", "write", "follow"]).await;

        let (status, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/accounts/{target}/follow"),
            None,
        )
        .await;
        expect_ok(status, &body, "POST …/follow");

        let (status, body) = send(
            &app,
            &token,
            "DELETE",
            &format!("/api/v1/accounts/{target}/follow"),
            None,
        )
        .await;
        let body = expect_ok(status, &body, "DELETE …/follow");
        let relationship: Value = serde_json::from_str(&body).expect("relationship");
        assert_eq!(relationship["following"], false);
        assert!(!following(&app, &token, &target).await);
    })
    .await;
}
