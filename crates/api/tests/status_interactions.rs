//! Who favourited and who boosted a status.
//!
//! The refusal matters as much as the success: a private post must not reveal the
//! non-followers who interacted with it, and a post the viewer cannot see must be a 404
//! rather than an empty list that confirms the id.

use axum::http::StatusCode;

use nodus_server_store::{social, statuses};

mod support;

use support::{
    create_account, create_status, create_token, follow, json_of, run_db_test, send, send_anon,
};

fn path(id: &str, kind: &str) -> String {
    format!("/api/v1/statuses/{id}/{kind}")
}

fn ids(body: &str) -> Vec<String> {
    json_of(body)
        .as_array()
        .expect("an array of accounts")
        .iter()
        .map(|account| account["id"].as_str().expect("account id").to_owned())
        .collect()
}

#[tokio::test]
async fn public_status_lists_every_interaction() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let alice = create_account(pool, "interact_alice").await;
        let bob = create_account(pool, "interact_bob").await;
        let carol = create_account(pool, "interact_carol").await;
        let viewer = create_account(pool, "interact_viewer").await;
        let token = create_token(pool, &viewer, &["read:statuses"]).await;

        let id = create_status(pool, &alice, "public post", "public", &[], &[]).await;
        social::favourite(pool, &bob, &id).await.expect("favourite");
        social::favourite(pool, &carol, &id)
            .await
            .expect("favourite");
        statuses::reblog(pool, &bob, &id).await.expect("reblog");
        statuses::reblog(pool, &carol, &id).await.expect("reblog");

        let (status, body) = send(&app, &token, "GET", &path(&id, "favourited_by"), None).await;
        assert_eq!(status, StatusCode::OK, "favourited_by: {body}");
        let mut got = ids(&body);
        got.sort();
        let mut want = vec![bob.clone(), carol.clone()];
        want.sort();
        assert_eq!(got, want);

        let (status, body) = send(&app, &token, "GET", &path(&id, "reblogged_by"), None).await;
        assert_eq!(status, StatusCode::OK, "reblogged_by: {body}");
        let mut got = ids(&body);
        got.sort();
        assert_eq!(got, want);
    })
    .await;
}

#[tokio::test]
async fn private_status_hides_non_followers_and_direct_hides_outsiders() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let alice = create_account(pool, "audience_alice").await;
        let bob = create_account(pool, "audience_bob").await;
        let carol = create_account(pool, "audience_carol").await;
        follow(pool, &bob, &alice).await;

        let bob_token = create_token(pool, &bob, &["read:statuses"]).await;
        let carol_token = create_token(pool, &carol, &["read:statuses"]).await;

        let private = create_status(pool, &alice, "followers only", "private", &[], &[]).await;
        social::favourite(pool, &bob, &private)
            .await
            .expect("favourite");
        social::favourite(pool, &carol, &private)
            .await
            .expect("favourite");

        let (status, body) = send(
            &app,
            &bob_token,
            "GET",
            &path(&private, "favourited_by"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "favourited_by: {body}");
        assert_eq!(ids(&body), vec![bob.clone()]);

        // A private post is not boostable, so the boost list is empty rather than
        // leaking a non-follower whose attempt the store refused.
        let (status, body) = send(
            &app,
            &bob_token,
            "GET",
            &path(&private, "reblogged_by"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "reblogged_by: {body}");
        assert!(ids(&body).is_empty());

        // Carol cannot see the private post at all.
        let (status, _) = send(
            &app,
            &carol_token,
            "GET",
            &path(&private, "favourited_by"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = send(
            &app,
            &carol_token,
            "GET",
            &path(&private, "reblogged_by"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let direct = create_status(
            pool,
            &alice,
            "just for bob",
            "direct",
            &[bob.clone()],
            &[],
        )
        .await;
        social::favourite(pool, &bob, &direct)
            .await
            .expect("favourite");
        social::favourite(pool, &carol, &direct)
            .await
            .expect("favourite");

        let (status, body) = send(&app, &bob_token, "GET", &path(&direct, "favourited_by"), None).await;
        assert_eq!(status, StatusCode::OK, "direct favourited_by: {body}");
        assert_eq!(ids(&body), vec![bob.clone()]);

        let (status, _) = send(&app, &carol_token, "GET", &path(&direct, "favourited_by"), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    })
    .await;
}

#[tokio::test]
async fn interaction_lists_refuse_anonymous_callers() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let alice = create_account(pool, "interact_anon").await;
        let id = create_status(pool, &alice, "public post", "public", &[], &[]).await;

        for kind in ["favourited_by", "reblogged_by"] {
            let (status, _) = send_anon(&app, "GET", &path(&id, kind)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{kind}");
        }
    })
    .await;
}
