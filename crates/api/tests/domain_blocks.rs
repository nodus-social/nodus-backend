//! A person's own domain blocks, end to end: the list, the shapes, and the timelines.

mod support;

use axum::http::StatusCode;
use serde_json::json;

use nodus_server_store::accounts::{self, RemoteAccount};
use nodus_server_store::social;

use support::{
    create_account, create_status, create_token, expect_ok, follow, json_of, run_db_test, send,
    send_anon,
};

#[tokio::test]
async fn a_domain_block_hides_its_posts_from_the_reader_who_asked() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let reader = create_account(pool, "domain-reader").await;
        let token = create_token(pool, &reader, &["read", "write"]).await;
        let remote = accounts::upsert_remote(
            pool,
            &RemoteAccount {
                uri: "https://blocked.test/users/author",
                username: "author",
                domain: "blocked.test",
                display_name: "Author",
                note: "",
                avatar_url: None,
                header_url: None,
                inbox_url: Some("https://blocked.test/users/author/inbox"),
                shared_inbox_url: None,
                public_key_pem: None,
                locked: false,
                bot: false,
            },
        )
        .await
        .expect("remote account");
        follow(pool, &reader, &remote.id).await;
        let status =
            create_status(pool, &remote.id, "from a blocked host", "public", &[], &[]).await;
        social::notify(pool, &reader, "mention", &remote.id, Some(&status))
            .await
            .expect("notification");

        // The post and the notification are there before anything is blocked.
        let (code, body) = send(&app, &token, "GET", "/api/v1/timelines/home", None).await;
        let home = expect_ok(code, &body, "/api/v1/timelines/home");
        assert!(json_of(&home).to_string().contains(&status), "home: {home}");
        let (code, body) = send_anon(&app, "GET", "/api/v1/timelines/public?local=false").await;
        let public_anon = expect_ok(code, &body, "/api/v1/timelines/public");
        assert!(json_of(&public_anon).to_string().contains(&status));
        let (code, body) = send(&app, &token, "GET", "/api/v1/notifications", None).await;
        let notifications = expect_ok(code, &body, "/api/v1/notifications");
        assert!(json_of(&notifications).to_string().contains(&status));

        let add = send(
            &app,
            &token,
            "POST",
            "/api/v2/domain_blocks",
            Some(json!({"domain": "Blocked.Test.", "reject_media": true, "reject_reports": true})),
        )
        .await;
        assert_eq!(add.0, StatusCode::OK, "add: {}", add.1);
        assert!(
            add.1.is_empty(),
            "Mastodon answers an empty body: {:?}",
            add.1
        );

        // v1 is strings; v2 is objects; neither leaks the other shape.
        let v1 = send(&app, &token, "GET", "/api/v1/domain_blocks", None).await;
        assert_eq!(v1.0, StatusCode::OK, "v1: {}", v1.1);
        assert_eq!(json_of(&v1.1), json!(["blocked.test"]));
        let v2 = send(&app, &token, "GET", "/api/v2/domain_blocks", None).await;
        assert_eq!(v2.0, StatusCode::OK, "v2: {}", v2.1);
        let v2 = json_of(&v2.1);
        assert_eq!(v2[0]["domain"], "blocked.test");
        assert_eq!(v2[0]["reject_media"], true);
        assert_eq!(v2[0]["reject_reports"], true);
        assert_eq!(
            v2[0]["digest"].as_str().map(str::len),
            Some(64),
            "digest: {v2}"
        );

        // The reader loses the post everywhere a personal block applies.
        let (code, body) = send(&app, &token, "GET", "/api/v1/timelines/home", None).await;
        let home = expect_ok(code, &body, "/api/v1/timelines/home");
        assert!(
            !json_of(&home).to_string().contains(&status),
            "home: {home}"
        );
        let (code, body) = send(
            &app,
            &token,
            "GET",
            "/api/v1/timelines/public?local=false",
            None,
        )
        .await;
        let public_auth = expect_ok(code, &body, "/api/v1/timelines/public");
        assert!(!json_of(&public_auth).to_string().contains(&status));
        let (code, body) = send(&app, &token, "GET", "/api/v1/notifications", None).await;
        let notifications = expect_ok(code, &body, "/api/v1/notifications");
        assert!(!json_of(&notifications).to_string().contains(&status));

        // An anonymous public reader has no personal list, so the post stays visible.
        let (code, body) = send_anon(&app, "GET", "/api/v1/timelines/public?local=false").await;
        let public_anon = expect_ok(code, &body, "/api/v1/timelines/public");
        assert!(json_of(&public_anon).to_string().contains(&status));

        // A repeated add is idempotent, in either API version.
        let again = send(
            &app,
            &token,
            "POST",
            "/api/v1/domain_blocks",
            Some(json!({"domain": "blocked.test"})),
        )
        .await;
        assert_eq!(again.0, StatusCode::OK, "duplicate: {}", again.1);
        let v1 = send(&app, &token, "GET", "/api/v1/domain_blocks", None).await;
        assert_eq!(json_of(&v1.1), json!(["blocked.test"]));

        for (host, why) in [
            ("https://evil.test/x", "a URL is not a host"),
            ("evil.test:8080", "a port is not part of a host"),
            ("social.test", "this instance's own domain"),
        ] {
            let refused = send(
                &app,
                &token,
                "POST",
                "/api/v2/domain_blocks",
                Some(json!({"domain": host})),
            )
            .await;
            assert_eq!(
                refused.0,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{why}: {}",
                refused.1
            );
            assert!(!refused.1.is_empty(), "the refusal must explain itself");
        }

        // Deleting brings the post back to a fresh page, and deleting a host that is not
        // blocked answers the same 200 upstream does.
        let remove = send(
            &app,
            &token,
            "DELETE",
            "/api/v2/domain_blocks?domain=blocked.test",
            None,
        )
        .await;
        assert_eq!(remove.0, StatusCode::OK, "remove: {}", remove.1);
        let (code, body) = send(&app, &token, "GET", "/api/v1/timelines/home", None).await;
        let home = expect_ok(code, &body, "/api/v1/timelines/home");
        assert!(json_of(&home).to_string().contains(&status), "home: {home}");
        let remove_again = send(
            &app,
            &token,
            "DELETE",
            "/api/v1/domain_blocks?domain=blocked.test",
            None,
        )
        .await;
        assert_eq!(
            remove_again.0,
            StatusCode::OK,
            "remove again: {}",
            remove_again.1
        );

        // No token, no list.
        let anonym = send_anon(&app, "GET", "/api/v1/domain_blocks").await;
        assert_eq!(anonym.0, StatusCode::UNAUTHORIZED);
        let anonym_post = send_anon(&app, "POST", "/api/v2/domain_blocks").await;
        assert_eq!(anonym_post.0, StatusCode::UNAUTHORIZED);
    })
    .await;
}
