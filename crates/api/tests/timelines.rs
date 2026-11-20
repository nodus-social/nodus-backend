//! The two timeline routes the clients already call: list pages and tag pages.
//!
//! Both are reads of a page the store materialises, so the assertions are about
//! membership and visibility — a list must not answer for another account, a tag page
//! must not outlive the visibility rule that `public_page` applies, and the `Link` header
//! must describe the same window the array does.

mod support;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt;

use nodus_server_store::lists;

use support::{
    create_account, create_status, create_token, expect_ok, follow, json_of, run_db_test, send,
};

/// A GET that also hands back the `Link` header, which `send` deliberately drops.
async fn get_with_link(
    app: &Router,
    token: &str,
    uri: &str,
) -> (StatusCode, String, Option<String>) {
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("router response");
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
    (status, String::from_utf8_lossy(&bytes).into_owned(), link)
}

fn ids(body: &str) -> Vec<String> {
    json_of(body)
        .as_array()
        .expect("timeline is an array")
        .iter()
        .map(|item| item["id"].as_str().expect("status has an id").to_owned())
        .collect()
}

#[tokio::test]
async fn a_list_timeline_shows_only_its_members_and_is_404_to_everyone_else() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let owner = create_account(pool, "list_owner").await;
        let member = create_account(pool, "list_member").await;
        let outsider = create_account(pool, "list_outsider").await;
        let token = create_token(pool, &owner, &["read"]).await;

        let owner_list = lists::create(pool, &owner, "Friends", "list", false)
            .await
            .expect("create list");
        lists::add_account(pool, &owner_list.id, &member)
            .await
            .expect("add member");

        let member_status =
            create_status(pool, &member, "from the member", "public", &[], &[]).await;
        create_status(pool, &outsider, "not on the list", "public", &[], &[]).await;
        create_status(
            pool,
            &owner,
            "the owner is not a member",
            "public",
            &[],
            &[],
        )
        .await;

        let uri = format!("/api/v1/timelines/list/{}", owner_list.id);
        let (status, body) = send(&app, &token, "GET", &uri, None).await;
        let body = expect_ok(status, &body, &uri);
        assert_eq!(
            ids(&body),
            vec![member_status],
            "only the member's post: {body}"
        );

        // The same id, read by an account that does not own the list, is indistinguishable
        // from an id that names no list at all.
        let other_token = create_token(pool, &outsider, &["read"]).await;
        let (status, body) = send(&app, &other_token, "GET", &uri, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json_of(&body)["error"], "Record not found");

        let missing = "/api/v1/timelines/list/no-such-list";
        let (status, body) = send(&app, &other_token, "GET", missing, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json_of(&body)["error"], "Record not found");

        let empty = lists::create(pool, &owner, "Empty", "list", false)
            .await
            .expect("create empty list");
        let uri = format!("/api/v1/timelines/list/{}", empty.id);
        let (status, body) = send(&app, &token, "GET", &uri, None).await;
        let body = expect_ok(status, &body, &uri);
        assert_eq!(json_of(&body).as_array().map(Vec::len), Some(0), "{body}");
    })
    .await;
}

#[tokio::test]
async fn a_list_timeline_keeps_a_private_member_post_only_for_a_follower() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let owner = create_account(pool, "list_private_owner").await;
        let member = create_account(pool, "list_private_member").await;
        let token = create_token(pool, &owner, &["read"]).await;
        let list = lists::create(pool, &owner, "Private", "list", false)
            .await
            .expect("create list");
        lists::add_account(pool, &list.id, &member)
            .await
            .expect("add member");
        let private_status =
            create_status(pool, &member, "members only", "private", &[], &[]).await;
        let uri = format!("/api/v1/timelines/list/{}", list.id);

        // Membership alone is not a visibility grant.
        let (status, body) = send(&app, &token, "GET", &uri, None).await;
        let body = expect_ok(status, &body, &uri);
        assert!(ids(&body).is_empty(), "not followed yet: {body}");

        follow(pool, &owner, &member).await;
        let (status, body) = send(&app, &token, "GET", &uri, None).await;
        let body = expect_ok(status, &body, &uri);
        assert_eq!(ids(&body), vec![private_status], "{body}");
    })
    .await;
}

#[tokio::test]
async fn a_tag_timeline_matches_case_insensitively_and_never_shows_a_private_post() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let author = create_account(pool, "tag_timeline_author").await;
        let reader = create_account(pool, "tag_timeline_reader").await;
        let token = create_token(pool, &reader, &["read"]).await;

        let public = create_status(
            pool,
            &author,
            "#Nodus is a hashtag",
            "public",
            &[],
            &["nodus"],
        )
        .await;
        create_status(
            pool,
            &author,
            "#Nodus but private",
            "private",
            &[],
            &["nodus"],
        )
        .await;
        create_status(pool, &author, "#Other", "public", &[], &["other"]).await;

        let (status, body) = send(&app, &token, "GET", "/api/v1/timelines/tag/nodus", None).await;
        let body = expect_ok(status, &body, "/api/v1/timelines/tag/nodus");
        assert_eq!(
            ids(&body),
            vec![public.clone()],
            "private post must not appear: {body}"
        );

        // The tag column is `citext`: the spelling in the path does not change the page.
        let (status, body) = send(&app, &token, "GET", "/api/v1/timelines/tag/NODUS", None).await;
        let body = expect_ok(status, &body, "/api/v1/timelines/tag/NODUS");
        assert_eq!(ids(&body), vec![public], "{body}");
    })
    .await;
}

#[tokio::test]
async fn a_tag_timeline_paginates_without_duplicating_a_status() {
    run_db_test(|store, app| async move {
        let pool = store.pool();
        let author = create_account(pool, "tag_page_author").await;
        let reader = create_account(pool, "tag_page_reader").await;
        let token = create_token(pool, &reader, &["read"]).await;

        let mut expected = Vec::new();
        for index in 0..4 {
            expected.push(
                create_status(
                    pool,
                    &author,
                    &format!("#Nodus number {index}"),
                    "public",
                    &[],
                    &["nodus"],
                )
                .await,
            );
        }

        let (status, body, link) =
            get_with_link(&app, &token, "/api/v1/timelines/tag/nodus?limit=2").await;
        let body = expect_ok(status, &body, "/api/v1/timelines/tag/nodus?limit=2");
        let first_page = ids(&body);
        assert_eq!(first_page.len(), 2, "{body}");
        let link = link.expect("a full page advertises the next one");
        let next = first_page.last().expect("last id");
        assert_eq!(
            link,
            format!("</api/v1/timelines/tag/nodus?max_id={next}&limit=2>; rel=\"next\"")
        );

        let (status, body, _) = get_with_link(
            &app,
            &token,
            &format!("/api/v1/timelines/tag/nodus?max_id={next}&limit=2"),
        )
        .await;
        let body = expect_ok(status, &body, "second tag page");
        let second_page = ids(&body);
        assert_eq!(second_page.len(), 2, "{body}");

        let mut seen: Vec<String> = first_page.into_iter().chain(second_page).collect();
        seen.sort();
        seen.dedup();
        expected.sort();
        assert_eq!(seen, expected, "two pages cover every post exactly once");
    })
    .await;
}
