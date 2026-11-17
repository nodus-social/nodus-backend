//! The SDK's own types, decoded from every screen the client paints.
//!
//! `mastodon_parity.rs` proves each endpoint exists and behaves; this file proves the
//! harder contract: that the JSON this server emits still deserialises into the exact
//! types the shipped client decodes it with (`nodus-client-core`, the crate the web
//! client and the SDK share). A missing field or a renamed key fails here instead of in
//! somebody's browser as "malformed response: missing field `followed_by`".
//!
//! The whole file is skipped when `DATABASE_URL` is unset, so `cargo test` still works
//! on a machine without a database.

mod support;

use axum::http::StatusCode;
use serde_json::json;

use nodus_client_core::model::{
    Account, Context, Conversation, CustomEmoji, FeaturedTag, InstanceInfo, Language, List,
    Notification, Preferences, Relationship, Rule, ScheduledStatus, SearchResults, Status, Tag,
    Visibility,
};

use support::{
    create_account, create_status, create_token, decode, expect_ok, follow, json_of, run_db_test,
    send, send_anon,
};

/// Every endpoint the client reads, paired with the type it decodes. Kept in one test so a
/// single run tells you the whole contract, and so the list reads like the client's screen
/// map: instance, timeline, thread, account, interactions, discovery, settings.
#[tokio::test]
// One test walks the whole screen map on purpose: the contract is "the client can render
// every screen", and a per-screen split would hide which screens share a payload shape.
#[expect(
    clippy::too_many_lines,
    reason = "one walk through every screen the client paints"
)]
async fn every_screen_decodes_into_the_clients_own_types() {
    run_db_test(|store, app| async move {
        let pool = store.pool().clone();
        let reader = create_account(&pool, "reader").await;
        let author = create_account(&pool, "author").await;
        let token = create_token(&pool, &reader, &["read", "write", "follow"]).await;
        follow(&pool, &reader, &author).await;
        let status = create_status(
            &pool,
            &author,
            "<p>a post with a <a href=\"https://example.test/\">link</a></p>",
            "public",
            &[],
            &["nodus", "test"],
        )
        .await;
        let reply = create_status(&pool, &reader, "<p>a reply</p>", "public", &[], &[]).await;
        // A tag trends only once more than one account used it this week, so the trend
        // assertions below need a second author rather than a second post.
        let other = create_account(&pool, "other").await;
        let tagged = create_status(
            &pool,
            &other,
            "<p>also #nodus</p>",
            "public",
            &[],
            &["nodus"],
        )
        .await;
        // Only that it exists: the trend assertions below are what prove it counted.
        let _ = tagged;
        nodus_server_store::social::notify(&pool, &reader, "mention", &author, Some(&reply))
            .await
            .expect("notify the reader");

        // ── instance ────────────────────────────────────────────────────────
        // The SDK reads only the v2 payload (`instance_info` → `/api/v2/instance`), and
        // that is the one that must decode into its own type. v1 keeps Mastodon's older
        // spelling — `thumbnail` as a bare URL, `registrations` as a boolean — which the
        // client never parses but older tools do, so it is asserted by key instead of
        // being forced into the v2 struct.
        let (status_code, body) = send(&app, &token, "GET", "/api/v1/instance", None).await;
        let older = json_of(&expect_ok(status_code, &body, "/api/v1/instance"));
        assert_eq!(older["title"], json!("Nodus test"));
        assert!(older["thumbnail"].is_string(), "v1 keeps the bare URL");
        assert!(older["registrations"].is_boolean(), "v1 keeps the flag");
        let (status_code, body) = send(&app, &token, "GET", "/api/v2/instance", None).await;
        let instance: InstanceInfo = decode(&expect_ok(status_code, &body, "/api/v2/instance"));
        assert_eq!(instance.domain, "social.test");
        assert_eq!(instance.title, "Nodus test");
        let (status_code, body) = send(&app, &token, "GET", "/api/v1/instance/rules", None).await;
        let _: Vec<Rule> = decode(&expect_ok(status_code, &body, "/api/v1/instance/rules"));
        let (status_code, body) =
            send(&app, &token, "GET", "/api/v1/instance/languages", None).await;
        let _: Vec<Language> = decode(&expect_ok(status_code, &body, "/api/v1/instance/languages"));

        // ── accounts ────────────────────────────────────────────────────────
        let (status_code, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/accounts/{author}"),
            None,
        )
        .await;
        let account: Account = decode(&expect_ok(status_code, &body, "/api/v1/accounts/{id}"));
        assert_eq!(account.id, author);
        assert_ne!(account.avatar, "", "an account needs a picture");
        let (status_code, body) = send(
            &app,
            &token,
            "GET",
            "/api/v1/accounts/verify_credentials",
            None,
        )
        .await;
        let me: Account = decode(&expect_ok(
            status_code,
            &body,
            "/api/v1/accounts/verify_credentials",
        ));
        assert_eq!(me.id, reader);

        // A fully-qualified handle for this instance is the local account, which is what
        // makes `/accounts/social.test/reader` resolvable on the host it names.
        let qualified = format!("/api/v1/accounts/lookup?acct={}%40social.test", me.acct);
        let (lookup_status, lookup_body) = send_anon(&app, "GET", &qualified).await;
        assert_eq!(lookup_status, StatusCode::OK, "{lookup_body}");
        let looked_up: Account = decode(&lookup_body);
        assert_eq!(looked_up.id, reader);
        let (status_code, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/accounts/{author}/statuses"),
            None,
        )
        .await;
        let posts: Vec<Status> = decode(&expect_ok(status_code, &body, "…/{id}/statuses"));
        assert_eq!(posts.len(), 1);
        assert!(posts[0].content.contains("a post with a"));
        assert_eq!(posts[0].account.id, author);
        let (status_code, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/accounts/{author}/followers"),
            None,
        )
        .await;
        let _: Vec<Account> = decode(&expect_ok(status_code, &body, "…/{id}/followers"));
        let (status_code, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/accounts/{author}/following"),
            None,
        )
        .await;
        let _: Vec<Account> = decode(&expect_ok(status_code, &body, "…/{id}/following"));
        let (status_code, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/accounts/relationships?id[]={author}"),
            None,
        )
        .await;
        let relations: Vec<Relationship> =
            decode(&expect_ok(status_code, &body, "…/accounts/relationships"));
        assert!(relations[0].following);
        // The key that once broke the profile page: a client destructures `followed_by`
        // without a default, so its absence is a hard failure.
        assert!(!relations[0].followed_by && !relations[0].blocking);

        // ── timelines and threads ───────────────────────────────────────────
        let (status_code, body) = send(&app, &token, "GET", "/api/v1/timelines/home", None).await;
        let home: Vec<Status> = decode(&expect_ok(status_code, &body, "/api/v1/timelines/home"));
        assert!(home.iter().any(|post| post.id == status));
        let (status_code, body) = send_anon(&app, "GET", "/api/v1/timelines/public").await;
        let public: Vec<Status> =
            decode(&expect_ok(status_code, &body, "/api/v1/timelines/public"));
        assert!(public.iter().any(|post| post.id == status));
        let (status_code, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/statuses/{status}"),
            None,
        )
        .await;
        let post: Status = decode(&expect_ok(status_code, &body, "/api/v1/statuses/{id}"));
        assert_eq!(post.tags.len(), 2);
        assert!(post
            .url
            .as_deref()
            .unwrap_or_default()
            .starts_with("https://social.test/"));
        let (status_code, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/statuses/{status}/context"),
            None,
        )
        .await;
        let _: Context = decode(&expect_ok(status_code, &body, "…/statuses/{id}/context"));

        // ── notifications and conversations ─────────────────────────────────
        let (status_code, body) = send(&app, &token, "GET", "/api/v1/notifications", None).await;
        let notices: Vec<Notification> =
            decode(&expect_ok(status_code, &body, "/api/v1/notifications"));
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].account.id, author);
        let (status_code, body) = send(&app, &token, "GET", "/api/v1/conversations", None).await;
        let _: Vec<Conversation> = decode(&expect_ok(status_code, &body, "/api/v1/conversations"));

        // ── collections ─────────────────────────────────────────────────────
        let (status_code, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/statuses/{status}/favourite"),
            None,
        )
        .await;
        let _: Status = decode(&expect_ok(status_code, &body, "…/favourite"));
        let (status_code, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/statuses/{status}/bookmark"),
            None,
        )
        .await;
        let _: Status = decode(&expect_ok(status_code, &body, "…/bookmark"));
        let (status_code, body) = send(&app, &token, "GET", "/api/v1/favourites", None).await;
        let favourites: Vec<Status> = decode(&expect_ok(status_code, &body, "/api/v1/favourites"));
        assert_eq!(favourites.len(), 1);
        let (status_code, body) = send(&app, &token, "GET", "/api/v1/bookmarks", None).await;
        let bookmarks: Vec<Status> = decode(&expect_ok(status_code, &body, "/api/v1/bookmarks"));
        assert_eq!(bookmarks.len(), 1);

        // ── search and discovery ────────────────────────────────────────────
        let (status_code, body) = send(
            &app,
            &token,
            "GET",
            "/api/v2/search?q=nodus&type=statuses",
            None,
        )
        .await;
        let found: SearchResults = decode(&expect_ok(status_code, &body, "/api/v2/search"));
        assert!(found.statuses.iter().any(|post| post.id == status));
        let (status_code, body) = send(&app, &token, "GET", "/api/v1/trends/tags", None).await;
        let trends: Vec<Tag> = decode(&expect_ok(status_code, &body, "/api/v1/trends/tags"));
        let trending = trends
            .iter()
            .find(|tag| tag.name == "nodus")
            .unwrap_or_else(|| panic!("no nodus trend in {body}"));
        assert_eq!(
            trending.history.first().map_or("", |day| day.uses.as_str()),
            "2"
        );
        assert!(trending.url.starts_with("https://social.test/"));
        let (status_code, body) = send(&app, &token, "GET", "/api/v1/trends/statuses", None).await;
        let _: Vec<Status> = decode(&expect_ok(status_code, &body, "/api/v1/trends/statuses"));
        let (status_code, body) = send(&app, &token, "GET", "/api/v1/directory", None).await;
        let _: Vec<Account> = decode(&expect_ok(status_code, &body, "/api/v1/directory"));
        let (status_code, body) = send(&app, &token, "GET", "/api/v1/custom_emojis", None).await;
        let _: Vec<CustomEmoji> = decode(&expect_ok(status_code, &body, "/api/v1/custom_emojis"));

        // ── settings, markers, featured tags, schedule ──────────────────────
        let (status_code, body) = send(&app, &token, "GET", "/api/v1/preferences", None).await;
        let _: Preferences = decode(&expect_ok(status_code, &body, "/api/v1/preferences"));
        let (status_code, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/markers",
            Some(json!({ "home": { "last_read_id": status } })),
        )
        .await;
        // The SDK has no marker type (no client screen reads one), so the shape is
        // asserted against Mastodon's documented keys instead.
        let markers: std::collections::BTreeMap<String, serde_json::Value> =
            decode(&expect_ok(status_code, &body, "/api/v1/markers"));
        assert_eq!(markers["home"]["last_read_id"], json!(status));
        assert_eq!(markers["home"]["version"], json!(1));
        let (status_code, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/featured_tags",
            Some(json!({ "name": "nodus" })),
        )
        .await;
        let _: FeaturedTag = decode(&expect_ok(status_code, &body, "/api/v1/featured_tags"));
        let (status_code, body) = send(&app, &token, "GET", "/api/v1/featured_tags", None).await;
        let _: Vec<FeaturedTag> = decode(&expect_ok(status_code, &body, "/api/v1/featured_tags"));
        let (status_code, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/statuses",
            Some(json!({ "status": "later", "scheduled_at": "2999-01-01T00:00:00Z" })),
        )
        .await;
        let scheduled: ScheduledStatus =
            decode(&expect_ok(status_code, &body, "scheduled /api/v1/statuses"));
        assert_eq!(scheduled.params.text, "later");
        let (status_code, body) =
            send(&app, &token, "GET", "/api/v1/scheduled_statuses", None).await;
        let _: Vec<ScheduledStatus> =
            decode(&expect_ok(status_code, &body, "/api/v1/scheduled_statuses"));

        // ── posting through the client's own body ───────────────────────────
        let (status_code, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/statuses",
            Some(json!({ "status": "posted by the sdk shape", "visibility": "public" })),
        )
        .await;
        let posted: Status = decode(&expect_ok(status_code, &body, "POST /api/v1/statuses"));
        assert_eq!(posted.visibility, Visibility::Public);
        // Somebody else's post is not the reader's to delete, and that refusal is part of
        // the contract too.
        let (status_code, body) = send(
            &app,
            &token,
            "DELETE",
            &format!("/api/v1/statuses/{status}"),
            None,
        )
        .await;
        assert_eq!(status_code, StatusCode::FORBIDDEN, "body was {body}");
        let (status_code, body) = send(
            &app,
            &token,
            "DELETE",
            &format!("/api/v1/statuses/{}", posted.id),
            None,
        )
        .await;
        let deleted: Status = decode(&expect_ok(status_code, &body, "DELETE …/statuses/{id}"));
        assert_eq!(deleted.id, posted.id);

        // ── a list, end to end ──────────────────────────────────────────────
        let (status_code, body) = send(
            &app,
            &token,
            "POST",
            "/api/v1/lists",
            Some(json!({ "title": "Reading" })),
        )
        .await;
        let list: List = decode(&expect_ok(status_code, &body, "POST /api/v1/lists"));
        let (status_code, body) = send(
            &app,
            &token,
            "POST",
            &format!("/api/v1/lists/{}/accounts", list.id),
            Some(json!({ "account_ids": [author] })),
        )
        .await;
        let _ = expect_ok(status_code, &body, "…/lists/{id}/accounts");
        let (status_code, body) = send(
            &app,
            &token,
            "GET",
            &format!("/api/v1/lists/{}/accounts", list.id),
            None,
        )
        .await;
        let members: Vec<Account> = decode(&expect_ok(status_code, &body, "…/lists/{id}/accounts"));
        assert_eq!(members.len(), 1);
    })
    .await;
}

/// The paths the client calls that take no session, so a signed-out visitor can still
/// read a shared link.
#[tokio::test]
async fn the_public_reads_answer_without_a_session() {
    run_db_test(|_store, app| async move {
        for uri in [
            "/api/v1/instance",
            "/api/v2/instance",
            "/api/v1/instance/rules",
            "/api/v1/instance/languages",
            "/api/v1/custom_emojis",
            "/api/v1/trends/tags",
            "/api/v1/trends/statuses",
            "/api/v1/directory",
            "/api/v1/timelines/public",
            "/api/v2/search?q=nodus",
        ] {
            let (status, body) = send_anon(&app, "GET", uri).await;
            assert!(
                status.is_success(),
                "{uri} answered {status} without a session: {body}"
            );
        }
    })
    .await;
}

/// Anything the client might call that this server does not implement has to answer with
/// JSON, so a screen can say what went wrong instead of rendering an empty string.
#[tokio::test]
async fn an_unknown_path_explains_itself_in_json() {
    run_db_test(|_store, app| async move {
        let (status, body) = send_anon(&app, "GET", "/api/v1/definitely-not-a-route").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let value = json_of(&body);
        assert!(
            value["error"]
                .as_str()
                .unwrap_or_default()
                .contains("no route for"),
            "404 body was {body}"
        );
    })
    .await;
}
