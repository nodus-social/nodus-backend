//! Every route that answers an account document asks the batch for its picture shapes.
//!
//! `avatar_meta`/`header_meta` are the only way a client can reserve an avatar's box
//! before the bytes arrive. The batch read that fills them is separate from the account
//! row, so an endpoint that maps `AccountDto::from_row` itself silently publishes `null`
//! for a shape the instance knows. The routes below are the reader-visible surfaces that
//! answer an account document; each row says what draws the avatar. A route added without
//! `accounts_with_pictures` should be added here and will fail on its first account.

mod support;

use axum::http::StatusCode;
use axum::Router;
use serde_json::{json, Value};
use support::{
    create_account, create_status, create_token, json_of, run_db_test, send, send_anon, send_form,
};

use nodus_server_core::id::Id;
use nodus_server_store::media::{self, VariantRow};
use nodus_server_store::statuses::NewStatus;

/// Seeds a media row and a rendered variant for one profile layer, then points the
/// account at it. The dimensions are deliberately unequal so a square guess would fail.
async fn render_picture(
    store: &nodus_server_store::Store,
    id: &str,
    slot: &str,
    width: i32,
    height: i32,
) {
    let media_id = format!("{id}-{slot}-media");
    sqlx::query(
        "INSERT INTO media_attachment (id, account_id, digest, content_type, size) \
         VALUES ($1, $2, $3, 'image/png', 1)",
    )
    .bind(&media_id)
    .bind(id)
    .bind(format!("{media_id}-digest"))
    .execute(store.pool())
    .await
    .expect("insert media");
    media::upsert_variant(
        store.pool(),
        &VariantRow {
            media_id: media_id.clone(),
            layer: slot.to_owned(),
            max_edge: i64::from(width),
            object_key: format!("media/{media_id}/{slot}"),
            content_type: "image/webp".to_owned(),
            digest: format!("{media_id}-{width}"),
            size: 1,
            width: Some(width),
            height: Some(height),
            expires_at: None,
            created_at: chrono::Utc::now(),
        },
    )
    .await
    .expect("insert variant");
}

/// The reference a profile stores: the bare media id means the layer sized for the slot.
async fn give_pictures(store: &nodus_server_store::Store, id: &str) {
    render_picture(store, id, "avatar", 400, 300).await;
    render_picture(store, id, "header", 1500, 500).await;
    sqlx::query("UPDATE account SET avatar_ref = $1, header_ref = $2 WHERE id = $3")
        .bind(format!("{id}-avatar-media"))
        .bind(format!("{id}-header-media"))
        .bind(id)
        .execute(store.pool())
        .await
        .expect("point the profile at its pictures");
}

/// Fails when any account document in the payload has a null shape, and when the route
/// answered none at all: a route that stops returning accounts must not pass by silence.
fn assert_shapes(body: &Value, what: &str) {
    fn walk(value: &Value, what: &str, found: &mut usize) {
        match value {
            Value::Object(map) => {
                if map.contains_key("acct") && map.contains_key("avatar_meta") {
                    *found += 1;
                    let id = map.get("id").and_then(Value::as_str).unwrap_or("?");
                    assert!(
                        !map["avatar_meta"].is_null(),
                        "{what}: account {id} published avatar_meta null"
                    );
                    assert!(
                        !map["header_meta"].is_null(),
                        "{what}: account {id} published header_meta null"
                    );
                }
                for child in map.values() {
                    walk(child, what, found);
                }
            }
            Value::Array(items) => {
                for child in items {
                    walk(child, what, found);
                }
            }
            _ => {}
        }
    }
    let mut found = 0;
    walk(body, what, &mut found);
    assert!(found > 0, "{what}: answered no account document");
}

async fn check(app: &Router, token: Option<&str>, method: &str, uri: &str, what: &str) {
    let (status, body) = match token {
        Some(token) => send(app, token, method, uri, None).await,
        None => send_anon(app, method, uri).await,
    };
    assert_eq!(status, StatusCode::OK, "{what} {uri}: {body}");
    assert_shapes(&json_of(&body), what);
}

#[tokio::test]
async fn every_reader_visible_route_that_answers_an_account_asks_for_its_picture_shapes() {
    run_db_test(|store, app| async move {
        let owner = create_account(store.pool(), "shapes-owner").await;
        let follower = create_account(store.pool(), "shapes-follower").await;
        let followed = create_account(store.pool(), "shapes-followed").await;
        let requester = create_account(store.pool(), "shapes-requester").await;
        let blocked = create_account(store.pool(), "shapes-blocked").await;
        let muted = create_account(store.pool(), "shapes-muted").await;
        for id in [&owner, &follower, &followed, &requester, &blocked, &muted] {
            give_pictures(&store, id).await;
        }
        let owner_token = create_token(store.pool(), &owner, &["read", "write"]).await;
        let owner_row = store
            .account(&owner)
            .await
            .expect("account read")
            .expect("owner");
        let status = create_status(
            store.pool(),
            &owner,
            "shapes are reserved",
            "public",
            &[],
            &[],
        )
        .await;

        // The owner is locked after the accepted follower so `requester` is pending.
        nodus_server_store::social::follow(store.pool(), &follower, &owner, true, false)
            .await
            .expect("accepted follow");
        nodus_server_store::social::follow(store.pool(), &owner, &followed, true, false)
            .await
            .expect("owner follows");
        sqlx::query("UPDATE account SET locked = true WHERE id = $1")
            .bind(&owner)
            .execute(store.pool())
            .await
            .expect("lock the owner");
        nodus_server_store::social::follow(store.pool(), &requester, &owner, true, false)
            .await
            .expect("pending follow");
        nodus_server_store::social::block(store.pool(), &owner, &blocked)
            .await
            .expect("block");
        nodus_server_store::social::mute(store.pool(), &owner, &muted, true)
            .await
            .expect("mute");
        nodus_server_store::social::favourite(store.pool(), &owner, &status)
            .await
            .expect("owner favourite");
        nodus_server_store::social::favourite(store.pool(), &follower, &status)
            .await
            .expect("follower favourite");
        nodus_server_store::statuses::reblog(store.pool(), &follower, &status)
            .await
            .expect("follower reblog");
        // A context names the accounts on both sides of the thread; a reply puts the
        // follower's account into `descendants`.
        let reply_id = Id::new().to_string();
        nodus_server_store::statuses::create(
            store.pool(),
            &NewStatus {
                id: &reply_id,
                account_id: &follower,
                content: "a reply with a face",
                content_html: "a reply with a face",
                content_source: None,
                content_format: "html",
                spoiler_text: "",
                visibility: "public",
                sensitive: false,
                in_reply_to_id: Some(&status),
                in_reply_to_account_id: Some(&owner),
                reblog_of_id: None,
                language: None,
            },
            &[],
            &[owner.clone()],
            &[],
        )
        .await
        .expect("reply");
        // A conversation has participants on both sides; both must carry their shapes.
        create_status(
            store.pool(),
            &follower,
            "a direct hello",
            "direct",
            &[owner.clone()],
            &[],
        )
        .await;
        // History carries the status author, as the revisions do.
        sqlx::query(
            "INSERT INTO status_edit (status_id, content, spoiler_text, sensitive) \
             VALUES ($1, 'an earlier draft', '', false)",
        )
        .bind(&status)
        .execute(store.pool())
        .await
        .expect("insert revision");

        let (list_status, list_body) = send(
            &app,
            &owner_token,
            "POST",
            "/api/v1/lists",
            Some(json!({"title": "shapes"})),
        )
        .await;
        assert_eq!(list_status, StatusCode::OK, "{list_body}");
        let list_id = json_of(&list_body)["id"]
            .as_str()
            .expect("list id")
            .to_owned();
        let (add_status, add_body) = send(
            &app,
            &owner_token,
            "POST",
            &format!("/api/v1/lists/{list_id}/accounts"),
            Some(json!({"account_ids": [followed]})),
        )
        .await;
        assert_eq!(add_status, StatusCode::OK, "{add_body}");

        // The account itself and the two self-service answers.
        check(
            &app,
            None,
            "GET",
            &format!("/api/v1/accounts/{owner}"),
            "account show",
        )
        .await;
        check(
            &app,
            Some(&owner_token),
            "GET",
            "/api/v1/accounts/verify_credentials",
            "verify_credentials",
        )
        .await;
        check(
            &app,
            None,
            "GET",
            &format!("/api/v1/accounts/lookup?acct={}", owner_row.username),
            "account lookup",
        )
        .await;

        // The three pages a profile reader scrolls: statuses, followers, following.
        check(
            &app,
            None,
            "GET",
            &format!("/api/v1/accounts/{owner}/statuses?limit=1"),
            "account statuses",
        )
        .await;
        check(
            &app,
            None,
            "GET",
            &format!("/api/v1/accounts/{owner}/followers"),
            "followers page",
        )
        .await;
        check(
            &app,
            None,
            "GET",
            &format!("/api/v1/accounts/{owner}/following"),
            "following page",
        )
        .await;

        // Lists and requests draw a face per row.
        check(
            &app,
            Some(&owner_token),
            "GET",
            &format!("/api/v1/lists/{list_id}/accounts"),
            "list members",
        )
        .await;
        check(
            &app,
            Some(&owner_token),
            "GET",
            "/api/v1/follow_requests",
            "follow requests",
        )
        .await;
        check(&app, Some(&owner_token), "GET", "/api/v1/blocks", "blocks").await;
        check(&app, Some(&owner_token), "GET", "/api/v1/mutes", "mutes").await;

        // Discovery answers account documents directly.
        check(
            &app,
            Some(&owner_token),
            "GET",
            "/api/v2/suggestions",
            "suggestions",
        )
        .await;
        check(&app, None, "GET", "/api/v1/directory", "directory").await;
        check(
            &app,
            None,
            "GET",
            &format!("/api/v2/search?q={}&type=accounts", owner_row.username),
            "v2 search accounts",
        )
        .await;
        check(
            &app,
            None,
            "GET",
            &format!("/api/v1/search?q={}&type=accounts", owner_row.username),
            "v1 search accounts",
        )
        .await;

        // Statuses reached through a thread, a page, a timeline, favourites, history and
        // the interaction lists all paint the author (and the boosted author).
        check(
            &app,
            None,
            "GET",
            &format!("/api/v1/statuses/{status}"),
            "status show",
        )
        .await;
        check(
            &app,
            None,
            "GET",
            &format!("/api/v1/statuses/{status}/context"),
            "status context",
        )
        .await;
        check(
            &app,
            Some(&owner_token),
            "GET",
            &format!("/api/v1/statuses/{status}/history"),
            "status history",
        )
        .await;
        check(
            &app,
            Some(&owner_token),
            "GET",
            &format!("/api/v1/statuses/{status}/favourited_by"),
            "favourited_by",
        )
        .await;
        check(
            &app,
            Some(&owner_token),
            "GET",
            &format!("/api/v1/statuses/{status}/reblogged_by"),
            "reblogged_by",
        )
        .await;
        check(
            &app,
            None,
            "GET",
            "/api/v1/timelines/public",
            "public timeline",
        )
        .await;
        check(
            &app,
            Some(&owner_token),
            "GET",
            "/api/v1/timelines/home",
            "home timeline",
        )
        .await;
        check(
            &app,
            Some(&owner_token),
            "GET",
            "/api/v1/favourites",
            "favourites",
        )
        .await;
        check(
            &app,
            None,
            "GET",
            &format!("/api/v1/pages/profile/{owner}"),
            "profile page",
        )
        .await;
        check(
            &app,
            None,
            "GET",
            &format!("/api/v1/pages/status/{status}"),
            "status page",
        )
        .await;
        check(
            &app,
            Some(&owner_token),
            "GET",
            "/api/v1/conversations",
            "conversations",
        )
        .await;

        // A notification carries both its actor and the status it is about.
        let (notifications_status, notifications_body) =
            send(&app, &owner_token, "GET", "/api/v1/notifications", None).await;
        assert_eq!(notifications_status, StatusCode::OK, "{notifications_body}");
        let notifications = json_of(&notifications_body);
        assert_shapes(&notifications, "notifications");
        let notification_id = notifications[0]["id"]
            .as_str()
            .expect("notification id")
            .to_owned();
        check(
            &app,
            Some(&owner_token),
            "GET",
            &format!("/api/v1/notifications/{notification_id}"),
            "notification show",
        )
        .await;

        // A status created through the endpoint answers with its author too.
        let (create_status, create_body) = send(
            &app,
            &owner_token,
            "POST",
            "/api/v1/statuses",
            Some(json!({"status": "a newly created post"})),
        )
        .await;
        assert_eq!(create_status, StatusCode::OK, "{create_body}");
        assert_shapes(&json_of(&create_body), "status create");

        // The self-service profile write keeps the pictures the account already has.
        let (update_status, update_body) = send_form(
            &app,
            &owner_token,
            "PATCH",
            "/api/v1/accounts/update_credentials",
            &[("display_name", "Owner")],
        )
        .await;
        assert_eq!(update_status, StatusCode::OK, "{update_body}");
        assert_shapes(&json_of(&update_body), "update_credentials");
    })
    .await;
}

#[tokio::test]
async fn a_route_that_knows_no_shape_keeps_publishing_null() {
    run_db_test(|store, app| async move {
        let owner = create_account(store.pool(), "null-owner").await;
        let owner_token = create_token(store.pool(), &owner, &["read", "write"]).await;

        // The default asset has no variant row: null is the truth, not a square guess.
        let (status, body) = send(&app, &owner_token, "GET", "/api/v1/accounts/verify_credentials", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let document = json_of(&body);
        assert!(document["avatar_meta"].is_null(), "default avatar must stay null");
        assert!(document["header_meta"].is_null(), "default header must stay null");

        // A reference whose render has not landed is unknown too, on the same wired route.
        sqlx::query("UPDATE account SET avatar_ref = 'unrendered-avatar', header_ref = 'unrendered-header' WHERE id = $1")
            .bind(&owner)
            .execute(store.pool())
            .await
            .expect("point at an unrendered reference");
        let (status, body) = send(&app, &owner_token, "GET", "/api/v1/accounts/verify_credentials", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let document = json_of(&body);
        assert!(document["avatar_meta"].is_null(), "a missing variant stays null");
        assert!(document["header_meta"].is_null(), "a missing header variant stays null");

        // A remote picture is stored as a URL, so its shape is unknown to us. The
        // followers list is a wired route that must not invent one.
        let remote = create_account(store.pool(), "null-remote").await;
        sqlx::query(
            "UPDATE account SET local = false, domain = 'remote.example', \
             avatar_url = 'https://remote.example/avatar.png', \
             header_url = 'https://remote.example/header.png' WHERE id = $1",
        )
        .bind(&remote)
        .execute(store.pool())
        .await
        .expect("make the follower remote");
        nodus_server_store::social::follow(store.pool(), &remote, &owner, true, false)
            .await
            .expect("remote follows");
        let (status, body) = send_anon(&app, "GET", &format!("/api/v1/accounts/{owner}/followers")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let followers = json_of(&body);
        let remote_document = followers
            .as_array()
            .expect("followers list")
            .iter()
            .find(|account| account["id"] == json!(remote))
            .expect("the remote follower is listed");
        assert!(
            remote_document["avatar_meta"].is_null(),
            "a remote picture has no local variant shape"
        );
        assert!(remote_document["header_meta"].is_null());

        // And the account page itself keeps the same distinction.
        let (status, body) = send_anon(&app, "GET", &format!("/api/v1/accounts/{remote}")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let document = json_of(&body);
        assert!(document["avatar_meta"].is_null());
        assert!(document["header_meta"].is_null());
    })
    .await;
}
