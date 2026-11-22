//! Which layer of a profile picture an account document asks a client to fetch.
//!
//! `avatar`/`header` are the layers that may animate; `avatar_static`/`header_static` are
//! their first-frame twins. A picture is stored as a media reference, so the URL the account
//! document publishes decides whether a client ever reaches the layer sized for a profile —
//! and whether the still fields have a suffix to strip at all.

mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};
use support::{create_account, json_of, run_db_test, send_anon};

/// A media id in the shape the store mints: 26 lowercase Crockford characters.
const MEDIA_ID: &str = "01m7jgpjjwhpq6d4aygqykrsp5";

/// The account document a client reads, asserted to be the public shape.
async fn account(app: &axum::Router, id: &str) -> Value {
    let (status, body) = send_anon(app, "GET", &format!("/api/v1/accounts/{id}")).await;
    assert_eq!(status, StatusCode::OK, "body was {body}");
    json_of(&body)
}

async fn store_references(store: &nodus_server_store::Store, id: &str, avatar: &str, header: &str) {
    sqlx::query("UPDATE account SET avatar_ref = $1, header_ref = $2 WHERE id = $3")
        .bind(avatar)
        .bind(header)
        .bind(id)
        .execute(store.pool())
        .await
        .expect("point the profile at the media");
}

#[tokio::test]
async fn an_account_with_an_animated_profile_picture_is_asked_for_in_the_layer_that_is_sized_for_a_profile(
) {
    run_db_test(|store, app| async move {
        let id = create_account(store.pool(), "pictures").await;
        store_references(&store, &id, MEDIA_ID, MEDIA_ID).await;

        let document = account(&app, &id).await;
        let avatar = document["avatar"].as_str().expect("avatar");
        let avatar_static = document["avatar_static"].as_str().expect("avatar_static");
        assert_eq!(
            avatar,
            format!("https://social.test/media/{MEDIA_ID}/avatar"),
            "the profile layer is 400 px; the original is the multi-megabyte upload"
        );
        assert_eq!(
            avatar_static,
            format!("https://social.test/media/{MEDIA_ID}/avatar_static")
        );
        assert_ne!(avatar, avatar_static, "an animation is not its own still");

        let header = document["header"].as_str().expect("header");
        let header_static = document["header_static"].as_str().expect("header_static");
        assert_eq!(
            header,
            format!("https://social.test/media/{MEDIA_ID}/header")
        );
        assert_eq!(
            header_static,
            format!("https://social.test/media/{MEDIA_ID}/header_static")
        );
        assert_ne!(header, header_static, "an animation is not its own still");
    })
    .await;
}

#[tokio::test]
async fn a_legacy_reference_keeps_the_shape_it_was_stored_with() {
    run_db_test(|store, app| async move {
        let id = create_account(store.pool(), "legacy").await;

        // Rows written before the profile layers existed name the preview themselves, and a
        // reference that already names its layer must not gain a second one.
        let preview = format!("{MEDIA_ID}/preview");
        store_references(&store, &id, &preview, &preview).await;
        let document = account(&app, &id).await;
        let expected = format!("https://social.test/media/{preview}");
        assert_eq!(document["avatar"], json!(expected));
        assert_eq!(document["header"], json!(expected));
        assert_eq!(document["avatar_static"], json!(expected));

        // The shape current writes store must pass through unchanged as well.
        let layered = format!("{MEDIA_ID}/avatar");
        store_references(&store, &id, &layered, &format!("{MEDIA_ID}/header")).await;
        let document = account(&app, &id).await;
        assert_eq!(
            document["avatar"],
            json!(format!("https://social.test/media/{layered}"))
        );
    })
    .await;
}

#[tokio::test]
async fn an_account_without_a_picture_keeps_the_default_avatar() {
    run_db_test(|store, app| async move {
        let id = create_account(store.pool(), "default").await;

        let document = account(&app, &id).await;
        let default = "https://social.test/media/default-avatar.png";
        assert_eq!(document["avatar"], json!(default));
        assert_eq!(document["avatar_static"], json!(default));
        assert_eq!(document["header"], json!(""));
        assert_eq!(document["header_static"], json!(""));
    })
    .await;
}
