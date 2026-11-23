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

use nodus_server_store::media::{self, VariantRow};

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

/// Seeds two media rows and the variant shapes a rendered profile layer records.
async fn store_picture_sizes(store: &nodus_server_store::Store, id: &str) {
    for media_id in ["avatar-media", "header-media"] {
        sqlx::query(
            "INSERT INTO media_attachment (id, account_id, digest, content_type, size) \
             VALUES ($1, $2, $3, 'image/png', 1)",
        )
        .bind(media_id)
        .bind(id)
        .bind(format!("{media_id}-digest"))
        .execute(store.pool())
        .await
        .expect("insert media");
    }
    for (media_id, layer, max_edge, width, height) in [
        ("avatar-media", "avatar", 400, 400, 300),
        ("header-media", "header", 1500, 1500, 500),
    ] {
        media::upsert_variant(
            store.pool(),
            &VariantRow {
                media_id: media_id.to_owned(),
                layer: layer.to_owned(),
                max_edge,
                object_key: format!("media/{media_id}/{layer}"),
                content_type: "image/webp".to_owned(),
                digest: format!("{media_id}-{max_edge}"),
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
        assert!(
            document["avatar_meta"].is_null(),
            "the default asset has no rendered shape; null, not a square guess"
        );
        assert!(document["header_meta"].is_null());
    })
    .await;
}

#[tokio::test]
async fn a_rendered_profile_picture_reports_the_variant_shape_in_both_meta_fields() {
    run_db_test(|store, app| async move {
        let id = create_account(store.pool(), "sized").await;
        store_picture_sizes(&store, &id).await;
        store_references(&store, &id, "avatar-media", "header-media").await;

        let document = account(&app, &id).await;
        assert_eq!(document["avatar_meta"]["original"]["width"], json!(400));
        assert_eq!(document["avatar_meta"]["original"]["height"], json!(300));
        assert_eq!(
            document["avatar_meta"]["original"]["size"],
            json!("400x300")
        );
        assert!(
            (document["avatar_meta"]["original"]["aspect"]
                .as_f64()
                .expect("aspect")
                - 4.0 / 3.0)
                .abs()
                < f64::EPSILON,
            "aspect is width over height, which is what reserves the box"
        );
        assert!(
            document["avatar_meta"]["small"].is_null(),
            "one profile rendition exists, so there is no second size to name"
        );

        assert_eq!(document["header_meta"]["original"]["width"], json!(1500));
        assert_eq!(document["header_meta"]["original"]["height"], json!(500));
        assert_eq!(
            document["header_meta"]["original"]["size"],
            json!("1500x500")
        );
    })
    .await;
}

#[tokio::test]
async fn a_remote_account_reports_no_picture_shape() {
    run_db_test(|store, app| async move {
        let id = create_account(store.pool(), "remote").await;
        sqlx::query(
            "UPDATE account SET local = false, domain = 'remote.example', \
             avatar_url = 'https://remote.example/avatar.png' WHERE id = $1",
        )
        .bind(&id)
        .execute(store.pool())
        .await
        .expect("make the account remote");

        let document = account(&app, &id).await;
        assert_eq!(
            document["avatar"],
            json!("https://remote.example/avatar.png"),
            "the URL still comes from the remote profile"
        );
        assert!(
            document["avatar_meta"].is_null(),
            "we hold no variant row for a remote picture"
        );
        assert!(document["header_meta"].is_null());
    })
    .await;
}
