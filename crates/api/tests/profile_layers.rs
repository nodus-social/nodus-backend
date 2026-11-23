//! What a request for a profile layer answers when the layer was never rendered.
//!
//! A picture chosen before the profile layers existed has no `avatar`/`header` variant,
//! and a replica's variant directory can be empty even when the catalogue row exists. The
//! media route has to keep such a profile working without ever answering a `*_static`
//! field with an animation, and it has to make the real layer exist for the next request.

mod support;

#[path = "profile_layers/fixture.rs"]
mod fixture;

use axum::http::StatusCode;

use fixture::{count_frames, get, probe_edge, read_variant, wait_for_layer, Fixture};
use support::{create_account, run_db_test};

#[tokio::test]
async fn an_avatar_with_only_a_preview_answers_it_and_renders_the_real_layer() {
    let Some(fixture) = Fixture::new().await else {
        return;
    };
    run_db_test(|store, _app| async move {
        let account = create_account(store.pool(), "layers").await;
        let id = fixture.store_picture(&store, &account).await;
        let media = fixture.router(&store);

        let (status, _, body) = get(&media, &format!("/media/{id}/avatar")).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a profile is never broken by a missing layer"
        );
        assert_eq!(body, fixture.preview, "the preview is already the picture");

        let avatar = wait_for_layer(&store, &id, "avatar")
            .await
            .expect("the request renders the layer behind its answer");
        let (status, content_type, body) = get(&media, &format!("/media/{id}/avatar")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type.as_deref(), Some("image/webp"));
        assert_eq!(body, read_variant(&fixture.variants, &avatar).await);
        assert_ne!(
            body, fixture.preview,
            "the next request finds the real layer"
        );
    })
    .await;
}

#[tokio::test]
async fn a_still_layer_is_rendered_rather_than_answered_with_the_animation() {
    let Some(fixture) = Fixture::new().await else {
        return;
    };
    run_db_test(|store, _app| async move {
        let account = create_account(store.pool(), "still").await;
        let id = fixture.store_picture(&store, &account).await;
        let media = fixture.router(&store);

        let (status, content_type, body) = get(&media, &format!("/media/{id}/avatar_static")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type.as_deref(), Some("image/webp"));
        assert_ne!(
            body, fixture.gif,
            "the still field must not answer the original animation"
        );
        assert_eq!(
            count_frames(&body),
            1,
            "an animated answer would defeat the whole field"
        );

        // The header has no variants at all, which is the older shape: both header fields
        // must still resolve, and the still one must still be one frame.
        let (status, _, _) = get(&media, &format!("/media/{id}/header")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, content_type, body) = get(&media, &format!("/media/{id}/header_static")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type.as_deref(), Some("image/webp"));
        assert_eq!(count_frames(&body), 1);
    })
    .await;
}

#[tokio::test]
async fn the_rendered_layers_are_the_profile_sizes() {
    let Some(fixture) = Fixture::new().await else {
        return;
    };
    run_db_test(|store, _app| async move {
        let account = create_account(store.pool(), "edges").await;
        let id = fixture.store_picture(&store, &account).await;
        let media = fixture.router(&store);

        // The animated field starts the render behind its answer; the still one renders
        // before answering, so both layers exist once the header request returns.
        let (status, _, _) = get(&media, &format!("/media/{id}/avatar")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = get(&media, &format!("/media/{id}/header_static")).await;
        assert_eq!(status, StatusCode::OK);

        let avatar = wait_for_layer(&store, &id, "avatar")
            .await
            .expect("avatar layer");
        let header = wait_for_layer(&store, &id, "header")
            .await
            .expect("header layer");
        assert_eq!(
            probe_edge(&read_variant(&fixture.variants, &avatar).await).await,
            400,
            "an avatar is drawn at 400 px"
        );
        assert_eq!(
            probe_edge(&read_variant(&fixture.variants, &header).await).await,
            1500,
            "a header is drawn at 1500 px"
        );
    })
    .await;
}
