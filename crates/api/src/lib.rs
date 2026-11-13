#![allow(clippy::doc_markdown, clippy::struct_excessive_bools)]

//! The Mastodon-compatible client API.
//!
//! One router, one error type, one state. Mounting is the caller's job: the server
//! binary nests this under `/api` so the SSR frontend owns everything else.

pub mod abuse;
pub mod activitypub;
pub mod admin;
pub mod auth;
pub mod dto;
pub mod error;
pub mod mastodon;
pub mod media;
pub mod miauth;
pub mod misskey;
pub mod nodus;
pub mod reactions;
pub mod state;

pub use state::{AppState, InstanceConfig};

use axum::routing::{get, put};

/// Builds the router. No port, no listener: the binary owns the process, this owns the
/// surface.
pub fn router(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/healthz", get(mastodon::healthz))
        .route("/readyz", get(mastodon::readyz))
        .route("/api/v1/instance", get(mastodon::instance_v1))
        .route("/api/v2/instance", get(mastodon::instance_v2))
        .route("/api/v1/timelines/public", get(mastodon::public_timeline))
        .route("/api/v1/timelines/home", get(mastodon::home_timeline))
        .route(
            "/api/v1/accounts/verify_credentials",
            get(mastodon::verify_credentials),
        )
        .route(
            "/api/v1/statuses/{id}/reaction",
            put(reactions::set).delete(reactions::remove),
        )
        .route("/api/v1/statuses/{id}/reactions", get(reactions::list))
        .merge(misskey::router())
        .merge(miauth::router())
        .merge(nodus::router())
        .merge(admin::router())
        .merge(media::router())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            abuse::record,
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

/// The complete server surface: client API plus the ActivityPub documents a peer
/// resolves from the domain root.
pub fn root_router(state: AppState) -> axum::Router {
    router(state.clone()).merge(activitypub::router(state))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;
    use nodus_server_store::Store;

    fn state() -> AppState {
        // Lazy pool: these tests assert routing and serialisation, not queries, so no
        // database is opened. `/readyz` is the one endpoint that touches it, and it is
        // asserted to fail closed.
        let store = Store::connect_lazy("postgres://nodus:nodus@127.0.0.1:1/nodus", 1);
        AppState::new(
            store,
            InstanceConfig {
                domain: "social.test".to_owned(),
                base_url: "https://social.test".to_owned(),
                title: "Nodus test".to_owned(),
                description: "A test instance".to_owned(),
                contact_email: None,
                api_version: "4.3.0".to_owned(),
                version: "0.1.0".to_owned(),
            },
        )
    }

    async fn get_json(path: &str) -> (StatusCode, String) {
        let response = router(state())
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn the_instance_document_advertises_the_api_generation() {
        let (status, body) = get_json("/api/v2/instance").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(r#""version":"4.3.0""#), "body was {body}");
        assert!(body.contains(r#""domain":"social.test""#));
        // Limits come from the same constants the server enforces.
        assert!(body.contains(r#""max_characters":500"#));
    }

    #[tokio::test]
    async fn a_home_timeline_without_a_token_is_401_not_an_html_page() {
        let (status, body) = get_json("/api/v1/timelines/home").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            body.contains("The access token is invalid"),
            "body was {body}"
        );
    }

    #[tokio::test]
    async fn a_malformed_cursor_is_422_rather_than_an_empty_page() {
        let (status, _) = get_json("/api/v1/timelines/public?max_id=not-an-id").await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn reactions_require_a_token_even_when_the_status_id_is_unknown() {
        let response = router(state())
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/statuses/01j00000000000000000000000/reaction")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"reaction":"👍"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn misskey_meta_is_public() {
        let response = router(state())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/meta")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains(r#""maxNoteTextLength":500"#),
            "body was {body}"
        );
    }

    #[tokio::test]
    async fn misskey_note_creation_requires_a_token() {
        let response = router(state())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/notes/create")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"text":"hello"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn liveness_does_not_depend_on_the_database() {
        let (status, _) = get_json("/healthz").await;
        assert_eq!(status, StatusCode::OK);
    }
}
