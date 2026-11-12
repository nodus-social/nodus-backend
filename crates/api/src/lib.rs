//! The Mastodon-compatible client API.
//!
//! One router, one error type, one state. Mounting is the caller's job: the server
//! binary nests this under `/api` so the SSR frontend owns everything else.

pub mod auth;
pub mod dto;
pub mod error;
pub mod routes;
pub mod state;

pub use state::{AppState, InstanceConfig};

use axum::routing::get;

/// Builds the router. No port, no listener: the binary owns the process, this owns the
/// surface.
pub fn router(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/healthz", get(routes::healthz))
        .route("/readyz", get(routes::readyz))
        .route("/api/v1/instance", get(routes::instance_v1))
        .route("/api/v2/instance", get(routes::instance_v2))
        .route("/api/v1/timelines/public", get(routes::public_timeline))
        .route("/api/v1/timelines/home", get(routes::home_timeline))
        .route(
            "/api/v1/accounts/verify_credentials",
            get(routes::verify_credentials),
        )
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
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
            .oneshot(Request::builder().uri(path).body(Body::empty()).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let body = response.into_body().collect().await.expect("body").to_bytes();
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
        assert!(body.contains("The access token is invalid"), "body was {body}");
    }

    #[tokio::test]
    async fn a_malformed_cursor_is_422_rather_than_an_empty_page() {
        let (status, _) = get_json("/api/v1/timelines/public?max_id=not-an-id").await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn liveness_does_not_depend_on_the_database() {
        let (status, _) = get_json("/healthz").await;
        assert_eq!(status, StatusCode::OK);
    }
}
