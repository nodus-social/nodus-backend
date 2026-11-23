#![allow(clippy::doc_markdown, clippy::struct_excessive_bools)]

//! The Mastodon-compatible client API.
//!
//! One router, one error type, one state. Mounting is the caller's job: the server
//! binary nests this under `/api` so the SSR frontend owns everything else.

pub mod abuse;
pub mod accounts;
pub mod activitypub;
pub mod admin;
pub mod announcements;
pub mod appeals;
pub mod apps;
pub mod assets;
pub mod auth;
pub mod authorized_fetch;
pub mod body;
pub mod client_metadata;
pub mod collections;
pub mod conversations;
pub mod discovery;
pub mod drive;
pub mod dto;
pub mod error;
pub mod filters;
pub mod follow_requests;
pub mod guard;
pub mod highlights;
pub mod home;
pub mod html;
pub mod lists;
pub mod markers;
pub mod mastodon;
pub mod media;
pub mod meta;
pub mod miauth;
pub mod misskey;
mod misskey_page;
pub mod nodeinfo;
pub mod nodus;
pub mod notifications;
pub mod outbox;
pub mod poll_votes;
pub mod polls;
pub mod preferences;
pub mod profile_fields;
pub mod reactions;
pub mod remote;
pub mod rulewatch;
pub mod run;
pub mod schedules;
pub mod state;
pub mod statuses;
pub mod streaming;
pub mod suggestions;
pub mod tags;
pub mod user_blocks;

pub use run::run;
pub use state::{AppState, FederationKey, InstanceConfig};

use axum::routing::{get, patch, post, put};

/// Builds the router. No port, no listener: the binary owns the process, this owns the
/// surface.
#[allow(clippy::too_many_lines)] // a route table reads better as one list than as helpers
pub fn router(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/healthz", get(mastodon::healthz))
        .route("/readyz", get(mastodon::readyz))
        .route("/api/v1/apps", axum::routing::post(apps::register))
        .route("/api/v1/instance", get(mastodon::instance_v1))
        .route("/api/v2/instance", get(mastodon::instance_v2))
        .route("/api/v1/meta", get(meta::meta))
        .route("/api/v1/timelines/public", get(mastodon::public_timeline))
        .route("/api/v1/timelines/home", get(mastodon::home_timeline))
        .route("/api/v1/timelines/list/{id}", get(mastodon::list_timeline))
        .route("/api/v1/timelines/tag/{tag}", get(mastodon::tag_timeline))
        .route(
            "/api/v1/accounts/verify_credentials",
            get(mastodon::verify_credentials),
        )
        .route(
            "/api/v1/accounts/update_credentials",
            patch(accounts::update_credentials).post(accounts::update_credentials),
        )
        .route(
            "/api/v1/statuses/{id}/reaction",
            put(reactions::set).delete(reactions::remove),
        )
        .route(
            "/api/v1/accounts/{id}",
            get(accounts::show).delete(accounts::delete),
        )
        .route("/api/v1/accounts/{id}/undelete", post(accounts::undelete))
        .route("/api/v1/accounts/{id}/export", get(accounts::export))
        .route("/api/v1/accounts/lookup", get(accounts::lookup))
        .route("/api/v1/accounts/{id}/followers", get(accounts::followers))
        .route("/api/v1/accounts/{id}/following", get(accounts::following))
        .route(
            "/api/v1/accounts/{id}/follow",
            post(accounts::follow).delete(accounts::unfollow),
        )
        .route("/api/v1/accounts/{id}/unfollow", post(accounts::unfollow))
        .route(
            "/api/v1/accounts/{id}/block",
            axum::routing::post(accounts::block),
        )
        .route(
            "/api/v1/accounts/{id}/unblock",
            axum::routing::post(accounts::unblock),
        )
        .route(
            "/api/v1/accounts/{id}/mute",
            axum::routing::post(accounts::mute),
        )
        .route(
            "/api/v1/accounts/{id}/unmute",
            axum::routing::post(accounts::unmute),
        )
        .route("/api/v1/blocks", axum::routing::get(accounts::blocks))
        .route("/api/v1/mutes", axum::routing::get(accounts::mutes))
        .route(
            "/api/v1/accounts/relationships",
            get(accounts::relationships),
        )
        .route("/api/v1/statuses", post(statuses::create))
        .route(
            "/api/v1/statuses/{id}",
            get(statuses::show).delete(statuses::destroy),
        )
        .route(
            "/api/v1/statuses/{id}/favourite",
            post(statuses::favourite).delete(statuses::unfavourite),
        )
        .route(
            "/api/v1/statuses/{id}/bookmark",
            post(statuses::bookmark).delete(statuses::unbookmark),
        )
        .route(
            "/api/v1/statuses/{id}/reblog",
            post(statuses::reblog).delete(statuses::unreblog),
        )
        .route("/api/v1/statuses/{id}/context", get(statuses::context))
        .route("/api/v1/statuses/{id}/history", get(statuses::history))
        .route(
            "/api/v1/statuses/{id}/favourited_by",
            get(statuses::favourited_by),
        )
        .route(
            "/api/v1/statuses/{id}/reblogged_by",
            get(statuses::reblogged_by),
        )
        .route(
            "/api/v1/accounts/{id}/statuses",
            get(statuses::account_statuses),
        )
        .route("/api/v1/statuses/{id}/reactions", get(reactions::list))
        .merge(misskey::router())
        .merge(miauth::router())
        .merge(nodus::router())
        .merge(announcements::router())
        .merge(appeals::router())
        .merge(admin::router())
        .merge(admin::public_router())
        .merge(assets::router())
        .merge(media::router())
        .merge(filters::router())
        .merge(tags::router())
        .merge(suggestions::router())
        .merge(lists::router())
        .merge(highlights::router())
        .merge(schedules::router())
        .merge(notifications::router())
        .merge(streaming::router())
        .merge(collections::router())
        .merge(conversations::router())
        .merge(discovery::router())
        .merge(preferences::router())
        .merge(markers::router())
        .merge(drive::router())
        .merge(polls::router())
        .merge(follow_requests::router())
        .merge(user_blocks::router())
        .fallback(error::not_found_fallback)
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
    router(state.clone())
        .merge(nodeinfo::router(state.clone()))
        .merge(activitypub::router(state.clone()))
        // Secure mode wraps the whole root surface rather than each ActivityPub
        // handler: a read can arrive as `/users/alice`, as `/actor`, or as an
        // `Accept: application/activity+json` request to a status or account URL, and
        // one place to decide is one place to keep the bypass rule in step.
        .layer(axum::middleware::from_fn_with_state(
            state,
            authorized_fetch::require_signature,
        ))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;
    use nodus_server_store::Store;

    fn instance_config() -> InstanceConfig {
        InstanceConfig {
            domain: "social.test".to_owned(),
            base_url: "https://social.test".to_owned(),
            title: "Nodus test".to_owned(),
            description: "A test instance".to_owned(),
            contact_email: None,
            api_version: "4.3.0".to_owned(),
            version: "0.1.0".to_owned(),
            registrations_open: false,
        }
    }

    fn state() -> AppState {
        // Lazy pool: these tests assert routing and serialisation, not queries, so no
        // database is opened. `/readyz` is the one endpoint that touches it, and it is
        // asserted to fail closed.
        let store = Store::connect_lazy("postgres://nodus:nodus@127.0.0.1:1/nodus", 1);
        AppState::new(store, instance_config())
    }

    /// A migrated schema of its own, the way the integration harness builds one. An
    /// endpoint that reads a table cannot be asserted against the lazy pool above, and
    /// asserting it against the shared database would make the test depend on whatever
    /// that database happens to hold. `None` when no database is configured, so the
    /// suite still builds and runs without one.
    async fn migrated_state() -> Option<(AppState, sqlx::PgPool, String)> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let admin = Store::connect(&url, 1).await.expect("connect to postgres");
        let schema = format!("pgunit_{}", nodus_server_core::id::Id::new()).to_lowercase();
        sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
            .execute(admin.pool())
            .await
            .expect("create isolated test schema");
        let separator = if url.contains('?') { '&' } else { '?' };
        let store = Store::connect(
            &format!("{url}{separator}options=-csearch_path%3D{schema}%2Cpublic"),
            2,
        )
        .await
        .expect("connect isolated store");
        store.migrate().await.expect("run migrations");
        Some((
            AppState::new(store, instance_config()),
            admin.pool().clone(),
            schema,
        ))
    }

    async fn get_json(path: &str) -> (StatusCode, String) {
        get_json_with(state(), path).await
    }

    async fn get_json_with(state: AppState, path: &str) -> (StatusCode, String) {
        let response = router(state)
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
        // The document carries the rules, which are a table, so this one needs a store.
        let Some((state, admin, schema)) = migrated_state().await else {
            return;
        };
        let (status, body) = get_json_with(state, "/api/v2/instance").await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert!(body.contains(r#""version":"4.3.0""#), "body was {body}");
        assert!(body.contains(r#""domain":"social.test""#));
        // Limits come from the same constants the server enforces.
        assert!(body.contains(r#""max_characters":500"#));
        assert!(
            body.contains(r#""rules":[]"#),
            "an instance starts with no rules: {body}"
        );
        let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
            .execute(&admin)
            .await;
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
    async fn lists_require_a_token() {
        let response = router(state())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/lists")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn filters_require_a_token() {
        let response = router(state())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v2/filters")
                    .body(Body::empty())
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
