//! `NodeInfo` discovery: what a peer or directory crawler learns first about this instance.

mod support;

use axum::http::StatusCode;

use nodus_server_api::{root_router, AppState, InstanceConfig};

use support::{create_account, create_status, instance_config, json_of, run_db_test, send_anon};

const SCHEMA: &str = "http://nodeinfo.diaspora.software/ns/schema/2.0";

#[tokio::test]
async fn the_nodeinfo_discovery_document_points_at_the_served_document() {
    run_db_test(|_store, app| async move {
        let (status, body) = send_anon(&app, "GET", "/.well-known/nodeinfo").await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(
            json_of(&body)["links"],
            serde_json::json!([{
                "rel": SCHEMA,
                "href": "https://social.test/nodeinfo/2.0",
            }])
        );

        // The advertised href must be a route, not a promise.
        let (status, body) = send_anon(&app, "GET", "/nodeinfo/2.0").await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
    })
    .await;
}

#[tokio::test]
async fn the_nodeinfo_document_describes_the_software_protocols_and_usage() {
    run_db_test(|store, app| async move {
        let poster = create_account(store.pool(), "nodeinfo-poster").await;
        create_account(store.pool(), "nodeinfo-lurker").await;
        create_status(store.pool(), &poster, "hello", "public", &[], &[]).await;

        let (status, body) = send_anon(&app, "GET", "/nodeinfo/2.0").await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        let document = json_of(&body);
        assert_eq!(document["version"], "2.0");
        assert_eq!(document["software"]["name"], "nodus");
        assert_eq!(document["software"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(document["protocols"], serde_json::json!(["activitypub"]));
        assert_eq!(
            document["services"],
            serde_json::json!({ "inbound": [], "outbound": [] })
        );
        assert_eq!(document["metadata"], serde_json::json!({}));
        assert_eq!(document["usage"]["users"]["total"], 2);
        assert_eq!(document["usage"]["users"]["activeMonth"], 1);
        assert_eq!(document["usage"]["users"]["activeHalfyear"], 1);
        assert_eq!(document["usage"]["localPosts"], 1);
    })
    .await;
}

#[tokio::test]
async fn nodeinfo_open_registrations_follow_the_configuration() {
    run_db_test(|store, closed| async move {
        let (status, body) = send_anon(&closed, "GET", "/nodeinfo/2.0").await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(json_of(&body)["openRegistrations"], false);

        let open = root_router(AppState::new(
            store,
            InstanceConfig {
                registrations_open: true,
                ..instance_config()
            },
        ));
        let (status, body) = send_anon(&open, "GET", "/nodeinfo/2.0").await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(json_of(&body)["openRegistrations"], true);
    })
    .await;
}

#[tokio::test]
async fn the_nodeinfo_well_known_path_is_read_only() {
    run_db_test(|_store, app| async move {
        let (status, _) = send_anon(&app, "POST", "/.well-known/nodeinfo").await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    })
    .await;
}
