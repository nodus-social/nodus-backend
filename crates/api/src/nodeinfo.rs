//! `NodeInfo`: the machine-readable description of this instance.
//!
//! Peers, fediverse directories and tooling decide whether and how to list a server by
//! reading it, and both Mastodon and Misskey serve it, so its absence is visible.
//! Before this module the root router answered `GET /.well-known/nodeinfo` with its own
//! 404, and every probe of the deployment got nothing.
//!
//! Discovery is two documents: a link from the well-known path, then the document itself.
//! They live at the domain root because a crawler starts from the host, not from `/api`.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::error::ApiResult;
use crate::state::AppState;

/// The schema relation a `NodeInfo` 2.0 discovery document advertises.
const NODEINFO_2_0: &str = "http://nodeinfo.diaspora.software/ns/schema/2.0";

/// The path the discovery document points at, and the route that serves it.
const DOCUMENT_PATH: &str = "/nodeinfo/2.0";

/// Builds the two discovery routes. Mounted at the root, next to WebFinger.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/.well-known/nodeinfo", get(discovery))
        .route(DOCUMENT_PATH, get(document))
        .with_state(state)
}

/// `GET /.well-known/nodeinfo`
///
/// The `href` is built from the instance's configured base URL, so a deployment behind a
/// proxy advertises the address a peer reached rather than one derived from the request.
async fn discovery(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "links": [{
            "rel": NODEINFO_2_0,
            "href": state.instance().url(DOCUMENT_PATH),
        }],
    }))
}

/// `GET /nodeinfo/2.0`
///
/// `metadata` is empty on purpose: `NodeInfo` allows it to carry extensions, and this
/// instance publishes none a peer would act on. The counts come from one store query, so
/// a crawler's poll costs one round trip.
async fn document(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let usage = state.store().nodeinfo_usage().await?;
    let instance = state.instance();
    Ok(Json(json!({
        "version": "2.0",
        "software": {
            "name": "nodus",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "protocols": ["activitypub"],
        "services": { "inbound": [], "outbound": [] },
        "openRegistrations": instance.registrations_open,
        "usage": {
            "users": {
                "total": usage.users_total,
                "activeMonth": usage.users_active_month,
                "activeHalfyear": usage.users_active_halfyear,
            },
            "localPosts": usage.local_posts,
        },
        "metadata": {},
    })))
}
