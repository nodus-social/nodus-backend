//! The instance's public face: the Mastodon-compatible API, the `ActivityPub` documents
//! and the auth pages.
//!
//! It owns no loop of its own beyond the two that publish queued work, because the work
//! that can be done later belongs to the services that do it.

use std::error::Error;
use std::sync::Arc;

use axum::Router;
use nodus_auth::store::PgAuthStore;
use nodus_server_api::{root_router, AppState};
use nodus_server_runtime::{self as runtime, Config};
use nodus_server_store::Store;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let agent = runtime::init("api");
    let config = runtime::read()?;
    let telemetry = config
        .telemetry
        .clone()
        .map(|address| runtime::serve_telemetry(address, Arc::clone(&agent)));

    let store = runtime::prepare(&config).await?;
    if config.migrate_only {
        tracing::info!("migrations applied");
        runtime::stop_telemetry(telemetry).await;
        return Ok(());
    }

    // Queued posts publish and outbound activities leave from the process that also
    // serves requests: one pool, one set of signing keys, and no second deployable to
    // keep in step with this one.
    let state = AppState::new(store.clone(), config.instance.clone());
    tokio::spawn(nodus_server_api::schedules::run(state.clone()));
    tokio::spawn(nodus_server_api::outbox::run(state));

    tracing::info!(
        address = %config.bind,
        domain = %config.instance.domain,
        "api listening"
    );
    nodus_server_transport::serve_http(&config.bind, router(&store, &config), runtime::shutdown())
        .await?;
    runtime::stop_telemetry(telemetry).await;
    Ok(())
}

/// Everything this service answers, in the order the router sees it.
fn router(store: &Store, config: &Config) -> Router {
    let api = root_router(AppState::new(store.clone(), config.instance.clone()));
    let auth = nodus_auth::router(nodus_auth::AppState::new(
        PgAuthStore::new(store.pool().clone()),
        nodus_auth::Config {
            domain: config.instance.domain.clone(),
            issuer: config.instance.base_url.clone(),
            secure_cookies: config.secure_cookies,
            registrations_open: config.registrations_open,
        },
    ));
    api.merge(auth)
}
