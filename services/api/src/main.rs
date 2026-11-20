//! The instance's public face: the Mastodon-compatible API, the `ActivityPub` documents
//! and the auth pages.
//!
//! It owns no loop of its own beyond the two that publish queued work, because the work
//! that can be done later belongs to the services that do it.

use std::error::Error;
use std::sync::Arc;

use axum::Router;
use nodus_auth::store::PgAuthStore;
use nodus_server_api::{root_router, AppState, FederationKey};
use nodus_server_runtime::{self as runtime, Config};
use nodus_server_store::invalidate::{InvalidationSink, ValkeyInvalidator, DEFAULT_CHANNEL};
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
    let sink = invalidation_sink();
    if config.migrate_only {
        tracing::info!("migrations applied");
        runtime::stop_telemetry(telemetry).await;
        return Ok(());
    }

    // Queued posts publish and outbound activities leave from the process that also
    // serves requests: one pool, one set of signing keys, and no second deployable to
    // keep in step with this one.
    let federation = FederationKey::from_env(&config.instance);
    let state = AppState::with_federation_and_sink(
        store.clone(),
        config.instance.clone(),
        federation.clone(),
        sink.clone(),
    )
    .with_authorized_fetch(config.authorized_fetch)
    .with_account_delete_grace_days(config.account_delete_grace_days);
    tokio::spawn(nodus_server_api::schedules::run(state.clone()));
    // The subscription sweep lives here rather than in the pruning worker: it is an
    // outbound fetch, and the outbound guard, the client and the import path all live in
    // this process. One more loop on a clock, not a third service.
    tokio::spawn(nodus_server_api::admin::blocklist::run(state.clone()));
    tokio::spawn(nodus_server_api::outbox::run(state));

    tracing::info!(
        address = %config.bind,
        domain = %config.instance.domain,
        "api listening"
    );
    nodus_server_transport::serve_http(
        &config.bind,
        router(&store, &config, federation, sink),
        runtime::shutdown(),
    )
    .await?;
    runtime::stop_telemetry(telemetry).await;
    Ok(())
}

/// The sink committed drive writes publish to, from the environment.
///
/// One variable decides it: `NODUS_VALKEY_URL` set means other replicas are told what
/// changed; unset means there is no cache to tell and every write behaves exactly as it
/// did before. The channel name is logged either way, because an operator debugging a
/// stale cache needs to know which channel to subscribe to.
fn invalidation_sink() -> Option<Arc<dyn InvalidationSink>> {
    let url = match std::env::var("NODUS_VALKEY_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            tracing::info!("NODUS_VALKEY_URL is unset: invalidations are off");
            return None;
        }
    };
    let channel = std::env::var("NODUS_VALKEY_CHANNEL")
        .ok()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_CHANNEL.to_owned());
    tracing::info!(channel = %channel, "drive invalidations publish to valkey");
    Some(Arc::new(ValkeyInvalidator::spawn(&url, &channel)))
}

/// Everything this service answers, in the order the router sees it.
fn router(
    store: &Store,
    config: &Config,
    federation: Option<FederationKey>,
    sink: Option<Arc<dyn InvalidationSink>>,
) -> Router {
    let api = root_router(
        AppState::with_federation_and_sink(
            store.clone(),
            config.instance.clone(),
            federation,
            sink,
        )
        .with_authorized_fetch(config.authorized_fetch)
        .with_account_delete_grace_days(config.account_delete_grace_days),
    );
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
