//! `nodus-media` — the bytes half of the media surface.
//!
//! Uploads belong to the API: they authenticate a user, write a catalogue row and queue the
//! variants. Reading them back does not, and it is the part that moves bytes, so it lives
//! here and can be sized, restarted and moved on its own.

#![forbid(unsafe_code)]

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use nodus_server_media::cluster;
use nodus_server_runtime::{self as runtime, Config};
use nodus_server_store::{media_nodes, Store};
use nodus_server_transport::Address;

/// How often this node says it is alive. A node that misses one heartbeat is still a
/// placement target; the membership window is many multiples of this.
const HEARTBEAT_EVERY: Duration = Duration::from_secs(15);

/// One cleanup sweep per ten minutes — the age that actually removes a node from placement
/// is [`cluster::MEMBER_MAX_AGE`]; this only bounds how long a dead row is kept.
const FORGET_EVERY: u32 = 40;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let agent = runtime::init("media");
    let config: Config = runtime::read()?;
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

    let node = std::env::var("NODUS_MEDIA_NODE")
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| config.bind.to_string());
    let endpoint = std::env::var("NODUS_MEDIA_ENDPOINT")
        .ok()
        .filter(|endpoint| !endpoint.is_empty())
        .unwrap_or_else(|| default_endpoint(&config.bind));
    let cluster_token = std::env::var("NODUS_MEDIA_CLUSTER_TOKEN")
        .ok()
        .filter(|token| !token.is_empty());

    spawn_heartbeat(store.clone(), node.clone(), endpoint.clone());

    let serving = Arc::new(nodus_server_media::serve::Serving::new(
        store.pool().clone(),
        runtime::media_dir(),
        runtime::variants_dir(),
        node.clone(),
        cluster_token,
    ));
    tracing::info!(
        address = %config.bind,
        %node,
        %endpoint,
        cluster = serving.cluster_enabled(),
        domain = %config.instance.domain,
        "media listening"
    );
    nodus_server_transport::serve_http(&config.bind, serving.router(), runtime::shutdown()).await?;
    runtime::stop_telemetry(telemetry).await;
    Ok(())
}

/// The endpoint a single-node instance advertises when none is configured.
///
/// The bind address is what the process listens on, which is usually `0.0.0.0`; a peer on
/// the same host cannot fetch from that, so the default names the loopback address at the
/// same port. A unix-socket bind has no port, so the bare loopback address is all we know.
fn default_endpoint(bind: &Address) -> String {
    match bind {
        Address::Tcp(address) => format!("http://127.0.0.1:{}", address.port()),
        _ => "http://127.0.0.1".to_owned(),
    }
}

/// Records this node and forgets nodes that stopped answering.
///
/// A failure is logged and retried on the next tick: a database hiccup must not take the
/// byte server down, and the membership row it could not write this time is written next
/// time. The task therefore never returns, even on error.
fn spawn_heartbeat(store: Store, node: String, endpoint: String) {
    tokio::spawn(async move {
        let mut since_forget = 0u32;
        let mut interval = tokio::time::interval(HEARTBEAT_EVERY);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if let Err(error) = media_nodes::heartbeat(store.pool(), &node, &endpoint).await {
                tracing::warn!(%error, %node, "could not record this media node");
            }
            since_forget += 1;
            if since_forget >= FORGET_EVERY {
                since_forget = 0;
                match media_nodes::forget_stale(store.pool(), cluster::MEMBER_MAX_AGE).await {
                    Ok(0) => {}
                    Ok(forgotten) => tracing::info!(forgotten, "forgot stale media nodes"),
                    Err(error) => tracing::warn!(%error, "could not forget stale media nodes"),
                }
            }
        }
    });
}
