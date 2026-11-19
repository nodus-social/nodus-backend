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

/// The first repair pass waits a minute, so a node that just restarted is not competing
/// with its own startup for the catalogue.
const REPAIR_FIRST: Duration = Duration::from_secs(60);

/// How often the repair walk compares the catalogue with the members that should hold
/// each digest. Ten minutes is a tenth of [`cluster::MEMBER_MAX_AGE`], so a replica lost
/// to a failed upload is back long before the membership itself would expire.
const REPAIR_EVERY: Duration = Duration::from_secs(600);

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
    if let Some(token) = cluster_token.clone() {
        if repair_enabled() {
            spawn_repair(store.clone(), runtime::media_dir(), node.clone(), token);
        }
    }

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
/// Whether this process runs the repair walk. `NODUS_MEDIA_REPAIR=off` leaves it to
/// another node, and keeps an unclustered instance from scanning a catalogue it cannot
/// repair.
fn repair_enabled() -> bool {
    std::env::var("NODUS_MEDIA_REPAIR").map_or(true, |value| !value.eq_ignore_ascii_case("off"))
}

fn spawn_repair(store: Store, root: std::path::PathBuf, node: String, token: String) {
    tokio::spawn(async move {
        tokio::time::sleep(REPAIR_FIRST).await;
        let mut every = tokio::time::interval(REPAIR_EVERY);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            every.tick().await;
            let summary =
                nodus_server_media::repair::pass(store.pool(), &root, &node, &token).await;
            tracing::info!("media repair pass {}", summary.line());
        }
    });
}

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
