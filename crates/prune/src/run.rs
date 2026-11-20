//! The process around the pruning passes: configuration, storage, the control listener and
//! the stop signal.
//!
//! It lives here rather than in `services/prune/src/main.rs` so `nodus prune` starts
//! exactly this process. `services/prune` is a two-line wrapper and `nodus prune` calls the
//! same function, which is what keeps the deployed unit and the new entrypoint from
//! drifting.

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use nodus_server_proto::control::control_server::Control;
use nodus_server_proto::control::{TriggerReply, TriggerRequest};
use nodus_server_runtime as runtime;
use nodus_server_store::Store;
use tonic::{Request, Response, Status};

/// An hour: media has a 24-hour grace, so anything faster is a scan for nothing.
const TICK: Duration = Duration::from_secs(3600);

struct Worker {
    wake: Arc<tokio::sync::Notify>,
}

#[tonic::async_trait]
impl Control for Worker {
    async fn trigger(
        &self,
        request: Request<TriggerRequest>,
    ) -> Result<Response<TriggerReply>, Status> {
        let work = request.into_inner().work;
        let accepted = work.is_empty() || work == "prune";
        if accepted {
            self.wake.notify_one();
        }
        Ok(Response::new(TriggerReply {
            accepted,
            detail: if accepted {
                "a pruning pass is queued".to_owned()
            } else {
                format!("this service does not do {work:?}")
            },
        }))
    }
}

/// Run the pruning worker as its own process, with its own logging, telemetry and stop
/// signal.
///
/// # Errors
///
/// Fails when the configuration is wrong, the database cannot be prepared, or the control
/// listener cannot bind.
pub async fn run() -> anyhow::Result<()> {
    serve().await.map_err(|error| anyhow::anyhow!("{error}"))
}

/// What `nodus prune` starts and where it listens, without binding.
///
/// The address is read from the environment this run path reads, so `--dry-run` prints the
/// worker's own answer rather than a copy of it kept in the entrypoint.
#[must_use]
pub fn plan() -> (&'static str, &'static str, String) {
    let listen = match (
        std::env::var("NODUS_TELEMETRY_SOCKET"),
        std::env::var("NODUS_TELEMETRY_BIND"),
    ) {
        (Ok(socket), _) => format!("the control socket {socket}"),
        (_, Ok(address)) => format!("the control address {address}"),
        _ => "nothing (no NODUS_TELEMETRY_SOCKET or NODUS_TELEMETRY_BIND)".to_owned(),
    };
    ("prune", "nodus_server_prune::run", listen)
}

async fn serve() -> Result<(), Box<dyn Error>> {
    let agent = runtime::init("prune");
    let config = runtime::read()?;
    let store = runtime::prepare(&config).await?;
    if config.migrate_only {
        tracing::info!("migrations applied");
        return Ok(());
    }

    let wake = Arc::new(tokio::sync::Notify::new());
    let telemetry = config.telemetry.clone().map(|address| {
        let worker = Worker {
            wake: Arc::clone(&wake),
        };
        runtime::serve_worker(address, Arc::clone(&agent), worker)
    });

    let task = tokio::spawn(sweep(store, wake));
    tracing::info!("prune worker running");
    runtime::shutdown().await;
    task.abort();
    runtime::stop_telemetry(telemetry).await;
    Ok(())
}

async fn sweep(store: Store, wake: Arc<tokio::sync::Notify>) {
    let mut ticker = tokio::time::interval(TICK);
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            () = wake.notified() => {}
        }
        runtime::prune_media(&store).await;
        // Account tombstones share this clock: the grace window is checked hourly, and the
        // erasure is idempotent, so a wake-up between ticks costs one empty query.
        match nodus_server_store::accounts::purge_due(store.pool(), 100).await {
            Ok(0) => {}
            Ok(count) => tracing::info!(accounts = count, "erased account tombstones"),
            Err(error) => tracing::warn!(%error, "could not purge account tombstones"),
        }
    }
}
