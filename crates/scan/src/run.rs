//! The process around the scanner sweep: configuration, storage, the control listener and
//! the stop signal.
//!
//! It lives here rather than in `services/scan/src/main.rs` so `nodus scan` starts exactly
//! this process. `services/scan` is a two-line wrapper and `nodus scan` calls the same
//! function, which is what keeps the deployed unit and the new entrypoint from drifting.

use std::error::Error;
use std::sync::Arc;

use nodus_server_proto::control::control_server::Control;
use nodus_server_proto::control::{TriggerReply, TriggerRequest};
use nodus_server_runtime as runtime;
use nodus_server_store::Store;
use tonic::{Request, Response, Status};

use crate::sweep;

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
        let accepted = work.is_empty() || work == "scan";
        if accepted {
            self.wake.notify_one();
        }
        Ok(Response::new(TriggerReply {
            accepted,
            detail: if accepted {
                "a sweep is queued".to_owned()
            } else {
                format!("this service does not do {work:?}")
            },
        }))
    }
}

/// Run the scan worker as its own process, with its own logging, telemetry and stop signal.
///
/// # Errors
///
/// Fails when the configuration is wrong, the database cannot be prepared, or the control
/// listener cannot bind.
pub async fn run() -> anyhow::Result<()> {
    serve().await.map_err(|error| anyhow::anyhow!("{error}"))
}

/// What `nodus scan` starts and where it listens, without binding.
///
/// The address is read from the environment this run path reads, so `--dry-run` prints the
/// scanner worker's own answer rather than a copy of it kept in the entrypoint.
#[must_use]
pub fn plan() -> (&'static str, &'static str, String) {
    ("scan", "nodus_server_scan::run", control_address())
}

/// The control address, phrased for the dry-run line. A worker with no telemetry address
/// still runs; it just has no way to be asked for a pass now.
fn control_address() -> String {
    match (
        std::env::var("NODUS_TELEMETRY_SOCKET"),
        std::env::var("NODUS_TELEMETRY_BIND"),
    ) {
        (Ok(socket), _) => format!("the control socket {socket}"),
        (_, Ok(address)) => format!("the control address {address}"),
        _ => "nothing (no NODUS_TELEMETRY_SOCKET or NODUS_TELEMETRY_BIND)".to_owned(),
    }
}

async fn serve() -> Result<(), Box<dyn Error>> {
    let agent = runtime::init("scan");
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

    start(&store, &config, wake);
    runtime::shutdown().await;
    runtime::stop_telemetry(telemetry).await;
    Ok(())
}

/// The scheduled sweep, and the address a controller asks for one on.
fn start(store: &Store, config: &runtime::Config, wake: Arc<tokio::sync::Notify>) {
    sweep::spawn(store.clone(), config.instance.base_url.clone(), wake);
    if config.telemetry.is_some() {
        tracing::info!("scan worker running");
    } else {
        tracing::warn!("scan worker running without a control address");
    }
}
