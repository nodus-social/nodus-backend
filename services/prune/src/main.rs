//! The pruning service.
//!
//! Everything here is on a clock, so it is the one service whose absence is invisible
//! until disk pressure or a stale session appears. It keeps the same call and stop shape
//! as every other worker so a controller can ask for a pass now.

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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
    }
}
