//! The scanning service: it asks the configured scanners about new content and applies
//! what they say.
//!
//! It owns no HTTP surface. It is reachable over the same address that reports on it, so
//! a controller can ask for a pass now without a second listener or a database row.

mod sweep;

use std::error::Error;
use std::sync::Arc;

use nodus_server_proto::control::control_server::Control;
use nodus_server_proto::control::{TriggerReply, TriggerRequest};
use nodus_server_runtime as runtime;
use nodus_server_store::Store;
use tonic::{Request, Response, Status};

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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
