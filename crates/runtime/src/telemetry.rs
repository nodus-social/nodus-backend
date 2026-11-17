//! The listener a service uses to answer about itself.
//!
//! It is always stopped explicitly: a socket file left behind by a killed process is
//! recreated by `unix_listen_unlink`, but one left behind by a clean stop is a lie about
//! what is running.

use std::sync::Arc;

use nodus_server_proto::control::control_server::Control;
use nodus_server_telemetry::Agent;
use nodus_server_transport::Address;

pub struct Telemetry {
    stopping: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

/// Start the report listener for a service that only answers questions.
#[must_use]
pub fn serve_telemetry(address: Address, agent: Arc<Agent>) -> Telemetry {
    let (stopping, stopped) = tokio::sync::oneshot::channel::<()>();
    tracing::info!(listen = %address, "telemetry listening");
    let task = tokio::spawn(async move {
        let served = nodus_server_telemetry::serve(agent, &address, async move {
            let _ = stopped.await;
        })
        .await;
        if let Err(error) = served {
            tracing::error!(%error, "the telemetry service stopped");
        }
    });
    Telemetry { stopping, task }
}

/// Start the report listener beside the work this service accepts on demand.
#[must_use]
pub fn serve_worker<C>(address: Address, agent: Arc<Agent>, control: C) -> Telemetry
where
    C: Control + Send + Sync + 'static,
{
    let (stopping, stopped) = tokio::sync::oneshot::channel::<()>();
    tracing::info!(listen = %address, "telemetry listening");
    let task = tokio::spawn(async move {
        let served =
            nodus_server_telemetry::serve_with(agent, &address, control, async move {
                let _ = stopped.await;
            })
            .await;
        if let Err(error) = served {
            tracing::error!(%error, "the telemetry service stopped");
        }
    });
    Telemetry { stopping, task }
}

/// Stop the listener, waiting for it to remove its socket.
pub async fn stop(telemetry: Option<Telemetry>) {
    let Some(telemetry) = telemetry else {
        return;
    };
    let _ = telemetry.stopping.send(());
    let _ = telemetry.task.await;
}
