//! Where the telemetry service listens.
//!
//! The address is the same one every other service takes, so a container can put its
//! telemetry beside its requests on a Unix socket and a spread-out deployment can reach
//! the same service over TCP without a second code path.

use std::sync::Arc;

use nodus_server_proto::control::control_server::{Control, ControlServer};
use nodus_server_proto::telemetry::telemetry_server::TelemetryServer;
use nodus_server_transport::Address;
use tonic::transport::Server;

use crate::agent::{Agent, Service};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the listener could not be prepared: {0}")]
    Io(#[from] std::io::Error),
}

/// Serve until `shutdown` resolves.
///
/// # Errors
///
/// Fails when the address cannot be bound or the server stops with an error, either of
/// which means this process cannot answer about itself.
pub async fn serve<F>(agent: Arc<Agent>, address: &Address, shutdown: F) -> Result<(), Error>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let service = Server::builder().add_service(TelemetryServer::new(Service::new(agent)));
    nodus_server_transport::serve_grpc(address, service, shutdown).await?;
    Ok(())
}

/// Serve this process's report and the work it accepts, on one address.
///
/// A worker that has nothing to report and everything to do still needs an address the
/// controller can dial, so the two services share a listener rather than a port each.
///
/// # Errors
///
/// Fails when the address cannot be bound or the server stops with an error.
pub async fn serve_with<F, C>(
    agent: Arc<Agent>,
    address: &Address,
    control: C,
    shutdown: F,
) -> Result<(), Error>
where
    F: std::future::Future<Output = ()> + Send + 'static,
    C: Control,
{
    let service = Server::builder()
        .add_service(TelemetryServer::new(Service::new(agent)))
        .add_service(ControlServer::new(control));
    nodus_server_transport::serve_grpc(address, service, shutdown).await?;
    Ok(())
}
