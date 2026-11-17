//! Where the telemetry service listens.
//!
//! The address is the same one every other service takes, so a container can put its
//! telemetry beside its requests on a Unix socket and a spread-out deployment can reach
//! the same service over TCP without a second code path.

use std::sync::Arc;

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
