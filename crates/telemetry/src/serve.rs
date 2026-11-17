//! Two transports, one service: a Unix socket where processes share a machine, TCP where
//! they do not.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nodus_server_proto::telemetry::telemetry_server::TelemetryServer;
use tonic::transport::Server;

use crate::agent::{Agent, Service};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the socket could not be prepared: {0}")]
    Io(#[from] std::io::Error),
    #[error("the telemetry server stopped: {0}")]
    Transport(#[from] tonic::transport::Error),
}

/// Serves on a Unix socket, replacing a socket left behind by an earlier run.
///
/// # Errors
///
/// Fails when the socket cannot be created or the server cannot run.
pub async fn serve_uds(agent: Arc<Agent>, socket: PathBuf) -> Result<(), Error> {
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if Path::new(&socket).exists() {
        std::fs::remove_file(&socket)?;
    }
    let listener = tokio::net::UnixListener::bind(&socket)?;
    Server::builder()
        .add_service(TelemetryServer::new(Service::new(agent)))
        .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
        .await?;
    Ok(())
}

/// Serves on TCP, for a host that reaches another host.
///
/// # Errors
///
/// Fails when the address cannot be bound or the server cannot run.
pub async fn serve_tcp(agent: Arc<Agent>, address: SocketAddr) -> Result<(), Error> {
    Server::builder()
        .add_service(TelemetryServer::new(Service::new(agent)))
        .serve(address)
        .await?;
    Ok(())
}
