//! What a service listens on.
//!
//! A deployment decides transport, not the binary: the same process accepts a Unix
//! socket path beside its neighbours in one container and a TCP address across hosts.
//! Every listener therefore takes an address string — `127.0.0.1:3000`,
//! `/var/run/app/api-http.sock`, `sd-listen` — and the parsing lives here so no
//! service grows its own socket-type switch.
//!
//! Unix sockets are unlinked before binding and removed on exit, so a restarted
//! process never fails with "address already in use" and never leaves a dead path
//! behind for an ingress to dial.

#![forbid(unsafe_code)]

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use axum::extract::ConnectInfo;
use axum::Router;
use futures_util::stream::unfold;
use tokio_listener::{Listener, SystemOptions, UserOptions};
use tonic::transport::server::Router as GrpcRouter;

pub use tokio_listener::ListenerAddress as Address;

/// Parse a configured listen address.
///
/// # Errors
///
/// Returns a message naming the value when it is neither a socket address nor a
/// socket path, so a mistyped environment variable stops the process at boot with
/// something an operator can act on.
pub fn parse(value: &str) -> Result<Address, String> {
    let value = value.trim();
    // A client names a socket as `unix:///var/run/app/api.sock`; a listener names the same
    // file by path. The prefix is accepted so one spelling works on both sides of a
    // deployment.
    let path = value
        .strip_prefix("unix://")
        .or_else(|| value.strip_prefix("unix:"))
        .unwrap_or(value);
    path.parse::<Address>()
        .map_err(|error| format!("{value:?} is not a listen address: {error}"))
}

/// The address a service reports in its startup line.
#[must_use]
pub fn describe(address: &Address) -> String {
    address.to_string()
}

fn user_options() -> UserOptions {
    let mut options = UserOptions::default();
    // A killed process leaves its socket file behind; the replacement must not trip
    // over it.
    options.unix_listen_unlink = true;
    options
}

async fn bind(address: &Address) -> io::Result<Listener> {
    if let Address::Path(path) = address {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }
    }
    Listener::bind(address, &SystemOptions::default(), &user_options()).await
}

async fn release(address: &Address) {
    if let Address::Path(path) = address {
        remove_socket(path).await;
    }
}

async fn remove_socket(path: &Path) {
    if let Err(error) = tokio::fs::remove_file(path).await {
        if error.kind() != io::ErrorKind::NotFound {
            tracing::warn!(path = %path.display(), %error, "could not remove the socket");
        }
    }
}

/// Serve an axum router on either transport until `shutdown` resolves.
///
/// Behind a socket path the peer is read from `x-forwarded-for`, because only the
/// ingress on this machine can dial it and it is the ingress that knows the caller.
/// On a TCP address the caller *is* the peer, and a forwarded header would be a claim
/// rather than an observation, so it is ignored.
///
/// # Errors
///
/// Returns the bind or accept failure; the caller should stop the process, because a
/// service that cannot listen is not healthy.
pub async fn serve_http<F>(address: &Address, router: Router, shutdown: F) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let listener = bind(address).await?;
    let router = match address {
        Address::Path(_) => router.layer(axum::middleware::from_fn(peer_from_ingress)),
        _ => router,
    };
    tracing::info!(listen = %address, "http listening");
    let served = axum::serve(listener, router.into_make_service())
        .with_graceful_shutdown(shutdown)
        .await;
    release(address).await;
    served
}

/// Serve a tonic router on either transport until `shutdown` resolves.
///
/// # Errors
///
/// Returns the bind failure or the server's own error; both mean the process should
/// stop rather than run without the service its peers expect.
pub async fn serve_grpc<F>(address: &Address, router: GrpcRouter, shutdown: F) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let listener = bind(address).await?;
    // Debug, because every caller announces the address it was given along with its own
    // name: one listen should produce one line.
    tracing::debug!(listen = %address, "grpc listening");
    let incoming = unfold(listener, |mut listener| async move {
        match listener.accept().await {
            Ok((connection, _peer)) => Some((Ok::<_, io::Error>(connection), listener)),
            Err(error) => Some((Err(error), listener)),
        }
    });
    let served = router
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await
        .map_err(io::Error::other);
    release(address).await;
    served
}

/// Take the caller's address from the ingress that dialled this socket.
async fn peer_from_ingress(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(peer) = forwarded_peer(&request) {
        request.extensions_mut().insert(ConnectInfo(peer));
    }
    next.run(request).await
}

fn forwarded_peer(request: &axum::extract::Request) -> Option<SocketAddr> {
    let value = request.headers().get("x-forwarded-for")?.to_str().ok()?;
    let first = value.split(',').next()?.trim();
    let ip: IpAddr = first.parse().ok()?;
    Some(SocketAddr::new(ip, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tcp_address_parses() {
        assert_eq!(
            parse("127.0.0.1:3000").expect("tcp"),
            Address::Tcp("127.0.0.1:3000".parse().expect("socket"))
        );
    }

    #[test]
    fn a_socket_path_parses() {
        assert_eq!(
            parse("/var/run/app/api-http.sock").expect("path"),
            Address::Path("/var/run/app/api-http.sock".into())
        );
    }

    #[test]
    fn a_socket_path_may_be_written_as_a_client_names_it() {
        assert_eq!(
            parse("unix:/var/run/app/api-http.sock").expect("short prefix"),
            Address::Path("/var/run/app/api-http.sock".into())
        );
        assert_eq!(
            parse("unix:///var/run/app/api-grpc.sock").expect("url prefix"),
            Address::Path("/var/run/app/api-grpc.sock".into())
        );
    }

    #[test]
    fn a_mistyped_address_names_the_value() {
        let refused = parse("localhost:3000").expect_err("hostnames are not addresses");
        assert!(refused.contains("localhost:3000"), "{refused}");
    }

    #[test]
    fn the_first_forwarded_hop_is_the_caller() {
        let request = axum::extract::Request::builder()
            .header("x-forwarded-for", "203.0.113.7, 10.0.1.1")
            .body(axum::body::Body::empty())
            .expect("request");
        assert_eq!(
            forwarded_peer(&request),
            Some(SocketAddr::new("203.0.113.7".parse().expect("ip"), 0))
        );
    }

    #[test]
    fn without_a_forwarded_header_there_is_no_caller() {
        let request = axum::extract::Request::builder()
            .body(axum::body::Body::empty())
            .expect("request");
        assert_eq!(forwarded_peer(&request), None);
    }
}
