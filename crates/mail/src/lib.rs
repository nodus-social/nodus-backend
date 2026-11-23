//! Transactional mail: the seam between a state change and a mail server.
//!
//! Everything above this crate writes an outbox row; only this crate talks SMTP. That is
//! deliberate: an instance with no mail configured must still start and serve every other
//! feature, and a broken mail server must never slow a request that only wanted to create
//! an account. The trait exists so tests can replace the network with a transport that
//! succeeds or fails on demand.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

mod connection;
mod smtp;

pub use smtp::{SmtpConfig, TlsMode};

/// A plain-text message with an optional HTML alternative.
///
/// Both bodies are rendered by the caller, which knows what the link is for; the transport
/// only decides how bytes reach the recipient. No remote resources belong in the HTML: a
/// confirmation must not tell a third party that an address exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: Option<String>,
}

/// Why a send failed. The outbox stores the display form as `last_error`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("mail configuration: {0}")]
    Config(String),
    #[error("mail transport: {0}")]
    Transport(String),
}

pub type SendFuture<'a> = Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>>;

/// One way to hand a message to the outside world.
///
/// A boxed future rather than an `async fn` because the caller holds an
/// `Arc<dyn Transport>`; the sender is chosen once at startup and never changes.
pub trait Transport: Send + Sync + 'static {
    fn send<'a>(&'a self, message: &'a Message) -> SendFuture<'a>;
}

/// The sender every instance starts with: it records nothing and never touches a network.
#[derive(Debug, Clone, Copy, Default)]
pub struct Noop;

impl Transport for Noop {
    fn send<'a>(&'a self, _message: &'a Message) -> SendFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

/// Builds the sender the environment asks for, or `None` when mail is unset.
///
/// A half-configured SMTP — say a host without a from-address — is logged and treated as
/// unset rather than crashing the process: the instance keeps working, and the capability
/// stays withheld, exactly as if the operator had configured nothing.
#[must_use]
pub fn sender_from_env() -> Option<Arc<dyn Transport>> {
    let config = match SmtpConfig::from_env() {
        Ok(Some(config)) => config,
        Ok(None) => {
            tracing::info!("no SMTP configured; transactional mail stays disabled");
            return None;
        }
        Err(error) => {
            tracing::warn!(%error, "SMTP configuration is incomplete; transactional mail stays disabled");
            return None;
        }
    };
    tracing::info!(
        host = %config.host,
        port = config.port,
        tls = ?config.tls,
        "transactional mail sends over SMTP"
    );
    Some(Arc::new(smtp::SmtpTransport::new(config)))
}
