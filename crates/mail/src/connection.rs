//! The socket under the SMTP dialogue: plaintext until STARTTLS says otherwise.
//!
//! Isolated from [`crate::smtp`] so the protocol code is one screen of commands and this
//! file is one screen of I/O.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::Error;

fn transport(error: impl std::fmt::Display) -> Error {
    Error::Transport(error.to_string())
}

/// Either a plaintext socket or one already wrapped in TLS.
pub(crate) enum Connection {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl Connection {
    pub(crate) fn plain(tcp: TcpStream) -> Self {
        Self::Plain(tcp)
    }

    pub(crate) async fn tls(
        tcp: TcpStream,
        host: &str,
        config: &Arc<rustls::ClientConfig>,
    ) -> Result<Self, Error> {
        let name = rustls_pki_types::ServerName::try_from(host.to_owned())
            .map_err(|_| Error::Config(format!("`{host}` is not a DNS name")))?;
        let stream = TlsConnector::from(Arc::clone(config))
            .connect(name, tcp)
            .await
            .map_err(transport)?;
        Ok(Self::Tls(Box::new(stream)))
    }

    pub(crate) async fn upgrade(
        self,
        host: &str,
        config: &Arc<rustls::ClientConfig>,
    ) -> Result<Self, Error> {
        let Self::Plain(tcp) = self else {
            return Err(Error::Transport("STARTTLS on a TLS connection".into()));
        };
        Self::tls(tcp, host, config).await
    }

    pub(crate) async fn command(&mut self, command: &str) -> Result<(), Error> {
        self.write(&format!("{command}\r\n")).await
    }

    pub(crate) async fn write(&mut self, bytes: &str) -> Result<(), Error> {
        match self {
            Self::Plain(stream) => stream.write_all(bytes.as_bytes()).await,
            Self::Tls(stream) => stream.write_all(bytes.as_bytes()).await,
        }
        .map_err(transport)
    }

    /// Reads one CRLF-terminated reply line.
    pub(crate) async fn line(&mut self) -> Result<String, Error> {
        let mut bytes = Vec::new();
        loop {
            let byte = match self {
                Self::Plain(stream) => stream.read_u8().await,
                Self::Tls(stream) => stream.read_u8().await,
            }
            .map_err(transport)?;
            if byte == b'\n' {
                break;
            }
            if bytes.len() >= 1024 {
                return Err(Error::Transport("SMTP reply line is too long".into()));
            }
            bytes.push(byte);
        }
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Consumes a (possibly multi-line) reply and requires its numeric code.
    pub(crate) async fn expect(&mut self, code: &str) -> Result<(), Error> {
        loop {
            let line = self.line().await?;
            if !line.starts_with(code) {
                return Err(Error::Transport(format!(
                    "SMTP expected {code}, got {line}"
                )));
            }
            if line.as_bytes().get(3) == Some(&b' ') {
                return Ok(());
            }
        }
    }
}
