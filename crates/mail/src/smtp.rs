//! A deliberately small SMTP client: EHLO, optional STARTTLS or implicit TLS, optional
//! `AUTH PLAIN`, one message, QUIT.
//!
//! It is not a mail library. The only message this instance sends is a confirmation, so
//! the surface is one envelope and one multipart body. Keeping it here avoids a large
//! dependency for a capability an operator may never switch on.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use std::fmt::Write as _;
use std::sync::Arc;

use tokio::net::TcpStream;

use crate::connection::Connection;
use crate::{Error, Message, SendFuture, Transport};

/// How the connection is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// Port 25-style plaintext. Only for a relay on the same trusted network.
    None,
    /// Connect in the clear, then upgrade with `STARTTLS` (the usual submission port).
    StartTls,
    /// TLS from the first byte (usually port 465).
    Implicit,
}

/// `NODUS_SMTP_*`, read once at startup.
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
    pub tls: TlsMode,
}

impl SmtpConfig {
    /// Reads the SMTP settings, or `None` when no host is configured.
    ///
    /// # Errors
    ///
    /// A host with an unreadable port, a one-sided credential, or an unknown TLS mode is
    /// an error the caller logs; it is not allowed to take the process down.
    pub fn from_env() -> Result<Option<Self>, Error> {
        let host = match std::env::var("NODUS_SMTP_HOST") {
            Ok(host) if !host.trim().is_empty() => host.trim().to_owned(),
            _ => return Ok(None),
        };
        let tls = match std::env::var("NODUS_SMTP_TLS")
            .unwrap_or_else(|_| "starttls".to_owned())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "none" => TlsMode::None,
            "starttls" => TlsMode::StartTls,
            "implicit" => TlsMode::Implicit,
            other => return Err(Error::Config(format!("unknown NODUS_SMTP_TLS `{other}`"))),
        };
        let default_port = match tls {
            TlsMode::None => 25,
            TlsMode::StartTls => 587,
            TlsMode::Implicit => 465,
        };
        let port = match std::env::var("NODUS_SMTP_PORT") {
            Ok(port) => port
                .trim()
                .parse()
                .map_err(|_| Error::Config(format!("NODUS_SMTP_PORT `{port}` is not a port")))?,
            Err(_) => default_port,
        };
        let from = std::env::var("NODUS_SMTP_FROM")
            .ok()
            .filter(|from| !from.trim().is_empty())
            .ok_or_else(|| Error::Config("NODUS_SMTP_FROM is required when a host is set".into()))?
            .trim()
            .to_owned();
        check_header("NODUS_SMTP_FROM", &from)?;
        let username = std::env::var("NODUS_SMTP_USERNAME")
            .ok()
            .filter(|value| !value.is_empty());
        let password = std::env::var("NODUS_SMTP_PASSWORD")
            .ok()
            .filter(|value| !value.is_empty());
        if username.is_some() != password.is_some() {
            return Err(Error::Config(
                "NODUS_SMTP_USERNAME and NODUS_SMTP_PASSWORD must be set together".into(),
            ));
        }
        Ok(Some(Self {
            host,
            port,
            username,
            password,
            from,
            tls,
        }))
    }
}

/// The real sender: every call opens one connection, sends one message and closes it.
#[derive(Debug, Clone)]
pub struct SmtpTransport {
    config: SmtpConfig,
    tls: Arc<rustls::ClientConfig>,
}

impl SmtpTransport {
    #[must_use]
    pub fn new(config: SmtpConfig) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            config,
            tls: Arc::new(tls),
        }
    }
}

impl Transport for SmtpTransport {
    fn send<'a>(&'a self, message: &'a Message) -> SendFuture<'a> {
        Box::pin(async move { self.deliver(message).await })
    }
}

impl SmtpTransport {
    async fn deliver(&self, message: &Message) -> Result<(), Error> {
        check_header("recipient", &message.to)?;
        check_header("subject", &message.subject)?;
        let tcp = TcpStream::connect((self.config.host.as_str(), self.config.port))
            .await
            .map_err(transport)?;
        let mut connection = match self.config.tls {
            TlsMode::Implicit => Connection::tls(tcp, &self.config.host, &self.tls).await?,
            TlsMode::None | TlsMode::StartTls => Connection::plain(tcp),
        };
        connection.expect("220").await?;
        connection.command("EHLO nodus").await?;
        connection.expect("250").await?;

        if self.config.tls == TlsMode::StartTls {
            connection.command("STARTTLS").await?;
            connection.expect("220").await?;
            connection = connection.upgrade(&self.config.host, &self.tls).await?;
            connection.command("EHLO nodus").await?;
            connection.expect("250").await?;
        }

        if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            let token = BASE64.encode(format!("\0{username}\0{password}").as_bytes());
            connection.command(&format!("AUTH PLAIN {token}")).await?;
            connection.expect("235").await?;
        }

        connection
            .command(&format!("MAIL FROM:<{}>", self.config.from))
            .await?;
        connection.expect("250").await?;
        connection
            .command(&format!("RCPT TO:<{}>", message.to))
            .await?;
        connection.expect("250").await?;
        connection.command("DATA").await?;
        connection.expect("354").await?;
        connection.write(&data(message, &self.config.from)).await?;
        connection.command(".").await?;
        connection.expect("250").await?;
        connection.command("QUIT").await?;
        // Some servers close immediately after QUIT; the message is already accepted.
        let _ = connection.expect("221").await;
        Ok(())
    }
}

/// The RFC 5322 message, dot-stuffed for the DATA phase.
fn data(message: &Message, from: &str) -> String {
    let boundary = "nodus-alternative-boundary";
    let mut body = String::new();
    let _ = write!(
        body,
        "From: {from}\r\nTo: {}\r\nSubject: {}\r\nDate: {}\r\nMIME-Version: 1.0\r\n",
        message.to,
        message.subject,
        chrono::Utc::now().to_rfc2822()
    );
    match message.html.as_deref() {
        Some(html) => {
            let _ = write!(
                body,
                "Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n"
            );
            body.push_str(&part("text/plain", &message.text, boundary));
            body.push_str(&part("text/html", html, boundary));
            let _ = write!(body, "--{boundary}--\r\n");
        }
        None => {
            let _ = write!(
                body,
                "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}",
                message.text
            );
        }
    }
    dot_stuff(&body)
}

fn part(content_type: &str, value: &str, boundary: &str) -> String {
    format!(
        "--{boundary}\r\nContent-Type: {content_type}; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\r\n{value}\r\n"
    )
}

/// Prefixes a line that begins with `.`; otherwise the server would read it as the end of
/// DATA. Normalising line endings first keeps a caller's `\n` from leaking into headers.
fn dot_stuff(body: &str) -> String {
    let normalised = body.replace("\r\n", "\n").replace('\n', "\r\n");
    let mut stuffed = String::with_capacity(normalised.len() + 8);
    for line in normalised.split("\r\n") {
        if line.starts_with('.') {
            stuffed.push('.');
        }
        stuffed.push_str(line);
        stuffed.push_str("\r\n");
    }
    stuffed
}

fn check_header(field: &str, value: &str) -> Result<(), Error> {
    if value.contains(['\r', '\n']) {
        return Err(Error::Config(format!("{field} contains a line break")));
    }
    Ok(())
}

fn transport(error: impl std::fmt::Display) -> Error {
    Error::Transport(error.to_string())
}
