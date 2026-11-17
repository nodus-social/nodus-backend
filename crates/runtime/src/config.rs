//! What a service is told when it starts.

use std::env;
use std::error::Error;

use nodus_server_core::instance::InstanceConfig;
use nodus_server_transport::Address;

/// The address a service takes when its unit says nothing. Every unit does say
/// something: this default exists so a developer can run a binary with no environment.
pub const DEFAULT_BIND: &str = "0.0.0.0:3000";
pub const DEFAULT_DATABASE_URL: &str = "postgres://nodus:nodus@localhost/nodus";

pub struct Config {
    /// Where this service accepts requests. A socket or a port; the binaries do not care.
    pub bind: Address,
    pub database_url: String,
    pub database_connections: u32,
    pub instance: InstanceConfig,
    pub secure_cookies: bool,
    /// Whether `/auth/register` accepts new accounts. Off unless the operator opts in.
    pub registrations_open: bool,
    pub migrate_only: bool,
    pub bootstrap: Option<Bootstrap>,
    /// Where this process answers questions about itself, if anywhere.
    pub telemetry: Option<Address>,
}

#[derive(Debug, Clone)]
pub struct Bootstrap {
    pub email: String,
    pub username: String,
    pub password: String,
}

/// Read the process-wide settings, and the instance identity that every service needs
/// to build an absolute URL.
///
/// # Errors
///
/// Fails on an address that does not parse, a number that is not a number, or a
/// half-given bootstrap login — each of which is a deployment mistake that would
/// otherwise show up much later as a wrong link or a forgotten password.
pub fn read() -> Result<Config, Box<dyn Error>> {
    let domain = env::var("NODUS_DOMAIN").unwrap_or_else(|_| "localhost".to_owned());
    let base_url = env::var("NODUS_BASE_URL")
        .unwrap_or_else(|_| format!("https://{domain}"))
        .trim_end_matches('/')
        .to_owned();
    let bind = nodus_server_transport::parse(
        &env::var("NODUS_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_owned()),
    )?;
    let database_connections = env::var("NODUS_DATABASE_CONNECTIONS")
        .ok()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(10);
    let secure_cookies =
        env::var("NODUS_AUTH_SECURE_COOKIES").map_or(Ok(true), |value| value.parse())?;
    let registrations_open =
        env::var("NODUS_REGISTRATIONS_OPEN").map_or(Ok(false), |value| value.parse())?;
    let bootstrap = match (
        env::var("NODUS_BOOTSTRAP_EMAIL"),
        env::var("NODUS_BOOTSTRAP_USERNAME"),
        env::var("NODUS_BOOTSTRAP_PASSWORD"),
    ) {
        (Ok(email), Ok(username), Ok(password)) => Some(Bootstrap {
            email,
            username,
            password,
        }),
        (Err(_), Err(_), Err(_)) => None,
        _ => {
            return Err("NODUS_BOOTSTRAP_EMAIL, NODUS_BOOTSTRAP_USERNAME and \
                 NODUS_BOOTSTRAP_PASSWORD must be set together"
                .into())
        }
    };
    let telemetry = match (
        env::var("NODUS_TELEMETRY_SOCKET").ok(),
        env::var("NODUS_TELEMETRY_BIND").ok(),
    ) {
        (Some(path), None) => Some(nodus_server_transport::parse(&path)?),
        (None, Some(address)) => Some(nodus_server_transport::parse(&address)?),
        (None, None) => None,
        (Some(_), Some(_)) => {
            return Err("set NODUS_TELEMETRY_SOCKET or NODUS_TELEMETRY_BIND, not both".into())
        }
    };

    Ok(Config {
        bind,
        database_url: env::var("NODUS_DATABASE_URL")
            .unwrap_or_else(|_| DEFAULT_DATABASE_URL.to_owned()),
        database_connections,
        instance: InstanceConfig {
            domain,
            base_url,
            title: env::var("NODUS_TITLE").unwrap_or_else(|_| "Nodus".to_owned()),
            description: env::var("NODUS_DESCRIPTION").unwrap_or_default(),
            contact_email: env::var("NODUS_CONTACT_EMAIL").ok(),
            api_version: "4.3.0".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            registrations_open,
        },
        secure_cookies,
        registrations_open,
        migrate_only: env::args().any(|argument| argument == "--migrate-only"),
        bootstrap,
        telemetry,
    })
}
