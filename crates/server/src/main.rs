#![allow(clippy::doc_markdown)]

//! The monolith runtime.
//!
//! One listener serves the ActivityPub documents, the Mastodon-compatible API and the
//! auth pages. Splitting a service out is a deployment change; this binary is the
//! default composition.

use std::env;
use std::error::Error;
use std::net::SocketAddr;

use axum::Router;
use nodus_auth::store::PgAuthStore;
use nodus_server_api::{AppState, InstanceConfig};
use nodus_server_store::Store;

const DEFAULT_BIND: &str = "0.0.0.0:3000";
const DEFAULT_DATABASE_URL: &str = "postgres://nodus:nodus@localhost/nodus";

#[derive(Debug, Clone)]
struct Config {
    bind: SocketAddr,
    database_url: String,
    database_connections: u32,
    instance: InstanceConfig,
    secure_cookies: bool,
    migrate_only: bool,
    bootstrap: Option<Bootstrap>,
}

#[derive(Debug, Clone)]
struct Bootstrap {
    email: String,
    username: String,
    password: String,
}

impl Config {
    fn from_env() -> Result<Self, Box<dyn Error>> {
        let domain = env::var("NODUS_DOMAIN").unwrap_or_else(|_| "localhost".to_owned());
        let base_url = env::var("NODUS_BASE_URL")
            .unwrap_or_else(|_| format!("https://{domain}"))
            .trim_end_matches('/')
            .to_owned();
        let bind = env::var("NODUS_BIND")
            .unwrap_or_else(|_| DEFAULT_BIND.to_owned())
            .parse()?;
        let database_connections = env::var("NODUS_DATABASE_CONNECTIONS")
            .ok()
            .map(|value| value.parse())
            .transpose()?
            .unwrap_or(10);
        let secure_cookies =
            env::var("NODUS_AUTH_SECURE_COOKIES").map_or(Ok(true), |value| value.parse())?;
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

        Ok(Self {
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
            },
            secure_cookies,
            migrate_only: env::args().any(|argument| argument == "--migrate-only"),
            bootstrap,
        })
    }
}

fn app(store: &Store, config: &Config) -> Router {
    let api = nodus_server_api::root_router(AppState::new(store.clone(), config.instance.clone()));
    let auth = nodus_auth::router(nodus_auth::AppState::new(
        PgAuthStore::new(store.pool().clone()),
        nodus_auth::Config {
            domain: config.instance.domain.clone(),
            issuer: config.instance.base_url.clone(),
            secure_cookies: config.secure_cookies,
        },
    ));
    api.merge(auth)
}

async fn provision_bootstrap(store: &Store, bootstrap: &Bootstrap) -> Result<(), Box<dyn Error>> {
    use nodus_server_store::accounts;

    let account = match accounts::local_by_username(store.pool(), &bootstrap.username).await? {
        Some(account) => account,
        None => {
            accounts::insert(
                store.pool(),
                &accounts::NewAccount {
                    username: &bootstrap.username,
                    display_name: &bootstrap.username,
                    note: "",
                    bot: false,
                    locked: false,
                },
            )
            .await?
        }
    };

    accounts::set_admin(store.pool(), &account.id, true).await?;
    let auth = PgAuthStore::new(store.pool().clone());
    if auth.has_credential(&bootstrap.email).await? {
        tracing::info!(username = %account.username, "bootstrap user already has a login");
        return Ok(());
    }
    let password_hash = nodus_auth::hash_password(&bootstrap.password)
        .map_err(|error| std::io::Error::other(format!("password hash failed: {error}")))?;
    auth.create_credential(&account.id, &bootstrap.email, &password_hash)
        .await?;
    tracing::info!(username = %account.username, "bootstrap user created as administrator");
    Ok(())
}

async fn shutdown() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
    tracing::info!("shutting down");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=info".into()),
        )
        .init();

    let config = Config::from_env()?;
    let store = Store::connect(&config.database_url, config.database_connections).await?;

    if config.migrate_only {
        store.migrate().await?;
        tracing::info!("migrations applied");
        return Ok(());
    }

    store.migrate().await?;
    if let Some(bootstrap) = &config.bootstrap {
        provision_bootstrap(&store, bootstrap).await?;
    }
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    tracing::info!(
        address = %config.bind,
        domain = %config.instance.domain,
        "nodus server listening"
    );
    axum::serve(
        listener,
        app(&store, &config).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::*;

    fn config() -> Config {
        Config {
            bind: "127.0.0.1:0".parse().expect("bind"),
            database_url: "postgres://nodus:nodus@127.0.0.1:1/nodus".to_owned(),
            database_connections: 1,
            instance: InstanceConfig {
                domain: "social.test".to_owned(),
                base_url: "https://social.test".to_owned(),
                title: "Nodus test".to_owned(),
                description: String::new(),
                contact_email: None,
                api_version: "4.3.0".to_owned(),
                version: "0.1.0".to_owned(),
            },
            secure_cookies: true,
            migrate_only: false,
            bootstrap: None,
        }
    }

    #[tokio::test]
    async fn the_monolith_router_serves_health_and_auth_metadata() {
        let store = Store::connect_lazy(&config().database_url, 1);
        let app = app(&store, &config());

        let health = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(health.status(), StatusCode::OK);

        let metadata = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oauth-authorization-server")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(metadata.status(), StatusCode::OK);
    }
}
