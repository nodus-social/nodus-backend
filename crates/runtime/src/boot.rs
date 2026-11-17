//! Starting and stopping a service.

use std::error::Error;

use nodus_auth::store::PgAuthStore;
use nodus_server_store::Store;
use nodus_server_telemetry::{Agent, Node, TelemetryLayer};

use crate::config::{Bootstrap, Config};

/// Install the subscriber, and return the agent that will report on this process.
///
/// The agent exists before logging so the ring buffer sees every line from the first
/// one: a service that dies during start-up is exactly the one whose log matters.
#[must_use]
pub fn init(node: &str) -> std::sync::Arc<Agent> {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let agent = Agent::new(Node {
        name: std::env::var("NODUS_NODE_NAME").unwrap_or_else(|_| node.to_owned()),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    });
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(TelemetryLayer::new(agent.ring(), agent.live()))
        .init();
    agent
}

/// Connect, migrate, and create the bootstrap administrator when one was asked for.
///
/// # Errors
///
/// Fails when the database cannot be reached or migrated, which means this service has
/// nothing to serve and should not pretend otherwise.
pub async fn prepare(config: &Config) -> Result<Store, Box<dyn Error>> {
    let store = Store::connect(&config.database_url, config.database_connections).await?;
    store.migrate().await?;
    if let Some(bootstrap) = &config.bootstrap {
        provision_bootstrap(&store, bootstrap).await?;
    }
    Ok(store)
}

/// Make the named account an administrator with a password login, once.
///
/// # Errors
///
/// Fails when the email is already bound to a different account, which would otherwise
/// silently leave an operator locked out of the instance they just provisioned.
pub async fn provision_bootstrap(
    store: &Store,
    bootstrap: &Bootstrap,
) -> Result<(), Box<dyn Error>> {
    use nodus_server_store::accounts;

    let mut tx = store.pool().begin().await?;

    let account = match accounts::local_by_username(&mut *tx, &bootstrap.username).await? {
        Some(account) => account,
        None => {
            accounts::insert(
                &mut *tx,
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

    if PgAuthStore::has_credential_for_account_with(&mut *tx, &account.id).await? {
        accounts::set_admin(&mut *tx, &account.id, true).await?;
        tx.commit().await?;
        tracing::info!(username = %account.username, "bootstrap user already has a login");
        return Ok(());
    }

    if PgAuthStore::has_credential_with(&mut *tx, &bootstrap.email).await? {
        return Err(std::io::Error::other(format!(
            "bootstrap email {} is already bound to another account",
            bootstrap.email
        ))
        .into());
    }

    accounts::set_admin(&mut *tx, &account.id, true).await?;
    let password_hash = nodus_auth::hash_password(&bootstrap.password)
        .map_err(|error| std::io::Error::other(format!("password hash failed: {error}")))?;
    PgAuthStore::create_credential_with(&mut *tx, &account.id, &bootstrap.email, &password_hash)
        .await?;
    tx.commit().await?;
    tracing::info!(username = %account.username, "bootstrap user created as administrator");
    Ok(())
}

/// Resolve when this process is asked to stop.
pub async fn shutdown() {
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
