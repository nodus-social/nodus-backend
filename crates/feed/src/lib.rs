//! The process around the recommendation, browsing and sync surface.
//!
//! The routes themselves live in `nodus-feeds`, in the recommendation engine's workspace.
//! This crate holds the part a deployed unit needs — configuration, logging, the
//! listener — so `nodus-feed` and the `nodus` entrypoint start the same process.

use std::future::Future;

use anyhow::anyhow;
use nodus_server_runtime::{self as runtime, Config};
use nodus_store::crypto::TokenSealer;

/// What `nodus feed` starts and where it listens, without binding.
#[must_use]
pub fn plan() -> (&'static str, &'static str, String) {
    let bind = std::env::var("NODUS_BIND").unwrap_or_else(|_| runtime::DEFAULT_BIND.to_owned());
    ("feed", "nodus_server_feed::run", bind)
}

/// Run the feed service as its own process, with its own logging, telemetry and stop
/// signal.
///
/// # Errors
///
/// Fails when the configuration is wrong, the engine schema cannot be prepared, or the
/// listener cannot bind.
pub async fn run() -> anyhow::Result<()> {
    let agent = runtime::init("feed");
    let config = runtime::read().map_err(|error| anyhow!("{error}"))?;
    let telemetry = config
        .telemetry
        .clone()
        .map(|address| runtime::serve_telemetry(address, agent));

    let result = serve(config, runtime::shutdown()).await;
    runtime::stop_telemetry(telemetry).await;
    result
}

/// Serve the feed routes on `config.bind` until `shutdown` resolves.
///
/// # Errors
///
/// Fails when the engine schema cannot be prepared or the listener cannot bind.
pub async fn serve<F>(config: Config, shutdown: F) -> anyhow::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    if config.migrate_only {
        nodus_feeds::prepare(&config.database_url, config.database_connections).await?;
        tracing::info!("migrations applied");
        return Ok(());
    }

    let sealer = token_enc_key(&config)?;
    if sealer.is_some() {
        // The positive half of the warning below: an operator reading the journal can
        // tell the sync surface is armed without calling it.
        tracing::info!("TOKEN_ENC_KEY loaded; background sync can seal stored tokens");
    }
    let router = nodus_feeds::mount(
        &config.database_url,
        &config.instance.base_url,
        config.database_connections,
        sealer,
    )
    .await?;
    tracing::info!(address = %config.bind, "feed listening");
    nodus_server_transport::serve_http(&config.bind, router, shutdown).await?;
    Ok(())
}

/// Parse `TOKEN_ENC_KEY` into the sealer the sync surface needs.
///
/// Absent is not fatal — a deployment may choose not to sync — but `/api/v1/meta`
/// advertises `sync_token`, so the feed says out loud what a caller will hit instead of
/// letting the capability fail quietly. A value that is present and unusable stops the
/// process: that is a mistyped key, not a choice.
fn token_enc_key(config: &Config) -> anyhow::Result<Option<TokenSealer>> {
    let Some(raw) = config.token_enc_key.as_deref() else {
        tracing::warn!(
            "TOKEN_ENC_KEY is not set; /api/v1/meta advertises sync_token but \
             POST /api/v1/sync/authorize will answer 503 sync_disabled"
        );
        return Ok(None);
    };
    TokenSealer::from_base64(raw)
        .map(Some)
        .map_err(|error| anyhow!("TOKEN_ENC_KEY is not usable: {error}"))
}
