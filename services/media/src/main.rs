//! `nodus-media` — the bytes half of the media surface.
//!
//! Uploads belong to the API: they authenticate a user, write a catalogue row and queue the
//! variants. Reading them back does not, and it is the part that moves bytes, so it lives
//! here and can be sized, restarted and moved on its own.

#![forbid(unsafe_code)]

use std::error::Error;
use std::sync::Arc;

use nodus_server_runtime::{self as runtime, Config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let agent = runtime::init("media");
    let config: Config = runtime::read()?;
    let telemetry = config
        .telemetry
        .clone()
        .map(|address| runtime::serve_telemetry(address, Arc::clone(&agent)));

    let store = runtime::prepare(&config).await?;
    if config.migrate_only {
        tracing::info!("migrations applied");
        runtime::stop_telemetry(telemetry).await;
        return Ok(());
    }

    let serving = Arc::new(nodus_server_media::serve::Serving::new(
        store.pool().clone(),
        runtime::media_dir(),
        runtime::variants_dir(),
    ));
    tracing::info!(
        address = %config.bind,
        domain = %config.instance.domain,
        "media listening"
    );
    nodus_server_transport::serve_http(
        &config.bind,
        serving.router(),
        runtime::shutdown(),
    )
    .await?;
    runtime::stop_telemetry(telemetry).await;
    Ok(())
}
