//! Recommendations, browsing and the sync endpoints the client reads.
//!
//! The engine keeps its tables in their own schema, so this service migrates them
//! separately from the instance's own history and can be restarted without touching it.

use std::error::Error;
use std::sync::Arc;

use nodus_server_runtime as runtime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let agent = runtime::init("feed");
    let config = runtime::read()?;
    let telemetry = config
        .telemetry
        .clone()
        .map(|address| runtime::serve_telemetry(address, Arc::clone(&agent)));

    if config.migrate_only {
        nodus_feeds::prepare(&config.database_url, config.database_connections).await?;
        tracing::info!("migrations applied");
        runtime::stop_telemetry(telemetry).await;
        return Ok(());
    }

    let router = nodus_feeds::mount(
        &config.database_url,
        &config.instance.base_url,
        config.database_connections,
    )
    .await?;
    tracing::info!(address = %config.bind, "feed listening");
    nodus_server_transport::serve_http(&config.bind, router, runtime::shutdown()).await?;
    runtime::stop_telemetry(telemetry).await;
    Ok(())
}
