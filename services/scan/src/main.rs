//! The scanning service: it asks the configured scanners about new content and applies
//! what they say.
//!
//! The run path lives in `nodus_server_scan::run` so `nodus scan` starts exactly this
//! process. This binary is the deployed unit's name and nothing else.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nodus_server_scan::run().await
}
