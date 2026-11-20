//! The recommendation engine's heavy half: crawling, recomputing and retention.
//!
//! The run path lives in `nodus_server_calc::run` so `nodus calc` starts exactly this
//! process. This binary is the deployed unit's name and nothing else.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nodus_server_calc::run().await
}
