//! The pruning service: media, sessions, codes and stale rows, on a clock.
//!
//! The run path lives in `nodus_server_prune::run` so `nodus prune` starts exactly this
//! process. This binary is the deployed unit's name and nothing else.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nodus_server_prune::run().await
}
