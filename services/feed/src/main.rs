//! Recommendations, browsing and the sync endpoints the client reads.
//!
//! The run path lives in `nodus_server_feed` so `nodus` starts exactly this process.
//! This binary is the deployed unit's name and nothing else.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nodus_server_feed::run().await
}
