//! `nodus-media` — the bytes half of the media surface.
//!
//! The run path lives in `nodus_server_media::run` so `nodus media-worker` starts exactly
//! this process. This binary is the deployed unit's name and nothing else.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nodus_server_media::run().await
}
