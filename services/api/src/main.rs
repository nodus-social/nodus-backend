//! The instance's public face: the Mastodon-compatible API, the `ActivityPub` documents
//! and the auth pages.
//!
//! The run path lives in `nodus_server_api::run` so `nodus api` starts exactly this
//! process. This binary is the deployed unit's name and nothing else.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nodus_server_api::run().await
}
