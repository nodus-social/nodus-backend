//! What every Nodus service needs before it does anything.
//!
//! Each service is its own binary and its own systemd unit, so the parts they agree on
//! live here rather than in five copies: how the environment is read, how a stop looks,
//! how the process reports on itself, and how the database is prepared. Nothing in this
//! crate knows what a service does with a request.

mod boot;
mod config;
mod media;
mod telemetry;

pub use boot::{init, prepare, provision_bootstrap, shutdown};
pub use config::{read, Bootstrap, Config, DEFAULT_BIND, DEFAULT_DATABASE_URL};
pub use media::{media_dir, prune_media, prune_media_in, variants_dir};
pub use telemetry::stop as stop_telemetry;
pub use telemetry::{serve_telemetry, serve_worker, Telemetry};
