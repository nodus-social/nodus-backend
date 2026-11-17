//! What every Nodus service answers when asked how it is doing.
//!
//! The numbers are this process's own: CPU and memory of this PID, never the machine's, so a
//! service on a busy host does not look like the problem. Logs live in a bounded ring in
//! memory and in a broadcast channel, so a reader can see what just happened without the
//! service writing anywhere it might not be allowed to.

mod agent;
mod layer;
mod ring;
mod serve;

pub use agent::{entry, Agent, Node, Sampler};
pub use layer::TelemetryLayer;
pub use ring::{Ring, CAPACITY};
pub use serve::{serve, serve_with, Error};

pub use nodus_server_proto::telemetry;
