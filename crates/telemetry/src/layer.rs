//! The subscriber layer that makes a service's log reachable without a log file.

use std::fmt::Debug;
use std::sync::Arc;

use nodus_server_proto::telemetry::LogEntry;
use tokio::sync::broadcast;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

use crate::agent::entry;
use crate::ring::Ring;

pub struct TelemetryLayer {
    ring: Arc<Ring>,
    live: broadcast::Sender<LogEntry>,
}

impl TelemetryLayer {
    #[must_use]
    pub fn new(ring: Arc<Ring>, live: broadcast::Sender<LogEntry>) -> Self {
        Self { ring, live }
    }
}

impl<S> Layer<S> for TelemetryLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let metadata = event.metadata();
        let mut visitor = Message::default();
        event.record(&mut visitor);
        let message = visitor.finish();
        if message.is_empty() {
            return;
        }
        let entry = entry(*metadata.level(), metadata.target(), message);
        self.ring.push(entry.clone());
        // No subscriber is not an error: the ring still has it.
        let _ = self.live.send(entry);
    }
}

/// Collects the `message` field, and every other field as `key=value` after it, which is how
/// a service's own log lines read in a file and should read here.
#[derive(Default)]
struct Message {
    message: String,
    rest: Vec<String>,
}

impl Message {
    fn finish(self) -> String {
        if self.rest.is_empty() {
            return self.message;
        }
        let rest = self.rest.join(" ");
        if self.message.is_empty() {
            rest
        } else {
            format!("{} {}", self.message, rest)
        }
    }
}

impl Visit for Message {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_owned();
        } else {
            self.rest.push(format!("{}={value}", field.name()));
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            self.rest.push(format!("{}={value:?}", field.name()));
        }
    }
}
