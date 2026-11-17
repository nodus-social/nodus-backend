//! The bounded memory a service keeps of its own log.
//!
//! A restart is allowed to lose it: this is for looking at what a service is doing right now,
//! not for an audit trail, which is what the database and the log files are for.

use std::collections::VecDeque;
use std::sync::Mutex;

use nodus_server_proto::telemetry::LogEntry;

/// How many entries a service keeps.
pub const CAPACITY: usize = 500;

pub struct Ring {
    capacity: usize,
    entries: Mutex<VecDeque<LogEntry>>,
}

impl Ring {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(VecDeque::with_capacity(capacity)),
        }
    }

    pub fn push(&self, entry: LogEntry) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        while entries.len() >= self.capacity {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// The newest `limit` entries at or above `min_level`, oldest first.
    #[must_use]
    pub fn snapshot(&self, min_level: i32, limit: usize) -> Vec<LogEntry> {
        let Ok(entries) = self.entries.lock() else {
            return Vec::new();
        };
        let keep: Vec<LogEntry> = entries
            .iter()
            .rev()
            .filter(|entry| entry.level >= min_level)
            .take(limit)
            .cloned()
            .collect();
        keep.into_iter().rev().collect()
    }
}
