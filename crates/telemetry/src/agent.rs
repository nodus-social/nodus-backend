//! One process describing itself: what it is, what it costs, and what it just said.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use nodus_server_proto::telemetry::{
    telemetry_server::Telemetry, Empty, Health, Level, LogEntry, LogStreamRequest, NodeTelemetry,
};
use sysinfo::{Pid, ProcessesToUpdate, System};
use tokio::sync::broadcast;
use tonic::{Request, Response, Status};

use crate::ring::Ring;

/// How many live subscribers may fall behind before their entries are dropped.
const LIVE_CAPACITY: usize = 256;

/// What this process is called in the topology.
#[derive(Debug, Clone)]
pub struct Node {
    pub name: String,
    pub version: String,
}

/// Reads this process's own share of the machine.
///
/// The first read reports no CPU: `sysinfo` computes usage from the interval between two
/// refreshes, and there is no earlier one yet.
pub struct Sampler {
    system: System,
    pid: Pid,
}

impl Sampler {
    #[must_use]
    pub fn new() -> Self {
        let pid = Pid::from_u32(std::process::id());
        let mut system = System::new();
        system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
        Self { system, pid }
    }

    pub fn sample(&mut self) -> (f64, u64) {
        self.system
            .refresh_processes(ProcessesToUpdate::Some(&[self.pid]), true);
        self.system.process(self.pid).map_or((0.0, 0), |process| {
            (f64::from(process.cpu_usage()), process.memory())
        })
    }
}

impl Default for Sampler {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Agent {
    node: Node,
    ring: Arc<Ring>,
    live: broadcast::Sender<LogEntry>,
    sampler: Mutex<Sampler>,
    started: Instant,
    queue: Option<Arc<dyn Fn() -> u64 + Send + Sync>>,
    degraded: Arc<AtomicU64>,
}

impl Agent {
    #[must_use]
    pub fn new(node: Node) -> Arc<Self> {
        Arc::new(Self {
            node,
            ring: Arc::new(Ring::new(crate::ring::CAPACITY)),
            live: broadcast::channel(LIVE_CAPACITY).0,
            sampler: Mutex::new(Sampler::new()),
            started: Instant::now(),
            queue: None,
            degraded: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Reports a queue a service drains, so the console can show work waiting.
    #[must_use]
    pub fn with_queue(mut self: Arc<Self>, queue: Arc<dyn Fn() -> u64 + Send + Sync>) -> Arc<Self> {
        Arc::get_mut(&mut self)
            .expect("the agent is configured before it is shared")
            .queue = Some(queue);
        self
    }

    #[must_use]
    pub fn ring(&self) -> Arc<Ring> {
        Arc::clone(&self.ring)
    }

    #[must_use]
    pub fn live(&self) -> broadcast::Sender<LogEntry> {
        self.live.clone()
    }

    pub fn mark_degraded(&self) {
        self.degraded.fetch_add(1, Ordering::Relaxed);
    }
}

/// The service wrapper.
///
/// The gRPC trait is foreign, so it cannot be implemented on `Arc<Agent>`; this newtype is
/// the one type the server builder needs.
pub struct Service {
    agent: Arc<Agent>,
}

impl Service {
    #[must_use]
    pub fn new(agent: Arc<Agent>) -> Self {
        Self { agent }
    }
}

#[tonic::async_trait]
impl Telemetry for Service {
    async fn get_node_telemetry(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<NodeTelemetry>, Status> {
        let (cpu, rss) = self
            .agent
            .sampler
            .lock()
            .map_or((0.0, 0), |mut sampler| sampler.sample());
        let waiting = self.agent.queue.as_ref().map(|queue| queue());
        let telemetry = NodeTelemetry {
            service_name: self.agent.node.name.clone(),
            binary_version: self.agent.node.version.clone(),
            uptime_seconds: self.agent.started.elapsed().as_secs(),
            cpu_usage_percent: cpu,
            rss_memory_bytes: rss,
            queue_depth: waiting,
            status: if self.agent.degraded.load(Ordering::Relaxed) == 0 {
                Health::Healthy as i32
            } else {
                Health::Degraded as i32
            },
        };
        Ok(Response::new(telemetry))
    }

    type StreamLogsStream = tokio_stream::wrappers::ReceiverStream<Result<LogEntry, Status>>;

    async fn stream_logs(
        &self,
        request: Request<LogStreamRequest>,
    ) -> Result<Response<Self::StreamLogsStream>, Status> {
        let asked = request.into_inner();
        let limit = if asked.buffered == 0 {
            crate::ring::CAPACITY
        } else {
            usize::try_from(asked.buffered).unwrap_or(crate::ring::CAPACITY)
        };
        let buffered = self.agent.ring.snapshot(asked.min_level, limit);
        let mut live = self.agent.live.subscribe();
        let min_level = asked.min_level;
        let (tx, rx) = tokio::sync::mpsc::channel(64);

        tokio::spawn(async move {
            for entry in buffered {
                if tx.send(Ok(entry)).await.is_err() {
                    return;
                }
            }
            loop {
                match live.recv().await {
                    Ok(entry) if entry.level >= min_level => {
                        if tx.send(Ok(entry)).await.is_err() {
                            return;
                        }
                    }
                    // A reader that fell behind keeps following: the ring still holds the
                    // entries it missed, and ending the stream would hide everything after.
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }
}

/// Turns one tracing event into an entry, copying the parts the console renders.
pub fn entry(level: tracing::Level, target: &str, message: String) -> LogEntry {
    let level = match level {
        tracing::Level::TRACE => Level::Trace,
        tracing::Level::DEBUG => Level::Debug,
        tracing::Level::INFO => Level::Info,
        tracing::Level::WARN => Level::Warn,
        tracing::Level::ERROR => Level::Error,
    };
    LogEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        level: level as i32,
        target: target.to_owned(),
        message,
    }
}
