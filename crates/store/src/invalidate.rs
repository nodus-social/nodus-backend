//! Invalidation: what a committed drive write tells the caches that may have copied it.
//!
//! The writer's only obligation is to say *what* changed, once, after the commit — and to
//! say it without waiting. [`InvalidationSink`] is therefore synchronous and
//! fire-and-forget: an implementation hands the keys to a task of its own and returns.
//! A slow, wedged or dead cache can then never make a write wait, which is the whole
//! point; the price is that an invalidation may be dropped rather than block a commit.
//!
//! Two sinks ship here:
//!
//! - [`BroadcastInvalidator`] fans the keys out inside this process (an in-memory cache,
//!   a websocket fan-out) through a `tokio::sync::broadcast` channel.
//! - [`ValkeyInvalidator`] publishes one JSON line per flush to a Valkey/Redis channel so
//!   other replicas can drop the same entries. Its worker reconnects with a 1 s → 30 s
//!   backoff and logs one warning per outage, never one per attempt.
//!
//! The wire shape is documented by [`ValkeyInvalidator::payload`]:
//!
//! ```json
//! {"channel":"nodus:invalidate","keys":[{"account_id":"…","kind":"folder","id":"…"}]}
//! ```
//!
//! `kind` is one of `folder`, `object`, `parent_folder`, `attachment`, `account`. A
//! `parent_folder` key names the folder whose *child listing* changed; its `id` is the
//! parent's id, or the empty string when the listing that changed is the drive's root.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};

/// One thing that changed, in the account that owns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidationKey {
    /// The account the changed row belongs to.
    pub account_id: String,
    /// What kind of row changed.
    pub kind: InvalidationKind,
    /// The row's id. Empty for a root-level `ParentFolder` key.
    pub id: String,
}

impl InvalidationKey {
    /// A key for one row.
    #[must_use]
    pub fn new(account: &str, kind: InvalidationKind, id: impl Into<String>) -> Self {
        Self {
            account_id: account.to_owned(),
            kind,
            id: id.into(),
        }
    }

    /// The key for a folder's child listing: the parent's id, or `""` for the root.
    #[must_use]
    pub fn parent_folder(account: &str, parent: Option<uuid::Uuid>) -> Self {
        Self::new(
            account,
            InvalidationKind::ParentFolder,
            parent.map(|id| id.to_string()).unwrap_or_default(),
        )
    }
}

/// The kinds a cache may hold separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationKind {
    /// A `drive_folder` row (name, parent, subtree).
    Folder,
    /// A `drive_object` row (name, folder, visibility, state, bytes).
    Object,
    /// The child listing of a folder.
    ParentFolder,
    /// A `media_attachment` minted from a drive object.
    Attachment,
    /// Account-wide numbers, such as the used-bytes total.
    Account,
}

impl InvalidationKind {
    /// The wire name, so a log and the JSON never disagree.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Folder => "folder",
            Self::Object => "object",
            Self::ParentFolder => "parent_folder",
            Self::Attachment => "attachment",
            Self::Account => "account",
        }
    }
}

/// What the writer tells its caches after a commit.
///
/// Deliberately synchronous: the actor calls this on its own task and moves on. An
/// implementation that needs to do I/O must hand the keys to a queue or a task and
/// return — blocking here blocks every write in the process. [`DbWriter`] also guards the
/// call with `catch_unwind`, so a panicking sink cannot take the writer down.
///
/// [`DbWriter`]: crate::writer::DbWriter
pub trait InvalidationSink: Send + Sync {
    /// Marks `keys` stale. Called once per committed batch, never for a rolled-back one.
    fn invalidate(&self, keys: &[InvalidationKey]);
}

/// Default channel [`ValkeyInvalidator`] publishes on.
pub const DEFAULT_CHANNEL: &str = "nodus:invalidate";

/// How many flushes may wait for the Valkey worker before new ones are dropped.
const VALKEY_QUEUE: usize = 256;

/// Fans committed keys out inside this process, without ever blocking the writer.
///
/// `tokio::sync::broadcast` has a fixed ring per channel (1024 by default here) and its
/// `send` is synchronous and never waits: a subscriber that falls behind loses the
/// oldest values (it gets `RecvError::Lagged`) instead of slowing the producer down.
pub struct BroadcastInvalidator {
    sender: broadcast::Sender<Vec<InvalidationKey>>,
    dropped: Option<Arc<AtomicU64>>,
}

impl BroadcastInvalidator {
    /// Creates the sink and the receiver a subscriber reads from.
    #[must_use]
    pub fn new() -> (Self, broadcast::Receiver<Vec<InvalidationKey>>) {
        Self::with_capacity(1024)
    }

    /// The same, with an explicit ring size.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> (Self, broadcast::Receiver<Vec<InvalidationKey>>) {
        let (sender, receiver) = broadcast::channel(capacity.max(1));
        (
            Self {
                sender,
                dropped: None,
            },
            receiver,
        )
    }

    /// A new subscription; the sink keeps working with none.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Vec<InvalidationKey>> {
        self.sender.subscribe()
    }
}

impl std::fmt::Debug for BroadcastInvalidator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BroadcastInvalidator")
            .field("subscribers", &self.sender.receiver_count())
            .finish_non_exhaustive()
    }
}

impl Default for BroadcastInvalidator {
    fn default() -> Self {
        Self::new().0
    }
}

impl InvalidationSink for BroadcastInvalidator {
    fn invalidate(&self, keys: &[InvalidationKey]) {
        // `send` returns the number of receivers that took the message, or an error when
        // there are none. Neither is a failure: nobody listening means the in-process
        // cache is not warm, not that the write should have waited.
        if self.sender.send(keys.to_vec()).is_err() {
            if let Some(dropped) = &self.dropped {
                let count = dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if count == 1 || count % 100 == 0 {
                    tracing::debug!(dropped = count, "invalidation broadcast had no subscribers");
                }
            }
        }
    }
}

/// Publishes committed keys to a Valkey/Redis channel, from a task of its own.
///
/// The writer only ever hands the payload to a bounded queue (`try_send`); a full queue
/// drops the batch with a warning rather than delaying a commit. The worker owns the
/// connection, reconnects with a 1 s → 30 s backoff, and holds at most one pending batch
/// while it is disconnected — so a Valkey that never answers costs one warning and no
/// memory growth.
pub struct ValkeyInvalidator {
    sender: mpsc::Sender<Vec<InvalidationKey>>,
    channel: String,
}

impl ValkeyInvalidator {
    /// Starts the publisher for `url` and returns the sink.
    ///
    /// A malformed URL is not fatal: the worker logs it once and stops, and writes keep
    /// committing with invalidations off.
    #[must_use]
    pub fn spawn(url: &str, channel: &str) -> Self {
        let (sender, receiver) = mpsc::channel(VALKEY_QUEUE);
        let worker = Worker {
            url: url.to_owned(),
            channel: channel.to_owned(),
            receiver,
            dropped: Arc::new(AtomicU64::new(0)),
        };
        // Nothing awaits this handle: the sink's lifetime is the process's, and a worker
        // that ends (closed channel) has nothing left to publish.
        tokio::spawn(worker.run());
        Self {
            sender,
            channel: channel.to_owned(),
        }
    }

    /// The channel this sink publishes on.
    #[must_use]
    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// The JSON line one flush publishes: the documented wire shape.
    ///
    /// Pure and server-free on purpose, so the shape can be tested without Valkey.
    #[must_use]
    pub fn payload(keys: &[InvalidationKey]) -> String {
        #[derive(Serialize)]
        struct Event<'a> {
            channel: &'a str,
            keys: &'a [InvalidationKey],
        }
        serde_json::to_string(&Event {
            channel: DEFAULT_CHANNEL,
            keys,
        })
        .unwrap_or_else(|_| "{\"channel\":\"nodus:invalidate\",\"keys\":[]}".to_owned())
    }
}

impl std::fmt::Debug for ValkeyInvalidator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValkeyInvalidator")
            .field("channel", &self.channel)
            .finish_non_exhaustive()
    }
}

impl InvalidationSink for ValkeyInvalidator {
    fn invalidate(&self, keys: &[InvalidationKey]) {
        match self.sender.try_send(keys.to_vec()) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                // A full queue means Valkey is slow or gone. Blocking here would make the
                // writer wait on the cache; dropping a batch is the cheaper failure.
                tracing::warn!(
                    channel = %self.channel,
                    "invalidation queue full, dropped a batch"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::debug!("invalidation worker stopped");
            }
        }
    }
}

/// The connection-owning half, kept private so nothing waits on it.
struct Worker {
    url: String,
    channel: String,
    receiver: mpsc::Receiver<Vec<InvalidationKey>>,
    dropped: Arc<AtomicU64>,
}

/// Longest a worker waits between reconnects.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

impl Worker {
    async fn run(mut self) {
        let client = match redis::Client::open(self.url.as_str()) {
            Ok(client) => client,
            Err(error) => {
                tracing::warn!(%error, channel = %self.channel, "invalid valkey url; invalidations are off");
                return;
            }
        };
        let mut connection: Option<redis::aio::MultiplexedConnection> = None;
        let mut backoff = Duration::from_secs(1);
        // One warning per outage: retrying every second must not fill the log.
        let mut warned = false;

        while let Some(mut keys) = self.receiver.recv().await {
            // Connect (or reconnect) before publishing. While the outage lasts, keep only
            // the newest batch: an old listing is stale anyway once a newer one arrives,
            // and holding every batch would grow without bound.
            while connection.is_none() {
                match client.get_multiplexed_async_connection().await {
                    Ok(open) => {
                        if warned {
                            tracing::info!(channel = %self.channel, "valkey reconnected");
                        }
                        warned = false;
                        backoff = Duration::from_secs(1);
                        connection = Some(open);
                    }
                    Err(error) => {
                        if !warned {
                            tracing::warn!(
                                %error,
                                channel = %self.channel,
                                "valkey unavailable; invalidations are dropped until it answers"
                            );
                            warned = true;
                        }
                        let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                        tracing::debug!(dropped, "dropped an invalidation batch during outage");
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        while let Ok(newer) = self.receiver.try_recv() {
                            keys = newer;
                        }
                    }
                }
            }

            let payload = ValkeyInvalidator::payload(&keys);
            let publish = match connection.as_mut() {
                Some(connection) => {
                    let mut command = redis::cmd("PUBLISH");
                    command
                        .arg(&self.channel)
                        .arg(payload)
                        .query_async::<i64>(connection)
                        .await
                }
                None => continue,
            };
            if let Err(error) = publish {
                // Drop the connection and reconnect on the next batch; one warn per outage.
                connection = None;
                if !warned {
                    tracing::warn!(
                        %error,
                        channel = %self.channel,
                        "valkey publish failed; reconnecting"
                    );
                    warned = true;
                }
            }
        }
        tracing::debug!("invalidation worker stopped: sink dropped");
    }
}
