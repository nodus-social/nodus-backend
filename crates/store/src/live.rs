//! The process-local live event fan-out that feeds `GET /api/v1/streaming`.
//!
//! One publish point per write, at the place the row commits: a notification insert, a
//! status create or delete, and a mute/block change. Nothing polls, no table is scanned,
//! and a stream that nobody listens to costs one map lookup.
//!
//! The buffer is a `tokio::sync::broadcast` channel per recipient. That choice carries the
//! whole backpressure story: the ring holds [`capacity`](Hub::new) messages, not one per
//! connection, a reader that stops reading reports `Lagged(n)` instead of growing memory,
//! and it drops the *oldest* events because that is what a live timeline wants when the
//! client fell behind. Every publish is fire-and-forget, so a stalled browser can never
//! make a status create wait.
//!
//! The hub is process-local on purpose: production runs one API process
//! (`docs/15-home-timelines.md` — `NODUS_VALKEY_URL` is unset), and a second replica would
//! need a real broker rather than a fancier static. `live_streams` and the shutdown token
//! are here too so the streaming handler, the deploy's stop signal, and the log line that
//! counts what was open all read the same numbers.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tokio::sync::{broadcast, watch};

/// One thing a client may be told about. Ids only: the HTTP layer turns them into
/// Mastodon's JSON from the database, so the event is never a second copy of a DTO that
/// can drift from the read path.
#[derive(Debug, Clone)]
pub enum LiveEvent {
    /// A notification row was inserted for the recipient.
    Notification { notification_id: String },
    /// A status the recipient should see was created (own post, or a home addition).
    Update { status_id: String },
    /// A direct message reached the recipient: Mastodon's `conversation` event.
    Conversation { status_id: String },
    /// A status the recipient could see was deleted. The payload is the id.
    Delete { status_id: String },
    /// The recipient's mute/block state changed, which Mastodon reports as
    /// `filters_changed` so clients refetch.
    FiltersChanged,
}

/// How many events one recipient may fall behind before the oldest are dropped.
const DEFAULT_CAPACITY: usize = 64;

/// The largest buffer an operator may configure, so a typo cannot turn one channel into a
/// memory leak. Well above the number of events a client takes a second.
const CAPACITY_MAX: usize = 4096;

/// A subscription to one recipient's events, or to the public stream.
///
/// Dropping it is how a connection closes: the broadcast sender then reports one fewer
/// receiver, and a channel with none left is removed on the next publish.
pub struct Subscription {
    rx: broadcast::Receiver<Arc<LiveEvent>>,
    /// True for the process-wide hub, so dropping a stream updates [`live_streams`].
    counted: bool,
}

impl Subscription {
    /// The next event, waiting for one.
    ///
    /// # Errors
    ///
    /// `Lagged(n)` when the reader fell more than the buffer behind; the caller logs the
    /// count and keeps the newest events, which are still queued.
    pub async fn recv(&mut self) -> Result<Arc<LiveEvent>, broadcast::error::RecvError> {
        self.rx.recv().await
    }

    /// The next event, if one is already queued.
    ///
    /// # Errors
    ///
    /// `Lagged`, `Empty`, or `Closed`, exactly as `broadcast::Receiver::try_recv`.
    pub fn try_recv(&mut self) -> Result<Arc<LiveEvent>, broadcast::error::TryRecvError> {
        self.rx.try_recv()
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if self.counted {
            LIVE.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// The hub itself. Public only so the streaming tests can build one with a small buffer;
/// normal code goes through the free functions below.
pub struct Hub {
    capacity: usize,
    accounts: Mutex<HashMap<String, broadcast::Sender<Arc<LiveEvent>>>>,
}

impl Hub {
    /// A hub whose per-recipient ring holds `capacity` events (at least one).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.clamp(1, CAPACITY_MAX);
        Self {
            capacity,
            accounts: Mutex::new(HashMap::new()),
        }
    }

    /// Channel count, for the test that a channel with no readers is dropped.
    #[cfg(test)]
    fn channels(&self) -> usize {
        self.accounts.lock().map(|map| map.len()).unwrap_or(0)
    }

    /// This hub's ring size, for the log line and the test that proves the bound.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// A stream of one account's events. Creates the channel if this is its first reader.
    pub fn subscribe_account(&self, account_id: &str) -> Subscription {
        Subscription {
            rx: self.channel(account_id).subscribe(),
            counted: false,
        }
    }

    /// Sends one event to one account. A channel nobody reads is dropped, so a long-lived
    /// instance does not accumulate one entry per account that was ever notified.
    pub fn send_account(&self, account_id: &str, event: Arc<LiveEvent>) {
        let Ok(mut accounts) = self.accounts.lock() else {
            return;
        };
        let Some(sender) = accounts.get(account_id) else {
            return;
        };
        if sender.receiver_count() == 0 {
            accounts.remove(account_id);
            return;
        }
        // Err means every receiver went away between the check and the send; the event is
        // simply not delivered, which is what a disconnected client asked for.
        let _ = sender.send(event);
    }

    fn channel(&self, account_id: &str) -> broadcast::Sender<Arc<LiveEvent>> {
        let Ok(mut accounts) = self.accounts.lock() else {
            // A poisoned map must not panic inside a request: this one stream gets a
            // channel nobody will publish to.
            return broadcast::channel(self.capacity).0;
        };
        accounts
            .entry(account_id.to_owned())
            .or_insert_with(|| broadcast::channel(self.capacity).0)
            .clone()
    }
}

/// Streams currently open on the process-wide hub.
static LIVE: AtomicUsize = AtomicUsize::new(0);

/// The hub, built on first publish or first subscription so the buffer can come from the
/// environment without a startup wiring step.
static HUB: OnceLock<Hub> = OnceLock::new();

/// The deploy's stop signal, installed once by `serve`; the stream handler selects on it.
static SHUTDOWN: OnceLock<watch::Receiver<bool>> = OnceLock::new();

/// The process-wide hub.
fn hub() -> &'static Hub {
    HUB.get_or_init(|| {
        let capacity = std::env::var("NODUS_STREAM_BUFFER")
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(DEFAULT_CAPACITY);
        Hub::new(capacity)
    })
}

/// A stream of one account's events, counted in [`live_streams`].
#[must_use]
pub fn subscribe_account(account_id: &str) -> Subscription {
    LIVE.fetch_add(1, Ordering::Relaxed);
    let mut subscription = hub().subscribe_account(account_id);
    subscription.counted = true;
    subscription
}

/// How many streams are open right now.
#[must_use]
pub fn live_streams() -> usize {
    LIVE.load(Ordering::Relaxed)
}

/// Installs the process stop signal. Called once from the server's run path; a test that
/// never calls it simply has no shutdown to select on.
pub fn install_shutdown(receiver: watch::Receiver<bool>) {
    let _ = SHUTDOWN.set(receiver);
}

/// The stop signal, if this process installed one.
#[must_use]
pub fn shutdown() -> Option<watch::Receiver<bool>> {
    SHUTDOWN.get().cloned()
}

/// Logs how many streams are open at the moment the deploy asked them to close.
pub fn begin_shutdown() {
    tracing::info!(streams = live_streams(), "closing live streams");
}

/// A notification was created for `account_id`.
pub fn notification(account_id: &str, notification_id: &str) {
    hub().send_account(
        account_id,
        Arc::new(LiveEvent::Notification {
            notification_id: notification_id.to_owned(),
        }),
    );
}

/// A status was created: to its author and to the home timelines the same transaction
/// fanned it out to.
///
/// `home` is the `timeline_entry` fan-out, not a second computation of follows. Accounts
/// above the big-account cut-off have no rows there, so their followers' home streams miss
/// the event; their reads already merge at request time, and building a push fan-out for
/// that case is the thing this slice deliberately does not do.
pub fn status_created(
    account_id: &str,
    status_id: &str,
    visibility: &str,
    mentions: &[String],
    home: &[String],
) {
    let update = Arc::new(LiveEvent::Update {
        status_id: status_id.to_owned(),
    });
    hub().send_account(account_id, update.clone());
    if visibility == "direct" {
        let conversation = Arc::new(LiveEvent::Conversation {
            status_id: status_id.to_owned(),
        });
        for mention in mentions {
            hub().send_account(mention, conversation.clone());
        }
    }
    let mut told: HashSet<&str> = HashSet::with_capacity(home.len() + 1);
    told.insert(account_id);
    for recipient in home {
        if told.insert(recipient.as_str()) {
            hub().send_account(recipient, update.clone());
        }
    }
}

/// A status was deleted. Same recipients as [`status_created`], minus mentions: the id is
/// all a client needs to drop it, and a status it never showed costs one lookup.
pub fn status_deleted(account_id: &str, status_id: &str, home: &[String]) {
    let event = Arc::new(LiveEvent::Delete {
        status_id: status_id.to_owned(),
    });
    hub().send_account(account_id, event.clone());
    let mut told: HashSet<&str> = HashSet::with_capacity(home.len() + 1);
    told.insert(account_id);
    for recipient in home {
        if told.insert(recipient.as_str()) {
            hub().send_account(recipient, event.clone());
        }
    }
}

/// The account's mute or block state changed.
pub fn filters_changed(account_id: &str) {
    hub().send_account(account_id, Arc::new(LiveEvent::FiltersChanged));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The point of the ring: a reader that stops pulling drops the oldest events and
    /// keeps a fixed amount of memory, however many are published.
    #[tokio::test]
    async fn a_stalled_reader_drops_the_oldest_and_stays_bounded() {
        let hub = Hub::new(8);
        let mut subscription = hub.subscribe_account("acct");
        for index in 0..1000 {
            hub.send_account(
                "acct",
                Arc::new(LiveEvent::Update {
                    status_id: format!("status-{index}"),
                }),
            );
        }
        let mut lagged = 0;
        let mut delivered = 0;
        loop {
            match subscription.try_recv() {
                Ok(_) => delivered += 1,
                Err(broadcast::error::TryRecvError::Lagged(dropped)) => lagged += dropped,
                Err(
                    broadcast::error::TryRecvError::Empty | broadcast::error::TryRecvError::Closed,
                ) => break,
            }
        }
        assert!(lagged > 0, "the stalled reader should have missed events");
        assert!(
            delivered <= hub.capacity(),
            "delivered {delivered} events from a {} slot buffer",
            hub.capacity()
        );
        assert_eq!(lagged + delivered as u64, 1000);
    }

    #[tokio::test]
    async fn a_closed_channel_is_not_kept() {
        let hub = Hub::new(4);
        {
            let _stalled = hub.subscribe_account("acct");
        }
        hub.send_account("acct", Arc::new(LiveEvent::FiltersChanged));
        assert_eq!(hub.channels(), 0);
    }
}
