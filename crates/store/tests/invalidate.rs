//! What the invalidation publisher does when Valkey is gone.
//!
//! The writer calls [`InvalidationSink::invalidate`] synchronously after a commit, so the
//! sink must never wait on a socket. The contract proved here is the failure mode: a full
//! bounded queue drops a batch with a warning and returns, the worker warns once per
//! outage, and the next batch after the broker returns is published. The broker is a
//! ~100-line RESP server in this file, so the case runs with no Valkey installed.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing_subscriber::layer::SubscriberExt;

use nodus_server_store::invalidate::{
    InvalidationKey, InvalidationKind, InvalidationSink, ValkeyInvalidator, DEFAULT_CHANNEL,
};

/// `VALKEY_QUEUE` in `crates/store/src/invalidate.rs:123`. The store crate cannot import
/// its own private constant from an integration test, so the number is repeated: if the
/// two drift, the overflow case stops overflowing and the warning assertion notices.
const QUEUE: usize = 256;

/// Warnings recorded for the whole test binary.
///
/// A global subscriber rather than a thread-local one: the warn being asserted comes from
/// the worker task, which the runtime may poll on any thread.
static WARNINGS: OnceLock<Arc<Mutex<Vec<String>>>> = OnceLock::new();

fn capture_warnings() -> &'static Arc<Mutex<Vec<String>>> {
    WARNINGS.get_or_init(|| {
        let warnings = Arc::new(Mutex::new(Vec::new()));
        let subscriber =
            tracing_subscriber::registry().with(CaptureWarnings(Arc::clone(&warnings)));
        tracing::subscriber::set_global_default(subscriber)
            .expect("install the warning capture once per test binary");
        warnings
    })
}

struct CaptureWarnings(Arc<Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureWarnings {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        let mut message = String::new();
        event.record(&mut Message(&mut message));
        if !message.is_empty() {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(message);
        }
    }
}

struct Message<'a>(&'a mut String);

impl tracing::field::Visit for Message<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        }
    }
}

fn warning_count(warnings: &Mutex<Vec<String>>, needle: &str) -> usize {
    warnings
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|warning| warning.contains(needle))
        .count()
}

async fn wait_for_warning(warnings: &Mutex<Vec<String>>, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while warning_count(warnings, needle) == 0 {
        assert!(
            Instant::now() < deadline,
            "no warning containing {needle:?} in 5s"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A broker that can be "down" (nothing bound) and then "up" (a listener on the same port).
///
/// Only the handshake and `PUBLISH` are implemented: `CLIENT SETINFO` (the redis-rs
/// handshake) gets `+OK`, `PUBLISH` records the payload and answers `:0`.
struct FakeValkey {
    address: SocketAddr,
    published: Arc<Mutex<Vec<String>>>,
}

impl FakeValkey {
    async fn new() -> Self {
        // Reserve an ephemeral port, then close it so the invalidator's first connection is
        // refused. The port is reused when the broker comes back up.
        let probe = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve a port for the fake broker");
        let address = probe.local_addr().expect("probe address");
        drop(probe);
        Self {
            address,
            published: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn url(&self) -> String {
        format!("redis://{}", self.address)
    }

    fn published(&self) -> Vec<String> {
        self.published
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    async fn start(&self) {
        let listener = TcpListener::bind(self.address)
            .await
            .expect("bind the fake broker");
        let published = Arc::clone(&self.published);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let published = Arc::clone(&published);
                tokio::spawn(async move { serve(socket, published).await });
            }
        });
    }
}

async fn serve(mut socket: TcpStream, published: Arc<Mutex<Vec<String>>>) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let Ok(read) = socket.read(&mut chunk).await else {
            return;
        };
        if read == 0 {
            return;
        }
        buffer.extend_from_slice(&chunk[..read]);
        while let Some((command, consumed)) = next_command(&buffer) {
            buffer.drain(..consumed);
            let reply = match command.first().map(|name| name.to_ascii_uppercase()) {
                Some(name) if name == "PUBLISH" => {
                    if let Some(payload) = command.get(2) {
                        published
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(payload.clone());
                    }
                    ":0\r\n".to_owned()
                }
                Some(name) if name == "PING" => "+PONG\r\n".to_owned(),
                _ => "+OK\r\n".to_owned(),
            };
            if socket.write_all(reply.as_bytes()).await.is_err() {
                return;
            }
        }
    }
}

/// One RESP command from the front of `buffer`, with the number of bytes it used.
///
/// `None` means the buffer holds only part of a command. Inline commands are accepted too,
/// because nothing guarantees a client sends only arrays.
fn next_command(buffer: &[u8]) -> Option<(Vec<String>, usize)> {
    if buffer.is_empty() {
        return None;
    }
    if buffer[0] != b'*' {
        let end = buffer.windows(2).position(|pair| pair == b"\r\n")?;
        let line = std::str::from_utf8(&buffer[..end]).ok()?;
        let command = line.split_whitespace().map(str::to_owned).collect();
        return Some((command, end + 2));
    }
    let mut cursor = 1;
    let (count, used) = read_line_number(&buffer[cursor..])?;
    cursor += used;
    let mut command = Vec::with_capacity(count);
    for _ in 0..count {
        if buffer.get(cursor) != Some(&b'$') {
            return None;
        }
        cursor += 1;
        let (length, used) = read_line_number(&buffer[cursor..])?;
        cursor += used;
        let end = cursor.checked_add(length)?;
        if buffer.len() < end + 2 {
            return None;
        }
        command.push(String::from_utf8_lossy(&buffer[cursor..end]).into_owned());
        cursor = end + 2;
    }
    Some((command, cursor))
}

fn read_line_number(buffer: &[u8]) -> Option<(usize, usize)> {
    let end = buffer.windows(2).position(|pair| pair == b"\r\n")?;
    let number = std::str::from_utf8(&buffer[..end]).ok()?.parse().ok()?;
    Some((number, end + 2))
}

#[tokio::test]
async fn an_outage_drops_batches_with_a_warning_and_recovers_when_the_broker_returns() {
    let warnings = capture_warnings();
    let broker = FakeValkey::new().await;
    let sink = ValkeyInvalidator::spawn(&broker.url(), DEFAULT_CHANNEL);
    let keys = [InvalidationKey::new(
        "account",
        InvalidationKind::Home,
        "status",
    )];

    // Nothing is listening: filling the queue past its depth must not wait on the socket.
    let started = Instant::now();
    for _ in 0..QUEUE + 64 {
        sink.invalidate(&keys);
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "the sink blocked its caller for {elapsed:?} during an outage"
    );

    wait_for_warning(warnings, "valkey unavailable").await;
    wait_for_warning(warnings, "invalidation queue full").await;
    assert_eq!(
        warning_count(warnings, "valkey unavailable"),
        1,
        "one warning per outage, not one per retry"
    );

    broker.start().await;
    // The worker retries on its own; a fresh batch makes the publish deterministic once the
    // connection is back.
    sink.invalidate(&keys);
    let deadline = Instant::now() + Duration::from_secs(10);
    while broker.published().is_empty() {
        assert!(
            Instant::now() < deadline,
            "nothing was published after the broker returned"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let published = broker.published();
    assert_eq!(
        published[0],
        ValkeyInvalidator::payload(&keys),
        "the recovered worker publishes the documented wire shape"
    );
    assert_eq!(
        warning_count(warnings, "valkey unavailable"),
        1,
        "recovery is not a second outage"
    );
}
