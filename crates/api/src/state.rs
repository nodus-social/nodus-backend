//! Shared handler state: the store, the instance's public identity, and the key this
//! instance signs its own requests with.
//!
//! `Arc<Inner>` rather than several fields so cloning into each router is one pointer
//! increment; the config is read-only for the process's lifetime.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nodus_activitypub_client::{ActivityPub, HttpSigner};
use nodus_server_store::invalidate::InvalidationSink;
use nodus_server_store::writer::{DbWriter, DbWriterHandle, WriterConfig};
use nodus_server_store::Store;
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};

use crate::admin::stats::StatsDto;
use crate::home::HomeShards;

pub use nodus_server_core::instance::InstanceConfig;

/// How long an admin stats answer may be reused. The console polls this view.
const STATS_CACHE_TTL: Duration = Duration::from_secs(60);

/// How long a deleted account waits before its profile and credentials are erased.
///
/// Thirty days is long enough to notice a mistaken deletion and short enough that the
/// instance is not holding someone's data indefinitely after they asked to leave. The
/// operator can change it with `NODUS_ACCOUNT_DELETE_GRACE_DAYS`.
pub const DEFAULT_ACCOUNT_DELETE_GRACE_DAYS: i64 = 30;

/// How long a signing actor's `publicKeyPem` is trusted after it is resolved.
///
/// Short enough that a peer rotating its key stops being refused within a few minutes,
/// long enough that a peer reading several of our URLs signed by the same key costs one
/// fetch rather than one per request. A failed fetch is never stored here: the next
/// attempt must try again, not verify against an empty key.
pub(crate) const ACTOR_KEY_TTL: Duration = Duration::from_secs(300);

/// Upper bound on cached actor keys, so a hostile peer cannot grow the map without
/// limit by inventing key ids. Well above the number of peers one instance talks to.
const ACTOR_KEY_CACHE_MAX: usize = 1024;

/// A `dyn InvalidationSink` that can be printed: the state's `Debug` is for diagnostics,
/// and a trait object has nothing readable inside it.
#[derive(Clone)]
struct DebugSink(Arc<dyn InvalidationSink>);

impl std::fmt::Debug for DebugSink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("InvalidationSink")
    }
}

#[derive(Debug)]
struct Inner {
    store: Store,
    instance: InstanceConfig,
    federation: Option<Arc<FederationKey>>,
    /// `NODUS_AUTHORIZED_FETCH`, read once at startup. Off means ActivityPub reads
    /// answer anyone, exactly as they did before the switch existed.
    authorized_fetch: bool,
    /// `NODUS_DRIVE_SHARE_SECRET`, read once at startup. Off means the drive's share
    /// route refuses, so `drive_share` is withheld from the handshake.
    drive_share: bool,
    /// Process-local, keyed by the `range` the console asked for.
    stats_cache: Mutex<HashMap<&'static str, (Instant, StatsDto)>>,
    /// Signing actor URL → (resolved at, PEM). Only successful lookups are inserted.
    actor_keys: Mutex<HashMap<String, (Instant, String)>>,
    /// One gate per actor URL, so concurrent cold requests do one fetch, not one each.
    key_fetches: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Days between a deletion request and the erasure of the tombstone's fields.
    account_delete_grace_days: i64,
    /// The single writer every drive mutation goes through.
    writer: DbWriterHandle,
    /// The home timelines' fan-out cache, when `NODUS_VALKEY_URL` named one. `None` is the
    /// deployment this instance has always run: every read is SQL.
    home: Option<Arc<HomeShards>>,
    /// The sink committed home removals are published to. Kept here as well as in the
    /// writer, because the delete path publishes long after the writer's commit.
    sink: Option<DebugSink>,
}

/// Cloned into every handler; `Store` is a pool handle and `InstanceConfig` is small.
#[derive(Debug, Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

/// The identity this instance signs its own reads with, as `{instance}/actor#main-key`.
///
/// Optional on purpose: a fresh instance has no key yet, and a server that refused to boot
/// over a missing key would turn degraded federation into an outage.
#[derive(Debug, Clone)]
pub struct FederationKey {
    signer: HttpSigner,
    public_pem: String,
}

impl FederationKey {
    /// Reads `NODUS_FEDERATION_KEY_PATH`, falling back to `NODUS_FEDERATION_KEY`.
    pub fn from_env(instance: &InstanceConfig) -> Option<Self> {
        let path = std::env::var("NODUS_FEDERATION_KEY_PATH")
            .ok()
            .filter(|path| !path.trim().is_empty());
        let pem = match path {
            Some(path) => match std::fs::read_to_string(&path) {
                Ok(pem) => pem,
                Err(error) => {
                    tracing::warn!(
                        %path,
                        %error,
                        "instance signing key is unreadable; outbound fetches stay unsigned"
                    );
                    return None;
                }
            },
            None => match std::env::var("NODUS_FEDERATION_KEY") {
                Ok(pem) if !pem.trim().is_empty() => pem,
                _ => {
                    tracing::info!(
                        "no instance signing key configured; outbound fetches stay unsigned"
                    );
                    return None;
                }
            },
        };
        let key = Self::from_pem(instance, &pem);
        if key.is_none() {
            tracing::warn!(
                "the configured instance signing key is not a PKCS#8 RSA key; \
                 outbound fetches stay unsigned"
            );
        }
        key
    }

    /// Builds the key whose id is `{instance}/actor#main-key`.
    #[must_use]
    pub fn from_pem(instance: &InstanceConfig, pem: &str) -> Option<Self> {
        let key_id = format!("{}#main-key", instance.url("/actor"));
        let signer = HttpSigner::from_pkcs8_pem(key_id, pem).ok()?;
        let public_pem = rsa::RsaPublicKey::from(&rsa::RsaPrivateKey::from_pkcs8_pem(pem).ok()?)
            .to_public_key_pem(LineEnding::LF)
            .ok()?;
        Some(Self { signer, public_pem })
    }

    #[must_use]
    pub fn signer(&self) -> &HttpSigner {
        &self.signer
    }

    #[must_use]
    pub fn public_pem(&self) -> &str {
        &self.public_pem
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        self.signer.key_id()
    }
}

impl AppState {
    #[must_use]
    pub fn new(store: Store, instance: InstanceConfig) -> Self {
        Self::with_federation(store, instance, None)
    }

    #[must_use]
    pub fn with_federation(
        store: Store,
        instance: InstanceConfig,
        federation: Option<FederationKey>,
    ) -> Self {
        Self::with_federation_and_sink(store, instance, federation, None)
    }

    /// The same, with the writer's post-commit invalidations going to `sink`.
    ///
    /// The sink is built by the binary (which is what reads the environment); tests and
    /// every other caller keep the default, where a commit invalidates nothing.
    #[must_use]
    pub fn with_federation_and_sink(
        store: Store,
        instance: InstanceConfig,
        federation: Option<FederationKey>,
        sink: Option<Arc<dyn InvalidationSink>>,
    ) -> Self {
        // One writer per state, started before the store is moved into it. It runs on a
        // thread of its own, so `new` stays callable outside a runtime.
        let writer = DbWriter::start_detached(
            store.write_pool(),
            WriterConfig {
                sink: sink.clone(),
                ..WriterConfig::default()
            },
        );
        Self {
            inner: Arc::new(Inner {
                store,
                instance,
                federation: federation.map(Arc::new),
                authorized_fetch: false,
                drive_share: false,
                stats_cache: Mutex::new(HashMap::new()),
                actor_keys: Mutex::new(HashMap::new()),
                key_fetches: Mutex::new(HashMap::new()),
                account_delete_grace_days: DEFAULT_ACCOUNT_DELETE_GRACE_DAYS,
                writer,
                home: None,
                sink: sink.map(DebugSink),
            }),
        }
    }

    /// The same state with the home timelines' fan-out cache, when one is configured.
    ///
    /// `None` keeps the deployment this instance has always run: `timeline_entry` is the
    /// only home timeline, read by one SQL query per page.
    #[must_use]
    pub fn with_home(self, home: Option<Arc<HomeShards>>) -> Self {
        Self {
            inner: Arc::new(Inner {
                store: self.inner.store.clone(),
                instance: self.inner.instance.clone(),
                federation: self.inner.federation.clone(),
                authorized_fetch: self.inner.authorized_fetch,
                drive_share: self.inner.drive_share,
                stats_cache: Mutex::new(HashMap::new()),
                actor_keys: Mutex::new(HashMap::new()),
                key_fetches: Mutex::new(HashMap::new()),
                account_delete_grace_days: self.inner.account_delete_grace_days,
                writer: self.inner.writer.clone(),
                home,
                sink: self.inner.sink.clone(),
            }),
        }
    }

    /// The same state with secure (authorized-fetch) mode on or off.
    ///
    /// The switch is read from the environment once, in the binary, and then only read:
    /// nothing re-reads the variable per request, so the mode cannot change mid-flight.
    #[must_use]
    pub fn with_authorized_fetch(self, enabled: bool) -> Self {
        Self {
            inner: Arc::new(Inner {
                store: self.inner.store.clone(),
                instance: self.inner.instance.clone(),
                federation: self.inner.federation.clone(),
                authorized_fetch: enabled,
                drive_share: self.inner.drive_share,
                stats_cache: Mutex::new(HashMap::new()),
                actor_keys: Mutex::new(HashMap::new()),
                key_fetches: Mutex::new(HashMap::new()),
                account_delete_grace_days: self.inner.account_delete_grace_days,
                writer: self.inner.writer.clone(),
                home: self.inner.home.clone(),
                sink: self.inner.sink.clone(),
            }),
        }
    }

    /// The same state with drive share links on or off.
    ///
    /// `NODUS_DRIVE_SHARE_SECRET` is read once, in the binary, for the same reason as the
    /// secure-mode switch: a capability that changed between two requests would let the
    /// handshake advertise a route that the next request refuses.
    #[must_use]
    pub fn with_drive_share(self, enabled: bool) -> Self {
        Self {
            inner: Arc::new(Inner {
                store: self.inner.store.clone(),
                instance: self.inner.instance.clone(),
                federation: self.inner.federation.clone(),
                authorized_fetch: self.inner.authorized_fetch,
                drive_share: enabled,
                stats_cache: Mutex::new(HashMap::new()),
                actor_keys: Mutex::new(HashMap::new()),
                key_fetches: Mutex::new(HashMap::new()),
                account_delete_grace_days: self.inner.account_delete_grace_days,
                writer: self.inner.writer.clone(),
                home: self.inner.home.clone(),
                sink: self.inner.sink.clone(),
            }),
        }
    }

    /// The same state with a different deletion grace period, in days.
    #[must_use]
    pub fn with_account_delete_grace_days(self, days: i64) -> Self {
        Self {
            inner: Arc::new(Inner {
                store: self.inner.store.clone(),
                instance: self.inner.instance.clone(),
                federation: self.inner.federation.clone(),
                authorized_fetch: self.inner.authorized_fetch,
                drive_share: self.inner.drive_share,
                stats_cache: Mutex::new(HashMap::new()),
                actor_keys: Mutex::new(HashMap::new()),
                key_fetches: Mutex::new(HashMap::new()),
                account_delete_grace_days: days.max(0),
                writer: self.inner.writer.clone(),
                home: self.inner.home.clone(),
                sink: self.inner.sink.clone(),
            }),
        }
    }

    /// Whether drive share links are configured (`NODUS_DRIVE_SHARE_SECRET` is set).
    #[must_use]
    pub fn drive_share(&self) -> bool {
        self.inner.drive_share
    }

    /// Days between a deletion request and the purge of the tombstone's fields.
    #[must_use]
    pub fn account_delete_grace_days(&self) -> i64 {
        self.inner.account_delete_grace_days
    }

    #[must_use]
    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    /// The home timelines' fan-out cache, when this process was configured with one.
    #[must_use]
    pub fn home(&self) -> Option<&Arc<HomeShards>> {
        self.inner.home.as_ref()
    }

    /// The sink invalidations are published to, when one was configured.
    #[must_use]
    pub fn invalidation_sink(&self) -> Option<&Arc<dyn InvalidationSink>> {
        self.inner.sink.as_ref().map(|sink| &sink.0)
    }

    /// The single writer: drive mutations are posted here, never run on this pool.
    #[must_use]
    pub fn writer(&self) -> &DbWriterHandle {
        &self.inner.writer
    }

    #[must_use]
    pub fn instance(&self) -> &InstanceConfig {
        &self.inner.instance
    }

    #[must_use]
    pub fn federation(&self) -> Option<&FederationKey> {
        self.inner.federation.as_deref()
    }

    /// Whether ActivityPub reads require an HTTP signature (`NODUS_AUTHORIZED_FETCH`).
    #[must_use]
    pub fn authorized_fetch(&self) -> bool {
        self.inner.authorized_fetch
    }

    /// An unexpired cached key for `actor`, or `None` when it must be resolved again.
    pub(crate) fn cached_actor_key(&self, actor: &str) -> Option<String> {
        let mut cache = self.inner.actor_keys.lock().ok()?;
        match cache.get(actor) {
            Some((at, pem)) if at.elapsed() < ACTOR_KEY_TTL => Some(pem.clone()),
            Some(_) => {
                cache.remove(actor);
                None
            }
            None => None,
        }
    }

    /// Records a key that was just resolved successfully. Failures are never cached.
    pub(crate) fn cache_actor_key(&self, actor: &str, pem: String) {
        let Ok(mut cache) = self.inner.actor_keys.lock() else {
            return;
        };
        if cache.len() >= ACTOR_KEY_CACHE_MAX && !cache.contains_key(actor) {
            cache.retain(|_, (at, _)| at.elapsed() < ACTOR_KEY_TTL);
            if cache.len() >= ACTOR_KEY_CACHE_MAX {
                // Still full of live entries: dropping them costs a refetch, which is
                // cheaper than an unbounded map a peer can grow at will.
                cache.clear();
            }
        }
        cache.insert(actor.to_owned(), (Instant::now(), pem));
    }

    /// The per-actor gate that serialises key resolution on a cold cache.
    pub(crate) fn key_fetch_gate(&self, actor: &str) -> Arc<tokio::sync::Mutex<()>> {
        let Ok(mut gates) = self.inner.key_fetches.lock() else {
            return Arc::new(tokio::sync::Mutex::new(()));
        };
        if let Some(gate) = gates.get(actor) {
            return Arc::clone(gate);
        }
        if gates.len() >= ACTOR_KEY_CACHE_MAX {
            // Drop gates nobody is waiting on, so the map tracks in-flight fetches.
            gates.retain(|_, gate| Arc::strong_count(gate) > 2);
        }
        let gate = Arc::new(tokio::sync::Mutex::new(()));
        gates.insert(actor.to_owned(), Arc::clone(&gate));
        gate
    }

    /// A stats answer younger than [`STATS_CACHE_TTL`], or `None` when it must be rebuilt.
    ///
    /// The lock is never held across an `await`: the caller copies the document out and
    /// then does its queries.
    pub(crate) fn cached_stats(&self, range: &str) -> Option<StatsDto> {
        let mut cache = self.inner.stats_cache.lock().ok()?;
        match cache.get(range) {
            Some((at, value)) if at.elapsed() < STATS_CACHE_TTL => Some(value.clone()),
            Some(_) => {
                cache.remove(range);
                None
            }
            None => None,
        }
    }

    pub(crate) fn cache_stats(&self, range: &'static str, value: StatsDto) {
        if let Ok(mut cache) = self.inner.stats_cache.lock() {
            cache.insert(range, (Instant::now(), value));
        }
    }

    /// The reader for documents owned by no local account: signed when a key is set.
    #[must_use]
    pub fn fediverse_client(&self) -> ActivityPub {
        let client = ActivityPub::new();
        match self.federation() {
            Some(key) => client.with_signer(key.signer.clone()),
            None => client,
        }
    }
}
