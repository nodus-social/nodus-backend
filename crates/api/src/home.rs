//! The home timeline's fan-out read path: a sorted set per account, filled on create.
//!
//! The database stays authoritative. `timeline_entry` (or, above
//! [`BIG_ACCOUNT_THRESHOLD`], the read-time merge) is what decides whether a status is in
//! a home timeline; the ZSET is a *copy* that lets the common read be one range and one
//! primary-key lookup instead of a `UNION` over follows. Everything the ZSET cannot answer
//! — it is empty, unreadable, or the reader follows a big account — falls back to
//! [`nodus_server_store::statuses::home_page`], the exact query that ran before this
//! module existed. There is no second implementation.
//!
//! Three rules keep the copy honest:
//!
//! - **Push on create, never on read.** [`fan_out`] mirrors what `fan_out_home` writes to
//!   `timeline_entry`: the author plus every accepted follower, but only while the author
//!   is below the big-account cut-off.
//! - **Trim to a window.** Each entry is written with its status id's ULID timestamp as the
//!   score, and the set is cut to `NODUS_HOME_CAP` (default 400) oldest-first in the same
//!   pipeline, so an account that follows a hundred people every hour does not grow a set
//!   without bound.
//! - **Filter on hydration.** A delete or a moderation hiding removes the id from the sets
//!   of the accounts it was fanned out to ([`hide`]) *and* publishes the removal on the
//!   existing `nodus:invalidate` channel, so a second replica drops it too. Even if both
//!   are lost, [`nodus_server_store::statuses::home_rows`] applies the same predicates as
//!   the SQL page: deleted, quarantined, silent/suspended, blocked or muted authors, a
//!   paused domain, a suspended remote actor. A mute or a block therefore needs no
//!   invalidation at all — the post is filtered where it is read.
//!
//! What is *not* here: provisioning. The cache is off until `NODUS_VALKEY_URL` is set; until
//! then [`HomeShards::from_env`] returns `None`, the writer never pushes, and every read
//! takes the SQL path. Turning it on is an operator decision; the runbook is
//! `docs/15-home-timelines.md`.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use nodus_server_core::limits::BIG_ACCOUNT_THRESHOLD;
use nodus_server_core::pagination::{PageOrder, PageParams, PageSize};
use nodus_server_core::{Id, Visibility};
use nodus_server_media::cluster::{placement, Member};
use nodus_server_store::invalidate::{InvalidationKey, InvalidationKind};
use nodus_server_store::statuses::{self, StatusPage, StatusRow};
use sqlx::PgPool;

use crate::AppState;

/// Entries one account's home timeline keeps by default.
pub const DEFAULT_CAP: usize = 400;

/// Shards a single upstream serves by default: one, the shape of today's deployment.
pub const DEFAULT_SHARDS: usize = 1;

/// Upper bound on `NODUS_HOME_SHARDS`, so a typo cannot fork a timeline across thousands
/// of keys nobody watches.
const SHARDS_MAX: usize = 64;

/// Followers per pipeline.
///
/// Smaller than [`nodus_server_core::limits::FAN_OUT_BATCH`] because every account in the
/// batch becomes two commands; 500 keeps one pipeline's reply small while still making a
/// 5 000-follower account ten round trips rather than ten thousand.
pub const PIPELINE_BATCH: usize = 500;

/// How long one cache call may take before the read falls back to SQL.
const CACHE_DEADLINE: Duration = Duration::from_secs(1);

/// How long a create waits for its fan-out before the request is answered anyway.
///
/// The database row is already committed, so a slow cache must not hold the response: the
/// status is visible through the fallback path either way.
const FANOUT_BUDGET: Duration = Duration::from_secs(2);

/// Something a home cache refused to do.
///
/// The message is for a log line: a cache error is never returned to a client, it only
/// decides whether this read takes the SQL path.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct HomeCacheError(pub String);

impl HomeCacheError {
    fn new(error: impl std::fmt::Display) -> Self {
        Self(error.to_string())
    }
}

/// One entry to add: whose timeline, which status, and where it sorts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeEntry {
    pub account_id: String,
    pub status_id: String,
    /// The status id's ULID timestamp, in milliseconds. Larger is newer.
    pub score: i64,
}

type Reply<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The four operations a home timeline cache owes the read path.
///
/// Boxed futures rather than `async fn` in the trait: the process holds
/// `Arc<dyn HomeCache>`, one per shard, chosen per account at request time.
pub trait HomeCache: Send + Sync {
    /// Adds `entries`, cutting each account's set to `cap` in the same round trip.
    fn push<'a>(&'a self, entries: &'a [HomeEntry], cap: usize) -> Reply<'a, Result<(), HomeCacheError>>;

    /// The newest `limit` status ids in one account's timeline, newest first.
    ///
    /// An empty vector means "nothing cached", which the reader treats as a miss.
    fn range<'a>(
        &'a self,
        account_id: &'a str,
        limit: usize,
    ) -> Reply<'a, Result<Vec<String>, HomeCacheError>>;

    /// Cuts one account's set to its oldest `cap` entries.
    fn trim<'a>(&'a self, account_id: &'a str, cap: usize) -> Reply<'a, Result<(), HomeCacheError>>;

    /// Removes one status from each of `account_ids`' timelines.
    fn remove<'a>(
        &'a self,
        account_ids: &'a [String],
        status_id: &'a str,
    ) -> Reply<'a, Result<(), HomeCacheError>>;
}

/// `home:{account_id}` — the key an account's timeline lives under.
#[must_use]
pub fn key(account_id: &str) -> String {
    format!("home:{account_id}")
}

/// An in-memory [`HomeCache`]: scripted timelines for tests, and the shape the trait is
/// specified against.
///
/// It implements the same ordering and trimming the Valkey one does — a `BTreeMap` keyed by
/// `(score, id)` is the sorted set, and re-pushing a status replaces its score exactly like
/// `ZADD` — so a test that passes here is testing the contract, not a stub.
#[derive(Debug, Default)]
pub struct MemoryHomeCache {
    timelines: Mutex<HashMap<String, BTreeMap<(i64, String), ()>>>,
    /// Set by [`Self::fail`] so a test can prove the SQL fallback runs on a broken cache.
    broken: AtomicBool,
}

impl MemoryHomeCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes every operation fail, the way an unreachable Valkey would.
    pub fn fail(&self, on: bool) {
        self.broken.store(on, Ordering::Relaxed);
    }

    fn check(&self) -> Result<(), HomeCacheError> {
        if self.broken.load(Ordering::Relaxed) {
            return Err(HomeCacheError::new("cache is marked as broken"));
        }
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, BTreeMap<(i64, String), ()>>> {
        self.timelines
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl HomeCache for MemoryHomeCache {
    fn push<'a>(
        &'a self,
        entries: &'a [HomeEntry],
        cap: usize,
    ) -> Reply<'a, Result<(), HomeCacheError>> {
        Box::pin(async move {
            self.check()?;
            let mut timelines = self.lock();
            for entry in entries {
                let timeline = timelines.entry(entry.account_id.clone()).or_default();
                // ZADD semantics: one member, its score replaced on every push.
                timeline.retain(|(_, id), ()| id != &entry.status_id);
                timeline.insert((entry.score, entry.status_id.clone()), ());
                while timeline.len() > cap.max(1) {
                    let oldest = timeline.keys().next().cloned();
                    match oldest {
                        Some(oldest) => timeline.remove(&oldest),
                        None => break,
                    };
                }
            }
            Ok(())
        })
    }

    fn range<'a>(
        &'a self,
        account_id: &'a str,
        limit: usize,
    ) -> Reply<'a, Result<Vec<String>, HomeCacheError>> {
        Box::pin(async move {
            self.check()?;
            let timelines = self.lock();
            let Some(timeline) = timelines.get(account_id) else {
                return Ok(Vec::new());
            };
            Ok(timeline
                .keys()
                .rev()
                .take(limit)
                .map(|(_, id)| id.clone())
                .collect())
        })
    }

    fn trim<'a>(&'a self, account_id: &'a str, cap: usize) -> Reply<'a, Result<(), HomeCacheError>> {
        Box::pin(async move {
            self.check()?;
            let mut timelines = self.lock();
            if let Some(timeline) = timelines.get_mut(account_id) {
                while timeline.len() > cap {
                    let oldest = timeline.keys().next().cloned();
                    match oldest {
                        Some(oldest) => timeline.remove(&oldest),
                        None => break,
                    };
                }
            }
            Ok(())
        })
    }

    fn remove<'a>(
        &'a self,
        account_ids: &'a [String],
        status_id: &'a str,
    ) -> Reply<'a, Result<(), HomeCacheError>> {
        Box::pin(async move {
            self.check()?;
            let mut timelines = self.lock();
            for account_id in account_ids {
                if let Some(timeline) = timelines.get_mut(account_id) {
                    timeline.retain(|(_, id), ()| id != status_id);
                }
            }
            Ok(())
        })
    }
}

/// A [`HomeCache`] backed by one Valkey/Redis instance.
///
/// The connection is multiplexed and opened lazily, so a process that starts while Valkey
/// is down still serves: the first call logs one warning, fails, and the read takes SQL.
/// Every call is wrapped in [`CACHE_DEADLINE`] by [`HomeShards`], never by this type.
pub struct ValkeyHomeCache {
    client: redis::Client,
    connection: tokio::sync::Mutex<Option<redis::aio::MultiplexedConnection>>,
    warned: AtomicBool,
}

impl std::fmt::Debug for ValkeyHomeCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ValkeyHomeCache").finish_non_exhaustive()
    }
}

impl ValkeyHomeCache {
    /// # Errors
    ///
    /// Fails when `url` is not a URL the client understands.
    pub fn open(url: &str) -> Result<Self, HomeCacheError> {
        let client = redis::Client::open(url).map_err(HomeCacheError::new)?;
        Ok(Self {
            client,
            connection: tokio::sync::Mutex::new(None),
            warned: AtomicBool::new(false),
        })
    }

    async fn connection(&self) -> Result<redis::aio::MultiplexedConnection, HomeCacheError> {
        let mut slot = self.connection.lock().await;
        if let Some(open) = slot.as_ref() {
            return Ok(open.clone());
        }
        let open = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(HomeCacheError::new)?;
        *slot = Some(open.clone());
        if self.warned.swap(false, Ordering::Relaxed) {
            tracing::info!("home timeline cache reconnected");
        }
        Ok(open)
    }

    /// Drops the connection after a failed command, so the next call reconnects instead of
    /// reusing a socket that is already dead.
    async fn disconnect(&self) {
        *self.connection.lock().await = None;
    }

    async fn run<T: redis::FromRedisValue>(
        &self,
        command: &mut redis::Cmd,
    ) -> Result<T, HomeCacheError> {
        let mut connection = self.connection().await?;
        match command.query_async::<T>(&mut connection).await {
            Ok(value) => Ok(value),
            Err(error) => {
                self.disconnect().await;
                if !self.warned.swap(true, Ordering::Relaxed) {
                    tracing::warn!(%error, "home timeline cache unreachable; reads fall back to sql");
                }
                Err(HomeCacheError::new(error))
            }
        }
    }

    async fn run_pipeline(&self, pipeline: &mut redis::Pipeline) -> Result<(), HomeCacheError> {
        let mut connection = self.connection().await?;
        match pipeline.query_async::<redis::Value>(&mut connection).await {
            Ok(_) => Ok(()),
            Err(error) => {
                self.disconnect().await;
                if !self.warned.swap(true, Ordering::Relaxed) {
                    tracing::warn!(%error, "home timeline cache unreachable; reads fall back to sql");
                }
                Err(HomeCacheError::new(error))
            }
        }
    }
}

impl HomeCache for ValkeyHomeCache {
    fn push<'a>(
        &'a self,
        entries: &'a [HomeEntry],
        cap: usize,
    ) -> Reply<'a, Result<(), HomeCacheError>> {
        Box::pin(async move {
            let mut pipeline = redis::pipe();
            for entry in entries {
                let key = key(&entry.account_id);
                pipeline
                    .cmd("ZADD")
                    .arg(&key)
                    .arg(entry.score)
                    .arg(&entry.status_id)
                    .ignore()
                    .cmd("ZREMRANGEBYRANK")
                    .arg(&key)
                    .arg(0)
                    .arg(-(i64::try_from(cap.max(1)).unwrap_or(i64::MAX) + 1))
                    .ignore();
            }
            self.run_pipeline(&mut pipeline).await
        })
    }

    fn range<'a>(
        &'a self,
        account_id: &'a str,
        limit: usize,
    ) -> Reply<'a, Result<Vec<String>, HomeCacheError>> {
        Box::pin(async move {
            let mut command = redis::cmd("ZREVRANGE");
            command
                .arg(key(account_id))
                .arg(0)
                .arg(i64::try_from(limit.max(1)).unwrap_or(i64::MAX) - 1);
            self.run::<Vec<String>>(&mut command).await
        })
    }

    fn trim<'a>(&'a self, account_id: &'a str, cap: usize) -> Reply<'a, Result<(), HomeCacheError>> {
        Box::pin(async move {
            let mut command = redis::cmd("ZREMRANGEBYRANK");
            command
                .arg(key(account_id))
                .arg(0)
                .arg(-(i64::try_from(cap).unwrap_or(i64::MAX) + 1));
            self.run::<i64>(&mut command).await.map(|_| ())
        })
    }

    fn remove<'a>(
        &'a self,
        account_ids: &'a [String],
        status_id: &'a str,
    ) -> Reply<'a, Result<(), HomeCacheError>> {
        Box::pin(async move {
            let mut pipeline = redis::pipe();
            for account_id in account_ids {
                pipeline.cmd("ZREM").arg(key(account_id)).arg(status_id).ignore();
            }
            self.run_pipeline(&mut pipeline).await
        })
    }
}

/// Where a replica listens for removals published by the others.
#[derive(Debug, Clone)]
struct Subscription {
    url: String,
    channel: String,
}

/// The home caches, one per shard, and the rendezvous that picks between them.
///
/// The placement is the same function the media cluster uses
/// ([`nodus_server_media::cluster::placement`]): an account's shard is a pure function of
/// its id and the member set, so adding a shard moves about `1/n` of the accounts and
/// leaves the rest where they were.
pub struct HomeShards {
    caches: Vec<Arc<dyn HomeCache>>,
    members: Vec<Member>,
    cap: usize,
    subscription: Option<Subscription>,
}

impl std::fmt::Debug for HomeShards {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HomeShards")
            .field("shards", &self.caches.len())
            .field("cap", &self.cap)
            .finish_non_exhaustive()
    }
}

impl HomeShards {
    /// Builds the shards from an explicit set of caches, for tests and for callers that
    /// already read their environment.
    #[must_use]
    pub fn new(caches: Vec<Arc<dyn HomeCache>>, cap: usize) -> Self {
        let caches = if caches.is_empty() {
            vec![Arc::new(MemoryHomeCache::new()) as Arc<dyn HomeCache>]
        } else {
            caches
        };
        let members = (0..caches.len())
            .map(|index| Member {
                name: format!("home-{index}"),
                endpoint: String::new(),
            })
            .collect();
        Self {
            caches,
            members,
            cap: cap.max(1),
            subscription: None,
        }
    }

    /// The caches the environment asks for, or `None` when no cache is configured.
    ///
    /// `NODUS_VALKEY_URL` set is the switch: one variable turns the whole read path on.
    /// `NODUS_HOME_SHARDS` (default 1) splits accounts across that many upstreams,
    /// `NODUS_HOME_SHARD_URLS` names them (comma separated, default: the one URL repeated),
    /// and `NODUS_HOME_CAP` (default 400) is the window each timeline keeps.
    ///
    /// A malformed URL is not fatal: it disables the cache with one warning and every read
    /// keeps working through SQL.
    #[must_use]
    pub fn from_env() -> Option<Arc<Self>> {
        let url = match std::env::var("NODUS_VALKEY_URL") {
            Ok(url) if !url.trim().is_empty() => url,
            _ => {
                tracing::info!("NODUS_VALKEY_URL is unset: home timelines read from the database");
                return None;
            }
        };
        let shards = env_count("NODUS_HOME_SHARDS", DEFAULT_SHARDS).clamp(1, SHARDS_MAX);
        let cap = env_count("NODUS_HOME_CAP", DEFAULT_CAP).max(1);
        let urls: Vec<String> = std::env::var("NODUS_HOME_SHARD_URLS")
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|part| !part.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let urls = if urls.len() == shards {
            urls
        } else {
            if !urls.is_empty() {
                tracing::warn!(
                    urls = urls.len(),
                    shards,
                    "NODUS_HOME_SHARD_URLS does not name one url per shard; using NODUS_VALKEY_URL for every shard"
                );
            }
            vec![url; shards]
        };
        let mut caches: Vec<Arc<dyn HomeCache>> = Vec::with_capacity(shards);
        for (index, shard_url) in urls.iter().enumerate() {
            match ValkeyHomeCache::open(shard_url) {
                Ok(cache) => caches.push(Arc::new(cache)),
                Err(error) => {
                    tracing::warn!(
                        shard = index,
                        %error,
                        "unreadable home timeline url; home timelines read from the database"
                    );
                    return None;
                }
            }
        }
        let channel = std::env::var("NODUS_VALKEY_CHANNEL")
            .ok()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| nodus_server_store::invalidate::DEFAULT_CHANNEL.to_owned());
        tracing::info!(
            shards,
            cap,
            channel = %channel,
            "home timelines are cached in valkey"
        );
        let channel_url = urls.first().cloned().unwrap_or_default();
        Some(Arc::new(
            Self::new(caches, cap).with_subscription(&channel_url, &channel),
        ))
    }

    /// How many shards the account set is spread over.
    #[must_use]
    pub fn len(&self) -> usize {
        self.caches.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.caches.is_empty()
    }

    /// The window each timeline keeps.
    #[must_use]
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// The shard `account_id` belongs to: highest rendezvous score wins, ties by name.
    #[must_use]
    pub fn shard_of(&self, account_id: &str) -> usize {
        if self.caches.len() <= 1 {
            return 0;
        }
        placement(account_id, &self.members, 1)
            .first()
            .and_then(|owner| {
                self.members
                    .iter()
                    .position(|member| member.name == owner.name)
            })
            .unwrap_or(0)
    }

    /// The cache that owns `account_id`'s timeline.
    #[must_use]
    pub fn shard(&self, account_id: &str) -> &Arc<dyn HomeCache> {
        &self.caches[self.shard_of(account_id).min(self.caches.len() - 1)]
    }

    /// Joins the invalidation channel at `url`, so removals another replica published are
    /// applied to these shards.
    ///
    /// [`Self::from_env`] is the path the process takes, because it is the one that reads
    /// the environment; this is for a caller that already holds its configuration. The
    /// cross-replica tests in `tests/home_fanout.rs` build two replicas over one server
    /// with it.
    #[must_use]
    pub fn with_subscription(mut self, url: &str, channel: &str) -> Self {
        self.subscription = Some(Subscription {
            url: url.to_owned(),
            channel: channel.to_owned(),
        });
        self
    }

    /// Whether a replica could be listening for published removals.
    #[must_use]
    fn subscription(&self) -> Option<Subscription> {
        self.subscription.clone()
    }

    /// Adds one status to each account's timeline, one pipeline per shard and batch.
    pub async fn push(&self, status_id: &str, score: i64, accounts: &[String]) {
        for (shard, batch) in self.group(accounts) {
            for chunk in batch.chunks(PIPELINE_BATCH) {
                let entries: Vec<HomeEntry> = chunk
                    .iter()
                    .map(|account_id| HomeEntry {
                        account_id: (*account_id).clone(),
                        status_id: status_id.to_owned(),
                        score,
                    })
                    .collect();
                match tokio::time::timeout(
                    CACHE_DEADLINE,
                    self.caches[shard].push(&entries, self.cap),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::warn!(shard, %error, "home timeline push failed");
                    }
                    Err(_) => tracing::warn!(shard, "home timeline push timed out"),
                }
            }
        }
    }

    /// Removes one status from each account's timeline.
    pub async fn remove(&self, status_id: &str, accounts: &[String]) {
        for (shard, batch) in self.group(accounts) {
            for chunk in batch.chunks(PIPELINE_BATCH) {
                let owned: Vec<String> = chunk.iter().map(|id| (*id).clone()).collect();
                match tokio::time::timeout(
                    CACHE_DEADLINE,
                    self.caches[shard].remove(&owned, status_id),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::warn!(shard, %error, "home timeline removal failed");
                    }
                    Err(_) => tracing::warn!(shard, "home timeline removal timed out"),
                }
            }
        }
    }

    /// The accounts of `accounts`, grouped by their shard.
    fn group<'a>(&self, accounts: &'a [String]) -> Vec<(usize, Vec<&'a String>)> {
        let mut grouped: Vec<Vec<&String>> = vec![Vec::new(); self.caches.len()];
        for account in accounts {
            grouped[self.shard_of(account)].push(account);
        }
        grouped
            .into_iter()
            .enumerate()
            .filter(|(_, batch)| !batch.is_empty())
            .collect()
    }
}

fn env_count(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

/// The page `GET /api/v1/timelines/home` serves: the cache when it can answer, SQL when it
/// cannot.
///
/// The fallback is [`statuses::home_page`] — the same function this route called before the
/// cache existed — for all four reasons a cache cannot be read: none configured, an empty
/// timeline (a miss), a failed range, or a reader who follows a big account (whose posts
/// are merged at read time and never materialised).
pub async fn page(
    pool: &PgPool,
    home: Option<&HomeShards>,
    account_id: &str,
    params: PageParams,
) -> Result<StatusPage, sqlx::Error> {
    let Some(home) = home else {
        return statuses::home_page(pool, account_id, params).await;
    };
    match cached_page(pool, home, account_id, params).await {
        Ok(Some(page)) => Ok(page),
        Ok(None) => statuses::home_page(pool, account_id, params).await,
        Err(error) => {
            tracing::warn!(%error, "home timeline read failed; falling back to sql");
            statuses::home_page(pool, account_id, params).await
        }
    }
}

async fn cached_page(
    pool: &PgPool,
    home: &HomeShards,
    account_id: &str,
    params: PageParams,
) -> Result<Option<StatusPage>, sqlx::Error> {
    if statuses::follows_big_account(pool, account_id, BIG_ACCOUNT_THRESHOLD).await? {
        // The ZSET holds the materialised lane only; the SQL read is the one that also
        // merges big accounts, so it has to answer this request.
        return Ok(None);
    }
    let ids = match tokio::time::timeout(
        CACHE_DEADLINE,
        home.shard(account_id).range(account_id, home.cap()),
    )
    .await
    {
        Ok(Ok(ids)) => ids,
        Ok(Err(error)) => {
            tracing::warn!(%error, "home timeline range failed; falling back to sql");
            return Ok(None);
        }
        Err(_) => {
            tracing::warn!("home timeline range timed out; falling back to sql");
            return Ok(None);
        }
    };
    if ids.is_empty() {
        return Ok(None);
    }

    let size = PageSize::default_max(params.limit);
    let limit = usize::try_from(size.get()).unwrap_or(usize::from(u16::MAX));
    let max_id = params.max_id.map(|id| id.to_string());
    let lower = params.lower_bound().map(|id| id.to_string());
    // The set is newest first. Cursors are id comparisons, the same ones the SQL page
    // makes, so a client can page with the ids it already holds.
    let mut ordered: Vec<String> = ids
        .into_iter()
        .filter(|id| {
            max_id.as_deref().is_none_or(|bound| id.as_str() < bound)
                && lower.as_deref().is_none_or(|bound| id.as_str() > bound)
        })
        .collect();
    if ordered.is_empty() {
        return Ok(None);
    }
    if params.order() == PageOrder::OldestFirst {
        ordered.reverse();
    }

    // Hidden ids shorten a page: the entry is dropped here, not necessarily from the set
    // yet (a delete whose invalidation was lost still must not serve the post). Widen the
    // window until the page is full or the set is exhausted, so a client never sees a short
    // page with no cursor to continue from.
    let mut take = (limit + 1).min(ordered.len());
    loop {
        let wanted = &ordered[..take];
        let rows = statuses::home_rows(pool, account_id, wanted).await?;
        let mut by_id: HashMap<String, StatusRow> =
            rows.into_iter().map(|row| (row.id.clone(), row)).collect();
        let mut items: Vec<StatusRow> = wanted
            .iter()
            .filter_map(|id| by_id.remove(id.as_str()))
            .collect();
        if items.len() > limit || take == ordered.len() {
            // Same rule as `statuses::finish`: one extra row is what says "there is more".
            let next_max_id = if items.len() > limit {
                items.truncate(limit);
                items.last().map(|row| row.id.clone())
            } else {
                None
            };
            return Ok(Some(StatusPage { items, next_max_id }));
        }
        take = (take * 2).min(ordered.len());
    }
}

/// Pushes a newly created status into its author's and followers' timelines.
///
/// Mirrors `statuses::fan_out_home` exactly: home-timeline visibilities only, the author
/// always, followers only while the author is below the big-account cut-off. A self-boost
/// pushes nothing new — the original is already in every one of those timelines.
///
/// Best effort and time-boxed: the row is committed, so a cache that does not answer costs
/// a warning, and the fallback read still finds the post.
pub async fn fan_out(state: &AppState, row: &StatusRow) {
    let Some(home) = state.home() else {
        return;
    };
    if !Visibility::from_str(&row.visibility).is_ok_and(Visibility::in_home_timeline) {
        return;
    }
    let pool = state.store().pool();
    if is_self_reblog(pool, row).await {
        return;
    }
    let Some(score) = score_of(&row.id) else {
        tracing::warn!(status = %row.id, "status id has no timestamp; home fan-out skipped");
        return;
    };
    let deadline = Instant::now() + FANOUT_BUDGET;

    // The author's own entry exists even when the fan-out cut-off excludes followers.
    home.push(&row.id, score, std::slice::from_ref(&row.account_id))
        .await;

    let mut after: Option<String> = None;
    loop {
        let batch = match statuses::home_fanout_accounts(
            pool,
            &row.account_id,
            after.as_deref(),
            i64::try_from(PIPELINE_BATCH).unwrap_or(500),
            Some(BIG_ACCOUNT_THRESHOLD),
        )
        .await
        {
            Ok(batch) => batch,
            Err(error) => {
                tracing::warn!(%error, status = %row.id, "home fan-out could not list followers");
                return;
            }
        };
        if batch.is_empty() {
            return;
        }
        let complete = batch.len() < PIPELINE_BATCH;
        home.push(&row.id, score, &batch).await;
        if complete {
            return;
        }
        after = batch.last().cloned();
        if Instant::now() >= deadline {
            tracing::warn!(status = %row.id, "home fan-out ran out of its time budget");
            return;
        }
    }
}

/// Removes a hidden status from the timelines it was fanned out to, on this replica and
/// through the invalidation channel on the others.
///
/// Called after a delete, a reblog deletion or a moderation hiding has committed. The
/// accounts are the same set [`fan_out`] pushed to, plus the author; an account missed
/// (say, one that crossed the follower cut-off since) keeps a stale id that the hydration
/// filter drops.
pub async fn hide(state: &AppState, author_id: &str, status_id: &str) {
    let Some(home) = state.home() else {
        return;
    };
    let pool = state.store().pool();
    let mut keys = Vec::new();
    let own = vec![author_id.to_owned()];
    home.remove(status_id, &own).await;
    keys.extend(own.iter().map(|account| {
        InvalidationKey::new(account, InvalidationKind::Home, status_id)
    }));

    let mut after: Option<String> = None;
    loop {
        let batch = match statuses::home_fanout_accounts(
            pool,
            author_id,
            after.as_deref(),
            i64::try_from(PIPELINE_BATCH).unwrap_or(500),
            Some(BIG_ACCOUNT_THRESHOLD),
        )
        .await
        {
            Ok(batch) => batch,
            Err(error) => {
                tracing::warn!(%error, status = %status_id, "could not list followers to unhide");
                break;
            }
        };
        if batch.is_empty() {
            break;
        }
        let complete = batch.len() < PIPELINE_BATCH;
        home.remove(status_id, &batch).await;
        keys.extend(batch.iter().map(|account| {
            InvalidationKey::new(account, InvalidationKind::Home, status_id)
        }));
        if complete {
            break;
        }
        after = batch.last().cloned();
    }

    if let Some(sink) = state.invalidation_sink() {
        sink.invalidate(&keys);
    }
}

/// Starts the subscriber that applies other replicas' `home` removals.
///
/// Only spawned when a cache and a URL are configured; a process with no cache has nothing
/// to remove from. The loop reconnects on its own, so a Valkey restart costs a pause, not a
/// restart of this process.
pub fn spawn_subscriber(home: &Arc<HomeShards>) {
    let Some(subscription) = home.subscription() else {
        return;
    };
    let home = home.clone();
    tokio::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        loop {
            match listen(&home, &subscription).await {
                Ok(()) => backoff = Duration::from_secs(1),
                Err(error) => {
                    tracing::warn!(%error, "home invalidation subscriber disconnected");
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    });
}

/// One connection's worth of listening. Returns when the channel closes or the process
/// stops.
async fn listen(home: &Arc<HomeShards>, subscription: &Subscription) -> Result<(), HomeCacheError> {
    let client = redis::Client::open(subscription.url.as_str()).map_err(HomeCacheError::new)?;
    let mut pubsub = client.get_async_pubsub().await.map_err(HomeCacheError::new)?;
    pubsub
        .subscribe(&subscription.channel)
        .await
        .map_err(HomeCacheError::new)?;
    tracing::info!(channel = %subscription.channel, "listening for home timeline invalidations");
    let mut messages = pubsub.on_message();
    while let Some(message) = messages.next().await {
        let payload: String = match message.get_payload() {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(%error, "unreadable invalidation payload");
                continue;
            }
        };
        for key in parse_home_keys(&payload) {
            let accounts = vec![key.account_id];
            home.remove(&key.id, &accounts).await;
        }
    }
    Ok(())
}

/// The `home` keys in one published payload.
///
/// The shape is [`nodus_server_store::invalidate::ValkeyInvalidator::payload`]:
/// `{"channel":"nodus:invalidate","keys":[…]}`, each key
/// `{"account_id":…,"kind":"home","id":…}`. A payload this process cannot read is skipped,
/// never fatal: it is another version's message, not this request's problem.
fn parse_home_keys(payload: &str) -> Vec<InvalidationKey> {
    #[derive(serde::Deserialize)]
    struct Event {
        keys: Vec<InvalidationKey>,
    }
    match serde_json::from_str::<Event>(payload) {
        Ok(event) => event
            .keys
            .into_iter()
            .filter(|key| key.kind == InvalidationKind::Home)
            .collect(),
        Err(error) => {
            tracing::warn!(%error, "unreadable invalidation payload");
            Vec::new()
        }
    }
}

/// The score a status id sorts by: its ULID timestamp in milliseconds.
fn score_of(status_id: &str) -> Option<i64> {
    Id::from_str(status_id)
        .ok()
        .and_then(|id| i64::try_from(id.timestamp_ms()).ok())
}

/// Whether `row` is a boost of one of the author's own statuses.
async fn is_self_reblog(pool: &PgPool, row: &StatusRow) -> bool {
    let Some(original_id) = row.reblog_of_id.as_deref() else {
        return false;
    };
    match statuses::by_id(pool, original_id).await {
        Ok(Some(original)) => original.account_id == row.account_id,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(account: &str, ids: &[(i64, &str)]) -> Vec<HomeEntry> {
        ids.iter()
            .map(|(score, id)| HomeEntry {
                account_id: account.to_owned(),
                status_id: (*id).to_owned(),
                score: *score,
            })
            .collect()
    }

    #[tokio::test]
    async fn a_push_keeps_the_newest_entries_and_orders_them_by_score() {
        let cache = MemoryHomeCache::new();
        cache
            .push(
                &entries(
                    "alice",
                    &[(30, "c"), (10, "a"), (20, "b"), (40, "d")],
                ),
                3,
            )
            .await
            .expect("push");
        let ids = cache.range("alice", 10).await.expect("range");
        assert_eq!(ids, ["d", "c", "b"], "the oldest entry is the one trimmed");
    }

    #[tokio::test]
    async fn a_second_push_of_the_same_status_replaces_its_score() {
        let cache = MemoryHomeCache::new();
        cache
            .push(&entries("alice", &[(10, "a")]), 400)
            .await
            .expect("first push");
        cache
            .push(&entries("alice", &[(99, "a"), (20, "b")]), 400)
            .await
            .expect("second push");
        assert_eq!(
            cache.range("alice", 10).await.expect("range"),
            ["a", "b"],
            "ZADD semantics: one member, new score"
        );
    }

    #[tokio::test]
    async fn trim_cuts_one_timeline_without_touching_another() {
        let cache = MemoryHomeCache::new();
        cache
            .push(&entries("alice", &[(1, "a"), (2, "b"), (3, "c")]), 400)
            .await
            .expect("push");
        cache
            .push(&entries("bob", &[(1, "a")]), 400)
            .await
            .expect("push");
        cache.trim("alice", 1).await.expect("trim");
        assert_eq!(cache.range("alice", 10).await.expect("range"), ["c"]);
        assert_eq!(cache.range("bob", 10).await.expect("range"), ["a"]);
    }

    #[test]
    fn a_shard_move_keeps_every_account_on_exactly_one_shard() {
        let accounts: Vec<String> = (0..2000)
            .map(|index| format!("01J{:022}", index))
            .collect();
        let one = HomeShards::new(
            vec![
                Arc::new(MemoryHomeCache::new()) as Arc<dyn HomeCache>,
            ],
            400,
        );
        let two = HomeShards::new(
            vec![
                Arc::new(MemoryHomeCache::new()) as Arc<dyn HomeCache>,
                Arc::new(MemoryHomeCache::new()) as Arc<dyn HomeCache>,
            ],
            400,
        );
        let before: Vec<usize> = accounts.iter().map(|id| one.shard_of(id)).collect();
        let after: Vec<usize> = accounts.iter().map(|id| two.shard_of(id)).collect();
        for shard in 0..two.len() {
            let set: Vec<&String> = accounts
                .iter()
                .zip(&after)
                .filter(|(_, owner)| **owner == shard)
                .map(|(id, _)| id)
                .collect();
            let unique: std::collections::HashSet<&&String> = set.iter().collect();
            assert_eq!(set.len(), unique.len(), "shard {shard} cannot hold an account twice");
        }
        // Every account is still owned by exactly one shard, so no id disappeared.
        assert_eq!(after.len(), accounts.len());
        let moved = before.iter().zip(&after).filter(|(l, r)| l != r).count();
        assert!(moved > 0, "adding a shard must move some accounts");
        assert!(
            moved < accounts.len() / 2,
            "rendezvous moves about 1/n of the accounts, not {moved} of {}",
            accounts.len()
        );
    }
}
