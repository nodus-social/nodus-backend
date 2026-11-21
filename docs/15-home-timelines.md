# Home timelines and the Valkey fan-out

`GET /api/v1/timelines/home` can be answered from a sorted set in Valkey instead of the
`timeline_entry` join. The database stays authoritative: the set is a copy that makes the
common read one `ZREVRANGE` plus a primary-key hydration, and everything the copy cannot
answer falls back to `statuses::home_page` — the query that ran before this module existed.
There is no second implementation of the timeline.

One variable turns it on: **`NODUS_VALKEY_URL`**. Unset, `HomeShards::from_env` returns
`None`, the writer never pushes, and every home read is SQL. The switch is read at boot;
changing it needs a restart, not a migration.

The code is `crates/api/src/home.rs` (read/write path, subscriber) and
`crates/store/src/invalidate.rs` (`ValkeyInvalidator`, the shared `nodus:invalidate`
channel). The two-replica proof is `crates/api/tests/home_fanout.rs`.

## The shape

| Piece | Value |
| --- | --- |
| Key | `home:{account_id}` — one sorted set per timeline owner |
| Member | status id |
| Score | the status id's ULID timestamp in milliseconds, so the set sorts newest-first |
| Cap | `NODUS_HOME_CAP`, default `400`; trimmed oldest-first in the same pipeline as the push |
| Shards | `NODUS_HOME_SHARDS`, default `1`, clamped to `1..=64` |
| Shard choice | rendezvous hashing (`nodus_server_media::cluster::placement`) over members named `home-0…home-n`, so every replica with the same shard count assigns an account to the same shard |
| Pipeline | 500 accounts per round trip (`PIPELINE_BATCH`) |
| Deadline | every cache call is bounded; `CACHE_DEADLINE` is 1 s |

There is no TTL: a set exists while the account is read, and entries age out through the
cap. Memory is roughly 40–50 KB per active account at the default cap (an estimate, not a
measurement); 100 000 active accounts is a few gigabytes.

## Write path

`home::fan_out` runs after a status commits, and mirrors `statuses::fan_out_home` exactly:

- home-timeline visibilities only, and never a self-boost (the original is already there);
- the author always;
- every accepted follower while the author is below `BIG_ACCOUNT_THRESHOLD` (50 000
  followers); above it, followers' timelines are merged at read time and nothing is
  materialised for them.

Followers are paged with `home_fanout_accounts` in batches of 500, and the whole write has
a `FANOUT_BUDGET` of 2 s. A cache that is slow or down costs a warning, never the create:
the row is committed and the SQL fallback still finds it.

## Removal and the invalidation channel

A delete, a reblog deletion or a moderation hiding calls `home::hide`. It removes the id
from the author's set and from the followers' sets (same paging as the fan-out), then
publishes one key per affected timeline — `{"account_id", "kind":"home", "id": status_id}`
— on the channel `NODUS_VALKEY_CHANNEL`, default `nodus:invalidate`. The channel and the
JSON envelope are shared with the drive caches: see `ValkeyInvalidator::payload`.

The sink is fire-and-forget. `ValkeyInvalidator` hands keys to a bounded queue (256
batches) and returns, so a wedged broker cannot make a mutation wait; when the queue is
full the incoming batch is dropped with `invalidation queue full, dropped a batch`. Its
worker retries with a 1 s → 30 s backoff and logs one warning per outage
(`valkey unavailable; invalidations are dropped until it answers`), then reconnects.

`home::spawn_subscriber` subscribes every replica to the same channel and re-applies each
`home` key as a `ZREM`. The removal is idempotent. With one shared Valkey the happy path
already removed the id in the writer, so the publish is a repair path: it covers a removal
that timed out on the replica handling the delete (1 s deadline) or a replica whose
connection was down, and it keeps the contract explicit for a deployment that splits
shards across URLs. A lost removal is not a user-visible bug — hydration filters deleted
and hidden rows — but the stale id keeps occupying a cap slot, so the retry matters.

## One process and two

| | One API process | Two or more API processes |
| --- | --- | --- |
| Writes | `fan_out` pushes to the same sets this process reads | every process pushes and reads the same sets |
| Reads | `ZREVRANGE` + hydration | same; a reader can be served by any replica |
| Removal | local `ZREM`, then a publish the same process hears (and finds nothing left) | local `ZREM` on the writer, publish, every replica re-applies `ZREM` |
| Config | defaults are enough | all replicas must share `NODUS_VALKEY_URL`, `NODUS_HOME_SHARDS`, `NODUS_HOME_CAP`, `NODUS_HOME_SHARD_URLS` and `NODUS_VALKEY_CHANNEL` |

Streaming is **not** part of this. `EventSource` clients are pinned to one replica and the
live hub is process-local; the home cache makes the timeline *reads* correct on any
replica, it does not replicate live events.

## Fallback

`home::page` asks the cache first and falls back to `statuses::home_page` for every reason
a cache cannot answer:

- no cache configured (`NODUS_VALKEY_URL` unset);
- an empty set (miss — including a fresh Valkey after a restart);
- a range error or the 1 s deadline;
- a reader who follows an account above `BIG_ACCOUNT_THRESHOLD`, whose posts are merged at
  read time and are never materialised.

`home_rows` applies the same visibility predicates as SQL (deleted, quarantined,
silent/suspended, blocked/muted, paused domain), so a stale or missing removal degrades to
a filtered page, not a wrong one.

## Measured latency

`crates/api/tests/home_fanout_timings.rs` seeds one author with 1000 followers (`bench0001`
is the reader), warms up once, then runs 30 timed iterations of each half, alternating which
half goes first so a busy host lands on both. The requests go through the real router, in a
**debug build**, against local Postgres and Valkey over loopback. One representative run:

| Path | POST `/api/v1/statuses` | GET `/api/v1/timelines/home` |
| --- | --- | --- |
| fan-out on | p50 62.7 ms · p95 78.2 ms | p50 19.1 ms · p95 23.2 ms |
| fan-out off (SQL) | p50 49.5 ms · p95 57.5 ms | p50 18.3 ms · p95 24.8 ms |
| cache push alone (1000 entries, 50 runs, no request) | p50 7.1 ms · p95 7.4 ms | — |

The two halves are not symmetric, so read them separately:

- **Create.** With the cache off, `fan_out` returns on its first line: no follower scan, no
  push. With it on, the create pays for the scan (two pages of 500 plus an empty tail) and
  for three pipelined pushes — the author, then each page. Seven interleaved HTTP runs on a
  shared host put the difference at **+13–18 ms p50**; about 7 ms of it is the push itself
  (last row), the rest is the follower query and the extra round trips.
- **Read.** At 1000 followers on a shared host the two paths were inside each other's noise
  (18–25 ms p50 on both halves, ±2 ms between runs). `ZREVRANGE` replaces one query; the
  request is dominated by hydration and JSON, which neither path avoids. This measurement
  shows the cache does not make the read slower and that the SQL page is a real path rather
  than a degraded one — not that the read got faster at this size.

So the cache moves work from the read to the write. It is not a win for a small instance; it
pays where reads are many and the timeline query is the expensive one (a large follower set
read repeatedly, deep pages, a database under pressure). That is a decision to make with
numbers from your own host: this is a local single-node measurement, not a capacity claim.

Run it with:

```bash
DATABASE_URL=postgres://nodus:nodus@127.0.0.1:5432/nodus \
NODUS_TEST_VALKEY_URL=redis://:PASSWORD@127.0.0.1:6390 \
NODUS_BENCH=1 \
cargo test -p nodus-server-api --test home_fanout_timings -- --nocapture
```

## Provisioning Valkey

The cache needs a Redis-compatible server with Pub/Sub. A dedicated instance is best: the
keys are derived from account ids and a stray `FLUSHDB` from another tenant silently turns
every read into the SQL fallback.

```conf
# /etc/valkey/valkey.conf (excerpt)
bind 127.0.0.1 10.0.0.12
protected-mode yes
requirepass <long-random-password>
appendonly yes
appendfsync everysec
maxmemory 4gb
maxmemory-policy noeviction
```

- **`requirepass` is mandatory** on any interface the API can reach. Put the password in
  the URL: `redis://:<password>@host:6379/0` (no username for the default user). Prefer an
  ACL user limited to `+@read +@write +@pubsub` on `home:*` and the invalidation channel;
  `redis` speaks RESP2 and works with either.
- **Persistence is optional but useful.** The sets are rebuildable from SQL, so an empty
  Valkey after a restart is correct — reads fall back to SQL and only new posts refill
  sets. `appendonly yes` / `everysec` (or RDB snapshots) avoids the cold window at the cost
  of disk writes; if the instance is treated as pure cache, persistence can be off.
- **Eviction:** keys have no TTL, so `volatile-*` policies will never evict them.
  `noeviction` with a sized instance is the predictable choice; `allkeys-lru` degrades to
  misses (SQL) instead of failing writes.
- **Network:** bind to the API network only, firewall the port, and use `rediss://` if the
  hop crosses an untrusted network.

## Enabling it

1. Provision Valkey as above and confirm `PING`.
2. Set on **every** API replica, then roll the deployment:

   | Variable | Default | Meaning |
   | --- | --- | --- |
   | `NODUS_VALKEY_URL` | unset | the switch; unset means SQL-only |
   | `NODUS_HOME_SHARDS` | `1` | 1–64; use more than one only with that many servers (or URLs) |
   | `NODUS_HOME_CAP` | `400` | entries kept per timeline |
   | `NODUS_HOME_SHARD_URLS` | the one URL repeated | comma-separated; must have exactly `NODUS_HOME_SHARDS` entries or it is ignored with a warning |
   | `NODUS_VALKEY_CHANNEL` | `nodus:invalidate` | invalidation channel; must match on every replica |

3. Check each replica's log for `home timelines are cached in valkey`, `invalidations
   publish to valkey` and `listening for home timeline invalidations`.
4. Exercise a create and a delete (below), then raise the reader traffic.

A rolling enable is safe: replicas without the variable keep reading SQL and never write
to the cache; replicas with it write and read the same sets. Disabling is the reverse and
needs no cleanup — the keys are simply not read. Remove them with `UNLINK` (or `FLUSHDB`
on a dedicated instance) if the memory is wanted back.

## Health and verification

```bash
# Reachability and auth
valkey-cli -u redis://:PASSWORD@127.0.0.1:6379 ping            # PONG
valkey-cli -u redis://:PASSWORD@127.0.0.1:6379 info persistence # aof_enabled:1 (if on)
valkey-cli -u redis://:PASSWORD@127.0.0.1:6379 info keyspace

# The fan-out is live: one subscriber per API replica
valkey-cli -u redis://:PASSWORD@127.0.0.1:6379 pubsub channels 'nodus:invalidate'
valkey-cli -u redis://:PASSWORD@127.0.0.1:6379 pubsub numsub nodus:invalidate

# A follower's set: after a post it holds the id, after a delete it does not
valkey-cli -u redis://:PASSWORD@127.0.0.1:6379 zcard home:<follower-id>
valkey-cli -u redis://:PASSWORD@127.0.0.1:6379 zrevrange home:<follower-id> 0 4 withscores
valkey-cli -u redis://:PASSWORD@127.0.0.1:6379 zscore home:<follower-id> <status-id>

# How many timelines are materialised and how big they are
valkey-cli -u redis://:PASSWORD@127.0.0.1:6379 --scan --pattern 'home:*' | wc -l
valkey-cli -u redis://:PASSWORD@127.0.0.1:6379 info commandstats | grep -E 'zadd|zrem|zrevrange'
```

Warnings worth alerting on: `home timeline read failed; falling back to sql`,
`home timeline range failed; falling back to sql`, `home timeline range timed out;
falling back to sql`, `home invalidation subscriber disconnected`, `valkey unavailable;
invalidations are dropped until it answers`, `invalidation queue full, dropped a batch`, and
`home fan-out ran out of its time budget`.

Two-replica smoke test: post from an account both replicas can serve, confirm
`ZCARD home:<follower-id>` on the Valkey, `curl` the home timeline from each replica (both
must include the post), delete it, then confirm `ZSCORE` is nil and both replicas' pages no
longer include it. `PUBSUB NUMSUB` must equal the replica count, otherwise one process is
not subscribed — with one shared set the delete still applies, but a timed-out removal will
not be repaired there.

## Tests

- `crates/api/tests/home_fanout.rs` — the cross-replica proof and the down-at-boot
  fallback; the Valkey half runs when `NODUS_TEST_VALKEY_URL` is set and prints a skip line
  otherwise.
- `crates/api/tests/home_fanout_timings.rs` — the numbers above; opt-in with
  `NODUS_BENCH=1`.
- `crates/store/tests/invalidate.rs` — the outage path: drops with one warning, then
  publishes after the broker returns (in-process fake broker, no Valkey needed).
- `crates/api/tests/home_timeline.rs` — the single-replica cache behaviour and the SQL
  filters.

```bash
DATABASE_URL=postgres://nodus:nodus@127.0.0.1:5432/nodus \
NODUS_TEST_VALKEY_URL=redis://:PASSWORD@127.0.0.1:6390 \
cargo test -p nodus-server-api
```
