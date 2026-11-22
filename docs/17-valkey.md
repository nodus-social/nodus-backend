# 17 — Valkey, the home-timeline broker

Status: deployed on CT 118 · Last revised: 2026-11-22

`docs/15-home-timelines.md` describes the fan-out; this is the broker it runs on in this
deployment. One container-local Valkey on `127.0.0.1:6379`, reached by `nodus-api` through
`NODUS_VALKEY_URL`. Nothing else on the host may own port 6379: the deployment has exactly
one broker and every replica uses the same URL.

## What is installed

| Piece | Value |
| --- | --- |
| Package | `valkey-server` `8.0.1+dfsg1-1~bpo12+1`, `valkey-tools` (the `valkey-cli`) |
| Source | Debian `bookworm-backports` (`/etc/apt/sources.list.d/bookworm-backports.list`) |
| Unit | `valkey-server.service` (the package also aliases `valkey.service`), enabled at boot |
| Config | `/etc/valkey/valkey.conf` |
| Data | `/var/lib/valkey` (`appendonlydir/`, `dump.rdb`), owner `valkey:valkey` |
| Password | `openssl rand -hex 32`, stored at `/root/valkey.pass` (0600) on CT 118 |

Debian 12's own archive carries no `valkey-server` (`apt-cache policy valkey-server` is empty
before backports), and `bookworm-backports` already has 8.0.1, so the third-party
`packages.valkey.io` repository and any tarball build were not needed. The installed version
is pinned by the package version above; a future backports upload does not replace it unless
`apt-get upgrade` is run for that package.

The container also has the old `redis-server` package installed (7.0.15), **disabled and
inactive** from an earlier deployment. It must stay disabled: it binds the same 6379 and
would either fail to start or shadow Valkey.

## Rebuilding it from scratch

```bash
pct exec 118 -- bash -lc '
  echo "deb http://deb.debian.org/debian bookworm-backports main" \
    > /etc/apt/sources.list.d/bookworm-backports.list
  apt-get update
  apt-get install -y valkey-server valkey-tools
'
```

Then make the config private and authenticated. The package ships `bind 127.0.0.1 -::1` and
`appendonly no`; change those two lines and append a managed block:

```conf
bind 127.0.0.1                     # 127.0.0.1 only: no ::1, no container address
protected-mode yes                 # shipped default; belt to bind's braces
requirepass <openssl rand -hex 32> # generated on the host, never committed
appendonly yes                     # the cache survives a broker restart
maxmemory 256mb
maxmemory-policy allkeys-lru
```

Generate the password on the container and append the same value to the config without
letting it reach a shell history or this repository:

```bash
umask 077; openssl rand -hex 32 > /root/valkey.pass
printf 'requirepass %s\n' "$(cat /root/valkey.pass)" >> /etc/valkey/valkey.conf
systemctl enable --now valkey-server
valkey-cli -a "$(cat /root/valkey.pass)" --no-auth-warning ping   # PONG
```

`valkey-cli ping` without `-a` must answer `NOAUTH Authentication required.` — that is the
proof the password is in force, not just configured.

**Why 256 MB and `allkeys-lru`.** The sets are a derivable copy (docs/15: roughly 40–50 KB
per active account at the default cap of 400, an estimate), so evicting any key costs a
timeline read that falls back to SQL — never correctness. 256 MB leaves the 4 GB container
plenty of room for six units and keeps the broker from becoming a memory hostage; LRU spends
it on the accounts that are actually read. `appendonly yes` is there so a restart of the
broker does not empty every set and force a full re-materialisation.

## Wiring the API

The secret lives only in the deployment environment file, following
`docs/09-deployment.md`: `/etc/nodus-backend.env`, `0640 root:nodus`. The line's shape is

```text
NODUS_VALKEY_URL=redis://:<password>@127.0.0.1:6379/0
```

The password is 64 hex characters, so no URL-encoding is needed. Append it, keep the mode,
and restart — the switch is read at boot, not per request:

```bash
stamp=$(date +%Y%m%d%H%M%S)
cp -a /etc/nodus-backend.env /etc/nodus-backend.env.bak-valkey-$stamp
cmp /etc/nodus-backend.env /etc/nodus-backend.env.bak-valkey-$stamp   # byte-identical
printf 'NODUS_VALKEY_URL=redis://:%s@127.0.0.1:6379/0\n' "$(cat /root/valkey.pass)" \
  >> /etc/nodus-backend.env
chown root:nodus /etc/nodus-backend.env; chmod 0640 /etc/nodus-backend.env
systemctl restart nodus-api
```

## What the log says

A healthy start replaces the pull-path line with three:

```text
INFO nodus_server_api::run: invalidations publish to valkey channel=nodus:invalidate
INFO nodus_server_api::home: home timelines are cached in valkey shards=1 cap=400 channel=nodus:invalidate
INFO nodus_server_api::home: listening for home timeline invalidations channel=nodus:invalidate
```

and `NODUS_VALKEY_URL is unset: home timelines take the pull path from the store`
(`crates/api/src/home.rs:535`) is gone. `shards=1` is `NODUS_HOME_SHARDS` unset; raise it
only with that many servers (`docs/15-home-timelines.md`).

## Keyspace

| Key / channel | Type | Content |
| --- | --- | --- |
| `home:{account_id}` (`crates/api/src/home.rs:150`) | sorted set | member = status id, score = the id's ULID timestamp in ms |
| `nodus:invalidate` | pub/sub channel | `{"account_id","kind":"home","id"}` per removed timeline |

No TTL and no other keys: a set exists while the account is read, trimmed to
`NODUS_HOME_CAP` (400) by `ZREMRANGEBYRANK` in the same pipeline as the push. A fresh broker
starts empty, so the first home reads are misses that fall back to SQL until `fan_out`
fills the sets again.

Inventory:

```bash
valkey-cli -a "$(cat /root/valkey.pass)" --no-auth-warning dbsize
valkey-cli -a "$(cat /root/valkey.pass)" --no-auth-warning --scan | head -20
valkey-cli -a "$(cat /root/valkey.pass)" --no-auth-warning pubsub numsub nodus:invalidate
valkey-cli -a "$(cat /root/valkey.pass)" --no-auth-warning info stats \
  | grep -E 'total_commands_processed|keyspace_hits|keyspace_misses'
```

`pubsub numsub nodus:invalidate` answers at least `1` while `nodus-api` is up: that number is
the subscriber that makes two-process invalidation work.

## Outages

Every cache path is bounded and degrades to SQL; the broker is never in the write path of a
status. The strings to grep for, by failure:

| Log | Meaning |
| --- | --- |
| `home timeline cache unreachable; reads fall back to sql` | a read could not reach the broker (`crates/api/src/home.rs:351`, `:365`); reads still answer |
| `home timeline push failed` / `home timeline push timed out` | a fan-out batch failed inside its 2 s budget; the status is already committed |
| `invalidation queue full, dropped a batch` | `ValkeyInvalidator`'s 256-batch queue is saturated; stale entries are filtered at read time |
| `valkey unavailable; invalidations are dropped until it answers` | one warning per outage; the worker retries 1 s → 2 s → … → 30 s |

Stopping `valkey-server` therefore costs latency, not availability. Restarting it costs the
whole keyspace only if AOF is off — with `appendonly yes` the sets come back.

## Rollback

```bash
sed -i '/^NODUS_VALKEY_URL=/d' /etc/nodus-backend.env   # or restore the .bak-valkey-* copy
systemctl restart nodus-api
```

The API then logs the pull-path line again and serves home timelines from Postgres. The
broker can be left running (unused) or stopped with `systemctl disable --now valkey-server`;
the env line is the switch, so stop it only after the restart has been verified.

## Not yet proven in production

`crates/api/tests/home_fanout.rs` proves two replicas over one Valkey in the lab. On this host
there is still one `nodus-api`, so what remains for #43 is: a second replica sharing this URL
and channel, an invalidation published by one replica observed by the other
(`pubsub numsub nodus:invalidate` → 2), and outage/timing numbers under a real failure —
how long a read takes when the broker is stopped, and how far the invalidator's backoff
stretches before it reconnects.
