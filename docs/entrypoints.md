# Entrypoints — one binary, seven roles

Status: current · Last revised: 2026-11-23

`nodus` is one binary that can start any of the six services, or the API and the
media worker together. The six units the host runs today are untouched: each
still starts `/usr/local/bin/nodus-<service>`, and each of those is now a
two-line wrapper around a public run path in its own crate. The point of this
entrypoint is that the run path is called, not copied — `nodus api` and
`nodus-api` execute the same `nodus_server_api::run`, and every other role has
the same arrangement with its own crate.

The single binary is built and installed by `deploy/lxc/deploy.sh` alongside the
six (`/usr/local/bin/nodus`), and it is verified there, but no unit uses it yet:
every `ExecStart=` still names `nodus-api` and friends.

## The roles

| Role | Calls | Listens on | Reads |
| --- | --- | --- | --- |
| `api` | `nodus_server_api::run()` | `NODUS_BIND`, default `0.0.0.0:3000` | the API's environment: `NODUS_BIND`, `NODUS_DATABASE_URL`, `NODUS_DOMAIN`, `NODUS_BASE_URL`, `NODUS_AUTH_SECURE_COOKIES`, `NODUS_REGISTRATIONS_OPEN`, `NODUS_AUTHORIZED_FETCH`, `NODUS_SMTP_HOST`, `NODUS_SMTP_PORT`, `NODUS_SMTP_USERNAME`, `NODUS_SMTP_PASSWORD`, `NODUS_SMTP_FROM`, `NODUS_SMTP_TLS`, `NODUS_REQUIRE_EMAIL_CONFIRMATION`, `NODUS_TELEMETRY_SOCKET` / `NODUS_TELEMETRY_BIND`, bootstrap and instance settings |
| `media-worker` | `nodus_server_media::run()` | `NODUS_BIND`, default `0.0.0.0:3000` | `NODUS_BIND`, `NODUS_DATABASE_URL`, `NODUS_MEDIA_DIR`, `NODUS_MEDIA_VARIANTS_DIR`, `NODUS_MEDIA_NODE`, `NODUS_MEDIA_ENDPOINT`, `NODUS_MEDIA_CLUSTER_TOKEN`, `NODUS_MEDIA_REPAIR`, `NODUS_MEDIA_REPAIR_SECS`, `NODUS_MEDIA_VIDEO_CODEC` (`vp8` default / `vp9`), `NODUS_TELEMETRY_SOCKET` |
| `feed` | `nodus_server_feed::run()` | `NODUS_BIND`, default `0.0.0.0:3000` | `NODUS_BIND`, `NODUS_DATABASE_URL`, `NODUS_DOMAIN`, `TOKEN_ENC_KEY`, the recommendation store and cache, `NODUS_TELEMETRY_SOCKET` / `NODUS_TELEMETRY_BIND` |
| `scan` | `nodus_server_scan::run()` | nothing, unless telemetry is configured: then `NODUS_TELEMETRY_SOCKET` or `NODUS_TELEMETRY_BIND` | `NODUS_DATABASE_URL`, the scanner endpoints, the sweep interval, `NODUS_TELEMETRY_SOCKET` / `NODUS_TELEMETRY_BIND` |
| `prune` | `nodus_server_prune::run()` | nothing, unless telemetry is configured, as `scan` | `NODUS_DATABASE_URL`, `NODUS_MEDIA_DIR`, `NODUS_TELEMETRY_SOCKET` / `NODUS_TELEMETRY_BIND` |
| `calc` | `nodus_server_calc::run()` | nothing, unless telemetry is configured, as `scan` | `NODUS_DATABASE_URL` (falling back to `NODUS_DATABASE_URL` from `DATABASE_URL`), `TOKEN_ENC_KEY`, the cache and crawl settings, `NODUS_TELEMETRY_SOCKET` / `NODUS_TELEMETRY_BIND` |
| `aio` | the api and media-worker run paths | API on `NODUS_BIND`, media on `NODUS_MEDIA_BIND` (default `0.0.0.0:3003`) | the two sets above, read once per role; each role gets its own address instead of `NODUS_BIND` |

`aio` is api plus media only. The three workers are deliberately not in it: they
are long-running loops rather than listeners, and folding them in would give one
process the failure domain of four services.

## `TOKEN_ENC_KEY`

`feed` and `calc` both read `TOKEN_ENC_KEY`: a base64-encoded 32-byte key
(`openssl rand -base64 32`) that seals the instance tokens stored for background
sync. It has no `NODUS_` prefix; that spelling appears in older notes and is not
read. Without it `feed` starts but `/api/v1/sync/*` answers 503 `sync_disabled`
while `/api/v1/meta` still advertises `sync_token`, so the release script refuses
to install a feed role on a host whose env file has no valid key.

**Never rotate this key without a re-seal plan.** It encrypts every token in the
database; a new key makes all existing sealed values undecryptable, and nothing
re-seals them automatically. Generate it once per host, persist it, and reuse it.

`nodus` with no arguments, `nodus --help` and `nodus -h` print the seven roles
and exit 0. Any other first argument exits 2 and names the accepted set.

`--dry-run` — or `NODUS_ROLE_DRY_RUN=1` — makes any role print
`nodus <role> dry run: would start <run path> on <address>` and exit 0 without
binding anything, reading the role's own environment exactly as the real path
would. It exists so `services/nodus/tests/roles.rs` can prove each role reaches
its own run path without starting another server; it is not a deployment knob.

`aio` runs the two run paths as tasks on one runtime with one shutdown token: a
role that fails, or that returns before anyone asked it to stop, stops the other
and the process exits non-zero. It does not leave a process that looks healthy
while half its listeners are gone. When both are asked to stop, each gets ten
seconds to finish before the process gives up on it.

`NODUS_AIO_ANNOUNCE_SECS=<n>` makes `aio` print `nodus aio: api on <addr>` and
`nodus aio: media on <addr>`, then raise the stop signal after `<n>` seconds. It
exists so the same test can dial both ports and watch the process exit on its
own; it is not a deployment knob either.

## From a unit to a role

Nothing is switched over yet. The host runs the six units; this table is what
each would become if it ever did.

| Deployed unit | Today | Would become |
| --- | --- | --- |
| `nodus-api` | `/usr/local/bin/nodus-api` | `nodus api` |
| `nodus-media` | `/usr/local/bin/nodus-media` | `nodus media-worker` |
| `nodus-feed` | `/usr/local/bin/nodus-feed` | `nodus feed` |
| `nodus-scan` | `/usr/local/bin/nodus-scan` | `nodus scan` |
| `nodus-prune` | `/usr/local/bin/nodus-prune` | `nodus prune` |
| `nodus-calc` | `/usr/local/bin/nodus-calc` | `nodus calc` |

A unit that moved would keep its `Environment=` lines and change only `ExecStart`
to `/usr/local/bin/nodus <role>`; the addresses above are the units' own
(`nodus-api` 3001, `nodus-media` 3003), not the defaults.

## Why not `aio` in production

The production host already runs the six units, which is the same split `aio`
creates plus the three workers it leaves out. Replacing them with one `aio`
process would trade six independent failure domains for one, lose per-unit
`ReadWritePaths` and restart policy, and would still need `nodus-feed`,
`nodus-scan`, `nodus-prune` and `nodus-calc` alongside it. `aio` is for a
single-container deployment and for tests; do not run it on the production host.
