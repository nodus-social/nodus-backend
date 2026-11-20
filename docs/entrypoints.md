# Entrypoints — one binary, three roles

Status: current · Last revised: 2026-11-20

`nodus` is one binary that can start the API, the media worker, or both in one
process. The six units the host runs today are untouched: each still starts
`/usr/local/bin/nodus-<service>`, and each of those is now a two-line wrapper
around a public run path in its own crate. The point of this entrypoint is that
the run path is called, not copied — `nodus api` and `nodus-api` execute the same
`nodus_server_api::run`.

## The roles

| Role | Calls | Listens on | Reads |
| --- | --- | --- | --- |
| `api` | `nodus_server_api::run()` | `NODUS_BIND`, default `0.0.0.0:3000` | the API's environment: `NODUS_BIND`, `NODUS_DATABASE_URL`, `NODUS_DOMAIN`, `NODUS_BASE_URL`, `NODUS_AUTH_SECURE_COOKIES`, `NODUS_REGISTRATIONS_OPEN`, `NODUS_AUTHORIZED_FETCH`, `NODUS_TELEMETRY_SOCKET` / `NODUS_TELEMETRY_BIND`, bootstrap and instance settings |
| `media-worker` | `nodus_server_media::run()` | `NODUS_BIND`, default `0.0.0.0:3000` | `NODUS_BIND`, `NODUS_DATABASE_URL`, `NODUS_MEDIA_DIR`, `NODUS_MEDIA_VARIANTS_DIR`, `NODUS_MEDIA_NODE`, `NODUS_MEDIA_ENDPOINT`, `NODUS_MEDIA_CLUSTER_TOKEN`, `NODUS_MEDIA_REPAIR`, `NODUS_MEDIA_REPAIR_SECS`, `NODUS_TELEMETRY_SOCKET` |
| `aio` | both of the above | API on `NODUS_BIND`, media on `NODUS_MEDIA_BIND` (default `0.0.0.0:3003`) | the two sets above, read once per role; each role gets its own address instead of `NODUS_BIND` |

`nodus` with no arguments, `nodus --help` and `nodus -h` print the three roles and
exit 0. Any other first argument exits 2 and names the accepted roles.

`aio` runs the two run paths as tasks on one runtime with one shutdown token: a
role that fails, or that returns before anyone asked it to stop, stops the other
and the process exits non-zero. It does not leave a process that looks healthy
while half its listeners are gone. When both are asked to stop, each gets ten
seconds to finish before the process gives up on it.

`NODUS_AIO_ANNOUNCE_SECS=<n>` makes `aio` print `nodus aio: api on <addr>` and
`nodus aio: media on <addr>`, then raise the stop signal after `<n>` seconds. It
exists so `services/nodus/tests/roles.rs` can dial both ports and watch the
process exit on its own; it is not a deployment knob.

## From a unit to a role

Nothing is switched over yet. The host runs the six units; this table is what
each would become if it ever did.

| Deployed unit | Today | Would become |
| --- | --- | --- |
| `nodus-api` | `/usr/local/bin/nodus-api` | `nodus api` |
| `nodus-media` | `/usr/local/bin/nodus-media` | `nodus media-worker` |
| `nodus-feed` | `/usr/local/bin/nodus-feed` | no role yet — `crates/feed` has the run path, the binary stays |
| `nodus-scan` | `/usr/local/bin/nodus-scan` | no role yet |
| `nodus-prune` | `/usr/local/bin/nodus-prune` | no role yet |
| `nodus-calc` | `/usr/local/bin/nodus-calc` | no role yet |

A unit that moved would keep its `Environment=` lines and change only `ExecStart`
to `/usr/local/bin/nodus <role>`; the addresses above are the units' own
(`nodus-api` 3001, `nodus-media` 3003), not the defaults.

## Why not `aio` in production

The production host already runs the six units, which is the same split `aio`
creates plus the four workers this binary does not start. Replacing them with one
`aio` process would trade six independent failure domains for one, lose per-unit
`ReadWritePaths` and restart policy, and would still need `nodus-feed`,
`nodus-scan`, `nodus-prune` and `nodus-calc` alongside it. `aio` is for a
single-container deployment and for tests; do not run it on the production host.
