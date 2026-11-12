# Nodus backend

A Mastodon-compatible server written in Rust: async, multi-threaded, with
Kubernetes workers. It speaks the Mastodon client API so existing apps work, and
serves its own server-rendered frontend from `nodus-web`.

Status: **pre-alpha, milestone M0**. Nothing here is deployable yet; the repository
starts with the design it intends to hit.

Nodus backend is not affiliated with, endorsed by, or sponsored by Mastodon GmbH.
"Mastodon" is a trademark of Mastodon GmbH and is used here only to describe
compatibility.

## What it is, and what it refuses to be

It is a server: accounts, posts, media, follows, timelines, moderation, and the
client API that every Mastodon app expects. Federation by ActivityPub follows in a
later milestone, deliberately behind the client API, so that the expensive part
(signatures, delivery, remote actors) lands on a surface that already works.

It is not a proxy in front of someone else's instance, and it is not a hosting
product. One deployment serves one instance. There is no multi-tenancy, no
per-tenant schema, no admin API for provisioning instances.

| Project | Role |
| --- | --- |
| `nodus-backend` (this repo) | the instance: API, storage, workers, federation |
| `nodus-web` | the frontend; gains an SSR entrypoint that this server mounts |
| `nodus-sdk` | the wire contract and client state machine, used by the web client |
| `nodus-recommender` | the recommendation service; **independent**, see `docs/01-architecture.md` |

## Layout

```text
nodus-backend/
├── docs/                  design, kept ahead of the code
├── crates/
│   ├── core/              ids, visibility, sanitisation, pure logic (no I/O)
│   ├── store/             sqlx, migrations, queries
│   ├── api/               axum router: Mastodon client API + streaming
│   ├── federation/        ActivityPub: WebFinger, actors, inbox/outbox, delivery
│   ├── worker/            the job runner (Kubernetes Deployment)
│   └── server/            the binary: migrations, API, SSR mount, shutdown
└── Cargo.toml
```

## Running it

Requires a Postgres 15+ database with `pg_trgm`. Redis is optional until streaming
fan-out across replicas exists.

```bash
export DATABASE_URL=postgres://nodus:nodus@localhost:5432/nodus
cargo run -p nodus-server          # API on :3001
cargo run -p nodus-server-worker   # job runner, one process per replica
```

## Docs

| Doc | Covers |
| --- | --- |
| `docs/00-scope.md` | what is in each milestone, what is out of scope and why |
| `docs/01-architecture.md` | crates, request path, process model, how the pieces talk |
| `docs/02-api-compat.md` | the Mastodon client API surface we promise and how it is tested |
| `docs/03-federation.md` | ActivityPub design, signatures, delivery, what "compatible" means |
| `docs/04-storage.md` | schema, id strategy, migrations, media |
| `docs/05-workers.md` | job kinds, leases, scaling on Kubernetes |
| `docs/06-ssr.md` | how `nodus-web` is mounted and where the boundary sits |
| `docs/07-decisions.md` | decisions with the reason each was made |
