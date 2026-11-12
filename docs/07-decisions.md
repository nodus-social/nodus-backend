# 07 — Decisions

Format: id · decision · why · what would make us revisit. Only decisions that
constrain the code belong here; preferences do not.

## D1 — Axum, not Actix

Axum's extractor model fits "route → typed request → typed response", which is
exactly the shape of a client-API server, and it composes with `tower` middleware for
scopes, rate limits and request ids. Actix is faster on synthetic benchmarks and worse
on the thing we need: a router whose middleware can be unit-tested.

*Revisit if:* we hit a throughput wall that profiling attributes to the router.

## D2 — sqlx, not Diesel or an ORM

The queries that matter are analytical: `FOR UPDATE SKIP LOCKED` lease acquisition,
`UNNEST` batch inserts for fan-out, `INSERT … ON CONFLICT` upserts for idempotent
inbox handling, and keyset pagination with `Link` headers. An ORM's DSL expresses
none of them without raw SQL escape hatches. sqlx gives async, compile-time checked
statements where they are static, and plain SQL where they are not.

*Revisit if:* sqlx's offline mode becomes a burden in CI (it would argue for fewer
checked macros, not a different library).

## D3 — Postgres is the queue

Delivery, fan-out, media processing and ingest are rows in `job`, claimed with a
lease. This makes the domain write and its consequence commit atomically, and makes
backlog observable with one query. A broker would add a component, a failure mode and
a duplicate-delivery semantics we would have to solve anyway.

*Revisit if:* sustained throughput exceeds what one Postgres can absorb (~10⁴
jobs/min), at which point the answer is partitioning or a second queue, documented
then.

## D4 — ULID ids, opaque to clients

Lexicographic order equals creation order, so `since_id`/`max_id` work without a
second sort key; ids are mintable by any replica. Numeric ids would collide across
shards; UUIDv4 would destroy ordering; UUIDv7 would work but its string form is long
and its monotonicity is not guaranteed inside a millisecond.

*Revisit if:* an app is found to parse ids as integers — a compatibility bug we would
have to fix, not a reason to change the id scheme.

## D5 — Fan-out in a worker, never in the request

A post with 40 000 followers is a 40 000-row insert. Doing it inline makes the API's
latency a function of the author's popularity and couples a user action to a queue
drain. The API therefore enqueues and returns.

*Revisit if:* never — the only question is where the worker runs, not whether.

## D6 — Redis for pub/sub only

Streaming across replicas needs fan-out to connected sockets; Redis pub/sub does that
with two commands and no schema. It is never the source of truth: timelines, jobs and
sessions live in Postgres, so a Redis restart costs a reconnect, not data.

*Revisit if:* streaming volume requires a dedicated fan-out service; the boundary
stays the same.

## D7 — RSA + draft-cavage signatures

Mastodon verifies `Signature` with RSASSA-PKCS1-v1_5-SHA256 and does not accept
Ed25519. Compatibility with the existing fediverse is the point of federation, so we
implement what the other side verifies, however much we would prefer modern
alternatives.

*Revisit when:* the fediverse converges on a signature standard we can verify against
two independent implementations.

## D8 — One deployment, one instance

Multi-tenancy changes the threat model (tenant isolation in every query), the schema
(tenant column or schema-per-tenant), and the failure model (one tenant's blast
radius). None of it is required to run a server, and all of it is hard to add later —
so we say no now, in writing, and stay single-tenant.

*Revisit if:* someone wants to operate Nodus as a hosting product; that is a different
project with its own repository.

## D9 — Independent from `nodus-recommender`

The recommender reads the database with `SELECT`-only credentials and serves its own
feed API; there are no shared tables, no shared migrations, and no compile-time
dependency. This keeps a plain Mastodon instance a supported deployment, and keeps
recommendation failures from taking posting down.

*Revisit if:* ranking needs data the read-only view cannot supply — then the answer is
an event stream, not a shared schema.

## D10 — Hybrid rendering: SSR for public, CSR for signed-in

Public pages need crawlers and link previews; the signed-in app needs a bearer token
that must never reach a server render. Rendering both ways from one component tree
gives each what it needs without a second frontend.

*Revisit if:* hydration cost on mid-range phones proves worse than a plain CSR shell;
the measurement lives in `nodus-web/docs/05-quality.md`.

## D11 — Advertise `4.3.0`, put our version elsewhere

Apps parse `version` to decide which features to use. Reporting `0.x` would make every
client hide working features; reporting our own number in `version` would be a lie the
clients act on. So `version` is the API generation we implement, and our build is in
`configuration.urls` plus an `X-Nodus-Version` header.

*Revisit each Mastodon API generation we implement.*

## D12 — Sanitise HTML on write

Storing raw HTML and sanitising on read puts the burden on every renderer and lets one
forgotten endpoint emit script tags. Sanitising on write stores exactly what we are
willing to serve, and makes the stored `content` auditable.

*Revisit if:* an edit-history feature needs the original text; then we store the raw
form alongside, never instead.
