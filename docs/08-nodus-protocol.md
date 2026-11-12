# 08 — Nodus protocol extensions

Status: design · Last revised: 2026-11-13

The Mastodon client API is the compatibility surface. A stock Mastodon app must
never need a Nodus extension, and an endpoint that exists in Mastodon keeps its
Mastodon shape. Everything in this document is additive, advertised, and optional.

The extensions exist for three things the Mastodon API cannot do well:

1. **Batch** independent reads into one round trip.
2. **Subscribe** to changes instead of polling.
3. **Synchronise history** by state hash instead of re-fetching a collection.

## Advertisement and fallback

`GET /api/v2/instance` gains a `nodus` object, and
`GET /api/v1/nodus/capabilities` returns the same contract:

```json
{
  "contract": "nodus-1",
  "features": ["batch", "events", "state_sync"],
  "limits": {
    "batch_calls": 20,
    "batch_bytes": 1048576,
    "event_resume_seconds": 600,
    "sync_events": 500
  }
}
```

A client uses an extension only after seeing its feature. If it is absent, the
client falls back to the standard endpoint, never to a degraded Nodus-only path.
The public timelines, account/status routes, pagination and OAuth remain exactly the
Mastodon ones; the extensions do not change their responses.

`/api/v1/nodus/*` is disabled as a whole by `NODUS_EXTENSIONS=off`. A deployment may
also compile the extension crate out; the capability document is then absent.

## Batch requests

`POST /api/v1/nodus/batch`

```json
{
  "calls": [
    { "id": "me", "method": "GET", "path": "/api/v1/accounts/verify_credentials" },
    { "id": "home", "method": "GET", "path": "/api/v1/timelines/home?limit=20" },
    { "id": "post", "method": "POST", "path": "/api/v1/statuses",
      "body": { "status": "hello" }, "after": ["me"] }
  ]
}
```

- Every call runs with the batch request's bearer token and scopes; a call cannot
  override `Authorization`.
- Independent calls run concurrently. `after` names earlier call ids and creates a
  dependency; a cycle is a `422` and no call runs.
- At most 20 calls, 1 MiB of request bodies, and one 5 s deadline for the batch.
  Exceeding a limit is `413`/`422` for the whole batch, not a silent truncation.
- Results preserve request order. Each result carries its own status, headers and
  body; one `404` does not fail the others.
- Batch is for ordinary API calls only. It rejects nested batch calls, event
  streams, media upload and any path outside `/api/`.
- Writes are not atomic. A write that needs an idempotency guarantee carries
  `Idempotency-Key` inside its call, exactly as it would standalone.

```json
{
  "results": [
    { "id": "me", "status": 200, "headers": { "content-type": "application/json" }, "body": {} },
    { "id": "home", "status": 200, "headers": { "link": "<...>; rel=\"next\"" }, "body": [] }
  ]
}
```

## Event subscriptions

`GET /api/v1/nodus/events` with `Accept: text/event-stream` (or a WebSocket upgrade
on the same path) opens a subscription scoped to the authenticated account.

Query parameters:

| Parameter | Meaning |
| --- | --- |
| `types` | comma-separated event types; empty means the account's default set |
| `timeline` | `home`, `local`, `federated`, or a list id |
| `account` | only events caused by, or addressed to, this account |
| `since` | event cursor, used when `Last-Event-ID` is unavailable |

Events use the `nodus-protocol::Event` envelope (`id`, `kind`, `instance_host`,
`payload`). SSE `id:` is the resume cursor. Filtering happens server-side before
the event is written, so a subscription never receives events it did not ask for.

- Delivery is **at least once**. Clients deduplicate by `event.id`.
- A reconnect with `Last-Event-ID` replays from the cursor for up to 10 minutes.
  Older cursors get a `resync` event and the client reloads the affected timeline
  through the standard API.
- The stream is per-account. It is never a public firehose and never exposes a
  status the account could not read through `/api/v1`.
- A slow consumer is disconnected rather than buffered without bound; the client
  reconnects with its last cursor.

Events are produced by the same transaction that writes the domain row, through an
outbox, so a published event cannot describe a write that rolled back.

## State-hash history synchronisation

A peer that already has a collection can ask "what is newer than the state I have?"
without knowing a timestamp or a local sequence number.

### Collections and event log

A collection is a named, ordered log:

```text
actor:{uri}              profile fields, keys, counts
status:{uri}             one status and its edits/deletion
timeline:local           public local timeline entries
timeline:{actor_uri}     an actor's home timeline
thread:{root_uri}        replies below one root
```

Only collections the caller may read are addressable. Direct messages and
followers-only posts are not exposed to a peer that is not entitled to them; the
same visibility check as the normal API applies per event.

Each event has `seq` (server-local, monotonic within the collection), `id`, `kind`,
`payload`, `prev` and `hash`. The hash chain is:

```text
genesis_prev = 00…00 (32 bytes)
hash = SHA-256(
  "nodus-sync-v1\0" ||
  collection || "\0" ||
  prev_bytes ||
  canonical_json({ id, kind, payload })
)
```

`canonical_json` is RFC 8785 JCS: object keys sorted, no insignificant whitespace,
UTF-8. The hash is over the event content and its predecessor, not over the local
`seq`, so two servers that applied the same events in the same order agree on the
root even when their sequence numbers differ.

`GET /api/v1/nodus/sync/root?collection=…` returns:

```json
{ "collection": "timeline:local", "seq": 9182, "hash": "9f2c…" }
```

### Diff

`POST /api/v1/nodus/sync/diff`

```json
{ "collection": "timeline:local", "have": "9f2c…", "limit": 500 }
```

```json
{
  "collection": "timeline:local",
  "status": "diff",
  "from": "9f2c…",
  "to": "41ab…",
  "root_seq": 9182,
  "events": [
    { "seq": 9170, "id": "01J…", "kind": "status.create",
      "prev": "9f2c…", "hash": "aa01…", "payload": {} }
  ],
  "next": "aa01…"
}
```

`status` is one of:

| Status | Meaning | Client action |
| --- | --- | --- |
| `up_to_date` | `have` equals the current root | nothing |
| `diff` | events after `have`, up to `limit` | apply in order; if `next` is present, ask again with `have=next` |
| `diverged` | `have` is not in this collection's log | discard the local cursor, fetch a snapshot/backfill, then resume |
| `reset` | the collection was compacted or recreated | replace the collection from the snapshot |

The server locates `have` by hash index and returns only events after it. The peer
never has to send its clock, and a clock skew cannot hide or duplicate an event.
A `diverged` response includes the current root so the caller can start a fresh
backfill; it never silently returns a partial diff from an unrelated position.

### Backfill and snapshots

`POST /api/v1/nodus/sync/snapshot` returns the current root plus the newest bounded
window for a collection the caller may read. It is for the `diverged`/new-peer case,
not for normal polling. Older history is then filled forward from the snapshot root
with repeated `diff` calls.

This is the "forward hash" rule: a peer proves where it is by hash, and the server
walks forward from that proof. There is no need for a global sequence, a shared
clock, or a full collection transfer on every reconnect.

### Federation use

Remote peers use the same protocol over signed HTTPS:

- `/.well-known/nodus` advertises the sync endpoint, contract version and the
  instance actor key.
- Requests are signed with the instance actor using the same draft-cavage
  RSA-SHA256 signature as ActivityPub; replay protection uses `Date` and a
  short-lived request id.
- The peer's actor must be allowed by the instance's federation policy. A blocked
  domain gets the same `404` as an unknown collection.
- A sync diff is a cache/backfill optimisation. ActivityPub delivery remains the
  authority for new activities; a missed delivery is repaired by the next diff.

## Limits and failure behaviour

| Limit | Value |
| --- | --- |
| batch calls | 20 |
| batch request bytes | 1 MiB |
| diff events per response | 500 (server may lower it) |
| snapshot window | 500 events |
| event replay window | 10 minutes |
| sync request body | 64 KiB |

All extension endpoints use the normal error body, rate-limit headers and token
scopes. Extensions never bypass moderation, blocks, domain blocks or visibility.
