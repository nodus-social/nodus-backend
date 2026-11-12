# 03 — Federation

Status: design · Milestone M1 (not in M0)

Federation is the part where "compatible" stops being a matter of JSON shapes: a
remote instance will not negotiate, retry politely, or degrade. Either our signature
verifies and our delivery is idempotent, or the remote silently ignores us and no
error appears on our side.

## Identity and discovery

```text
acct:alice@social.example
  ├── GET https://social.example/.well-known/webfinger?resource=acct:alice@social.example
  │     → { subject, links: [{ rel: "self", type: "application/activity+json", href: … }] }
  └── GET https://social.example/users/alice   (Accept: application/activity+json)
        → { id, type: "Person", preferredUsername, inbox, outbox, followers, following,
            endpoints: { sharedInbox }, publicKey: { id, owner, publicKeyPem },
            attachment, summary, icon, image, published, manuallyApprovesFollowers }
```

Two decisions worth stating:

- **`Person`, not `Service`.** Mastodon treats `Service` actors as bots and hides
  their posts more aggressively. Our accounts are people by default.
- **RSA-2048 keys, RSASSA-PKCS1-v1_5-SHA256 signatures (draft-cavage).** Not
  Ed25519: Mastodon does not accept it, and the point of M1 is interoperability with
  what exists. Keys are generated per account at registration and never shared
  between accounts, because a shared key would make one compromised actor able to
  sign as everyone.

## Inbox

`POST /inbox` on the actor, plus `POST /inbox` on the shared inbox. Both require:

1. `Digest: SHA-256=…` matching the body (verified before parsing — the body is read
   with a hard 10 MB cap and hashed once).
2. `Signature: keyId="…",headers="(request-target) host date digest",signature="…"`
   verified against the key fetched for `keyId`, cached for one hour, refetched once
   on failure (key rotation arrives as an `Update` we may have missed).
3. `Date` within ±12 hours, otherwise `401` — replay defence that also stops a stale
   retry from a queued delivery being replayed by an attacker.

Then, in one transaction:

| Activity | Handling |
| --- | --- |
| `Follow` | upsert remote actor, `follow` row pending or accepted by policy, reply `Accept` |
| `Accept` / `Reject` | resolve the outstanding follow; the `Follow` activity id is the key |
| `Undo(Follow\|Like\|Announce\|Block)` | delete the corresponding row, `404`-tolerant |
| `Create(Note)` | idempotent by activity `id`; store status, fan out to followers |
| `Update(Note)` | replace the status body, bump `edited_at`, notify clients |
| `Delete` | tombstone by activity `id` **or** by the object's own id; remove from timelines |
| `Announce` | a boost: store the wrapper, not a copy of the boosted post |
| `Like` | favourite by the actor's id; duplicate Likes are no-ops |
| `Block` | record, and stop delivering anything to that domain |

**Idempotency is keyed on the activity `id`, never on a hash of the body.** Two
different retries of the same `Follow` must collapse; two genuinely different
`Create`s that happen to have identical text must not.

## Delivery

```text
status published
  └── enqueue deliver (host, activity_json) per distinct inbox
        ├── shared inbox preferred: one request per host, not per follower
        ├── 10 concurrent per host, serialised per inbox
        ├── 429/503 honour Retry-After, otherwise exponential backoff 1 m → 6 h, 10 attempts
        └── permanent 4xx (400, 401, 403, 410) stops after one attempt and marks the follower dead
```

- **Per-host queues.** One slow or hostile instance must not delay deliveries to
  everyone else, so the worker picks jobs ordered by `(priority, earliest_at)` with
  a per-host `IN (SELECT …)` exclusion — the same shape as the recommender's token
  pool, for the same reason.
- **Never inside a transaction.** The job row commits with the status; the HTTP call
  happens later, in the worker, with no lock held.
- **Delivery is at-least-once.** Remotes must dedupe; ours does.

## Fetching

Remote actors, statuses and media are fetched lazily and cached: actor documents 15
minutes, statuses 5 minutes, media by digest forever. Fetching requires an
`Accept: application/activity+json` GET signed with the **instance actor's** key
(`/actor`), because some instances refuse unsigned fetches — Mastodon itself does
not, but spending one signature is cheaper than discovering who does.

## What "compatible" means here

Testable against real software, in this order:

1. A local post is delivered to `mastodon.social` and appears in a follower's
   timeline there (the only test that proves signatures, digest and ordering).
2. A post from `mastodon.social` reaches a local follower's home timeline within a
   minute.
3. Follow from a remote account is accepted, and its `Accept` reaches the remote.
4. Delete and edits propagate.
5. An unsigned or replayed inbox POST is rejected with `401` and leaves no rows.

## Explicitly deferred

- `Move` (account migration), `EmojiReact`, `Question` polls in activities, relays,
  and authorized-fetch (secure mode) — all M2, after the five tests above pass.
- We do not implement `Group` actors or `FeaturedCollection`.
- We do not attempt to federate with instances that require `authorized_fetch`
  before our instance actor has a stable URL; that ordering is part of the rollout,
  not the protocol.
