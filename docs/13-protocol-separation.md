# Protocol separation

Three client-facing surfaces share one server and one storage layer:

| Surface | Wire shape | Where it lives |
| --- | --- | --- |
| ActivityPub | Actors, Notes, ordered collections, inbox/outbox, HTTP signatures | `server-sdk/crates/activitypub*`, `crates/api/src/activitypub.rs` |
| Mastodon | `/api/v1` and `/api/v2`, bearer token | `server-sdk/crates/extensions/mastodon`, `crates/api/src/{mastodon,statuses,accounts,notifications,lists,filters,...}.rs` |
| Misskey | `/api/*`, body token `i`, MiAuth, `/streaming` | `server-sdk/crates/extensions/misskey`, `crates/api/src/{misskey,miauth,streaming}.rs` |
| Nodus | `/api/v1/nodus/*`, batch, events, hash-chain sync | `server-sdk/crates/extensions/nodus`, `crates/api/src/nodus.rs` |

ActivityPub is the protocol. The other three are client APIs over the same data; none of them
may change an ActivityPub document shape, and `activitypub-core` never depends on a client
dialect.

## Detection

A client probes the documents an instance already publishes:

1. `/api/v1/nodus/capabilities` with a non-empty `contract` means Nodus.
2. `/api/meta` with `maxNoteTextLength` means Misskey.
3. `/api/v2/instance` means Mastodon compatibility.

The SDK exposes this as `Probe`/`Protocol` and a typed `NodusClient`; Mastodon and Misskey
remain the compatibility floor. Detection chooses the richest surface, not the only one that
works.

## Administration and moderation

Moderation is server policy, not a protocol: reports, audit rows, account actions, domain
blocks and measures live in `crates/store/src/moderation.rs` and are exposed through the
Mastodon admin namespace and the server's own admin routes. Every mutation writes an audit
row, and blocked domains are refused when ingesting remote ActivityPub content.
