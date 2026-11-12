# 00 — Scope

Status: draft · Last revised: 2026-11-07

Target: **client API compatible with Mastodon 4.3**, one instance per deployment,
single-tenant, no federation until M1 is closed. The compatibility target is the
Mastodon *client* API — the one third-party apps speak — not Mastodon's internal
admin API or its database.

## Milestones

Each milestone is closed when its acceptance test passes, not when its code merges.

### M0 — an instance apps can use

| Area | In M0 |
| --- | --- |
| Accounts | register (invite or open), confirm, profile edit, avatar/header, follow/unfollow/block/mute, relationships |
| Auth | `POST /api/v1/apps`, OAuth2 authorization code **with PKCE**, scopes `read write follow push`, revocable tokens, `verify_credentials` |
| Statuses | publish, edit (Mastodon 4.0 edit history), delete, visibility, content warning, media attachments, favourites, reblogs, bookmarks |
| Timelines | home, public (local), tag, account, list-less M0; `max_id`/`min_id`/`since_id` with `Link` headers |
| Streaming | `/api/v1/streaming` for `user`, `public:local`, `public` over SSE and WebSocket |
| Media | upload, dedupe by digest, transcode to the sizes Mastodon advertises, alt text |
| Moderation | report, silence, suspend, admin role — the minimum that makes a public instance defensible |
| Notifications | follow, favourite, reblog, mention, with `dismiss` |
| Frontend | `nodus-web` SSR mounted at `/`, client API at `/api` |

**Acceptance:** an official Mastodon app (Tusky on Android, Mona or the web client
in a browser) logs in against a fresh deployment, posts, boosts, follows, and sees
the post arrive in a second account's timeline over streaming, without any
Mastodon-specific client patch.

### M1 — federation

WebFinger, actor documents, HTTP signatures (draft-cavage, RSA-SHA256 — Mastodon
does not accept Ed25519), inbox/outbox, follow/accept/undo, Create/Announce/Like/
Delete delivery, remote account fetch and refresh, remote media caching, instance
block list. Acceptance: a post from a real Mastodon instance appears in a local
timeline within a minute of delivery, and a local post appears on that instance.

### M2 — the parts users notice when they are missing

Search (accounts, statuses, hashtags), lists, filters, polls, scheduled posts,
bookmarks export, push notifications (WebPush), admin dashboard API, migrations of
an existing account from another instance.

## Out of scope, with the reason

| Not doing | Why |
| --- | --- |
| Multi-tenancy / hosting | one deployment is one instance; sharing a database between instances is a different security model |
| Phone apps | `nodus-web` is the frontend; the client API is what makes existing apps work, not ours |
| A Mastodon-compatible admin API | it is unstable in Mastodon itself and adds surface with no user benefit yet |
| ActivityPub `Move`/account migration in M0–M1 | needs federation to be solid first; tracked for M2 |
| Tor/onion, IPFS media, other transports | nothing in the product needs them |
| Custom emoji import tooling | emoji are supported, importing from another instance is M2 |

## Non-negotiables

- **No silent data loss.** Deleting a status removes it from every timeline it was
  fanned out to, and the fan-out is the same transaction that removes the row.
- **Ids are opaque strings.** They are never parsed by clients; our own code parses
  them only through `core::Id`.
- **Compatibility is tested, not claimed.** `docs/02-api-compat.md` lists the
  surface and the probe that covers it.
- **Workers never hold a transaction across a network call.** Delivery retries;
  locks do not.
