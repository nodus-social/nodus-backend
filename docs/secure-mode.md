# Secure mode (authorized fetch)

Status: **live on `https://nodus.luxuride.eu` since 2026-11-19** · Last revised: 2026-11-19

Secure mode requires an HTTP signature from the asking instance before this instance
serves an ActivityPub document. It is the same setting Mastodon calls
`AUTHORIZED_FETCH`: off, anyone can scrape every profile and post by pretending to be a
browser; on, a read has to say who is asking.

The switch is `NODUS_AUTHORIZED_FETCH`. Code: `crates/api/src/authorized_fetch.rs`,
installed on the root router in `crates/api/src/lib.rs` (`require_signature`). The flag
is read once at boot, so changing it needs `systemctl restart nodus-api` — and only that
unit.

## What is on, and where

On CT 118 (`nodus`), `/etc/nodus-backend.env`:

```text
NODUS_AUTHORIZED_FETCH=true
```

Backup taken before the edit: `/etc/nodus-backend.env.bak-20261119-091136`.

Enabled 2026-11-19 09:11 UTC. All six units stayed active (`nodus-api`, `nodus-calc`,
`nodus-feed`, `nodus-media`, `nodus-prune`, `nodus-scan`) and `/readyz` answered 200
one second after the restart; the clause is global, not per unit.

## What it covers

A `GET` or `HEAD` needs a signature (RSA-SHA256, covering at least `(request-target)`
and `date`, dated within an hour) when it targets:

- `/actor`, `/users/*`, `/objects/*`, `/statuses/*` — the ActivityPub documents;
- any other path when the request asks for `application/activity+json` or
  `application/ld+json`.

Anything else is untouched. The middleware wraps the API router
(`root_router` in `crates/api/src/lib.rs`), so it sees `/api/*`, `/oauth/*`, `/auth/*`,
`/users/*`, `/actor`, `/inbox`, `/statuses/*` and the ActivityPub documents. The
server-rendered shell (`/home`, `/admin`, `/api/session`) is a different process behind
Caddy, and `/media/*` is `nodus-media`; neither passes through this middleware.

## Exemptions, and why each exists

| Exemption | Why |
| --- | --- |
| `/.well-known/*` (WebFinger) | Discovery comes before a peer knows the key it would sign with. Requiring a signature here makes the instance unfindable, not private. |
| `/api/*` | The client API has its own authentication (bearer token, OAuth scopes) and its own rules; it is not an ActivityPub document and must keep answering apps and the console. |
| `/media/*` | Bytes, not documents. Media URLs are embedded in signed documents and fetched by browsers; gating them breaks rendering without protecting a post. |
| `POST /inbox` | Delivery is a `POST` that already verifies its own signature and has its own replay rules. Secure mode is about reads. |
| A bearer token this instance issued | Our own sessions are not a scrape. The browser console and the apps carry a token we minted, so they are let through; requiring a signature would lock our users out of their own instance. Unknown, revoked or malformed tokens fall through to the signature check. |

The exemption list is deliberately path-shaped and narrow: `/.well-known/`, `/api/`,
`/media/`, plus `POST`.

## Turning it off

```sh
ssh root@hyper.luxuride.eu
pct exec 118 -- cp -a /etc/nodus-backend.env /etc/nodus-backend.env.bak-$(date +%F)
pct exec 118 -- sed -i '/^NODUS_AUTHORIZED_FETCH=/d' /etc/nodus-backend.env
pct exec 118 -- systemctl restart nodus-api
pct exec 118 -- curl -s -o /dev/null -w '%{http_code}\n' -H 'Accept: application/activity+json' https://nodus.luxuride.eu/actor   # expect 200
```

Deleting the line (or setting it to `false`) restores the previous behaviour exactly:
the middleware returns `next.run(request)` before doing any work.

## Evidence collected on 2026-11-19

Before the flag (09:10 UTC):

```text
GET /actor                Accept: application/activity+json  -> 200   (our own actor document)
GET /users/luxuride                                           -> 200
GET /.well-known/webfinger?resource=acct:luxuride@…           -> 200   (self link: /users/luxuride)
GET /healthz                                                  -> 200
GET /home                                                     -> 200
GET /api/v1/meta                                              -> 200 application/json
signed   GET https://mastodon.social/users/Gargron            -> 200
unsigned GET https://mastodon.social/users/Gargron            -> 401   (that peer enforces)
```

After the flag and restart (09:12–09:18 UTC):

```text
GET /actor, /users/luxuride, /users/luxuride/outbox, /statuses/<id>   -> 401 application/json
  {"error":"this instance requires an HTTP signature for ActivityPub reads (secure mode is on)"}
same paths with Authorization: Bearer <token issued here>             -> 200
GET /home, /admin                                                     -> 200
GET /healthz, /api/v1/meta, /.well-known/webfinger                    -> 200
GET /media/<missing>                                                  -> 404   (not 401: exempt)
POST /inbox (unsigned)                                                -> 401 {"error":"missing signature"}   (the inbox's own gate)
signed GET /actor and /users/luxuride (key of a local account)        -> 200
signed GET with a Date an hour stale                                  -> 401 "the signed Date is more than an hour from now"
signed GET replayed against a different path                          -> 401
```

The signed requests were produced with the repo's own signer,
`nodus_server_federation::sign`, driving the live instance key and the stored key of the
local account `luxuride` (a throwaway binary, not a test double); nothing was inferred
from the unit tests. The refusals appear in the journal as:

```text
INFO nodus_server_api::authorized_fetch: refused an unsigned secure-mode read method=GET path=/actor \
  reason=this instance requires an HTTP signature for ActivityPub reads (secure mode is on)
```

Over the ten minutes after the restart the only refusals were the probes above; no peer
request was refused, `/readyz` stayed 200 and all six units stayed active.

## Known gap: a keyId on our own domain cannot verify

A signature whose `keyId` is the instance actor (`https://nodus.luxuride.eu/actor#main-key`)
is refused — including one made with our own instance key:

```text
refused an unsigned secure-mode read method=GET path=/actor \
  reason=cannot fetch the signing actor's key: activitypub read failed: error sending request for url (https://nodus.luxuride.eu/actor)
```

The verifier looks the signer's key up in `account` first, then fetches the actor
document. The instance actor is not an account row, so it tries to fetch our own
`/actor`, and that outbound fetch fails from inside the container. Nothing federates
with the instance actor pointed at this instance, so no peer read is affected — remote
accounts are found in `account` (or fetched successfully) and local accounts resolve
without the network. To test a signed read on this host, sign with a local account's key
(`/users/<user>#main-key`), not the instance actor.

Turn the flag off if this ever matters in production. A real fix would fall back to the
configured instance key when the keyId names our own actor; that is a code change, not
an operational one, and has not been made.
