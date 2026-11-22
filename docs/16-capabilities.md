# Capabilities: one question, three vocabularies

Before paint a client answers one question: *what does this server actually serve?* Three
vocabularies answer it — the API's list (`crates/api/src/meta.rs:32`, 42 names), the SDK's typed
`Feature` set baselined per protocol (`sdk/crates/nodus/src/baseline.rs`), and the shell's doors
(`web/crates/ui/src/capabilities.rs:56` `admits`). One name means one surface everywhere.

## 1. The publication rule

A surface is **named** when it is a user-facing door whose absence a client must handle — a panel
it should not draw, a command it should not offer. Naming is not "the route exists":
`/api/v1/instance` is a route every client calls either way.

`crates/api/tests/capabilities.rs::every_routed_surface_group_is_named_in_both_directions`
(`:1307`) parses the router's `.route(...)` literals, groups them by prefix in `SURFACE_GROUPS`
(`:974`), and refuses:

| It fails when | Why that is a bug |
| --- | --- |
| a registered route falls under no group | a surface no console can draw — how favourites, notifications and eleven more shipped unreachable |
| a named prefix covers zero routes | the name advertises a door onto a 404 |
| an allowlisted (unnamed) prefix covers zero routes | a stale allowlist row, left by a retired route |
| a group's feature is absent from `FEATURES` | the group and the published list disagree |

An advertised API name with no group fails too, as does a group claiming one of the feed's three
names (§3); the allowlist is no silencer — an unnamed group needs a `reason` over 20 characters,
a named one none (`:1356-1365`). Renaming is breaking, adding is safe. `/api/v1/meta` and
`/api/v1/nodus/capabilities` both answer from `features(share_links)`
(`crates/api/src/meta.rs:117`), so the two documents cannot disagree
(`crates/api/tests/capabilities.rs::the_handshake_and_the_protocol_screen_publish_one_vocabulary`).

## 2. The one conditional name: `drive_share`

41 names are published unconditionally; `drive_share` is not.

```rust
// crates/api/src/meta.rs:117-121
FEATURES.iter().filter(|name| **name != "drive_share" || share_links)
```

`POST /api/v1/drive/files/{id}/share` signs its link with `NODUS_DRIVE_SHARE_SECRET`
(`crates/api/src/state.rs:312-314`) and refuses without one, so an instance with no secret must not
advertise a button that can only fail: **withheld, not advertised**. A client sees no name, draws
no control, and a call made anyway reaches `Error::UnsupportedCapability` (§6). The secret is read
once and passed as a `bool` (`crates/api/src/state.rs:268`), so replicas and tests answer alike.

## 3. Three names the API does not serve

`feed_accounts`, `events` and `sync_token` belong to `nodus-feed` on the same origin
(`/api/v1/feed/accounts`, `/api/v1/events`, `/api/v1/sync/token`;
`recommender/crates/feeds/src/routes/meta.rs:19`). The API asserts they are advertised and *not
shadowed* by its router, and the lab's live check proves the sibling answers them
(`crates/api/tests/capabilities.rs:20-24`). `/api/v1/nodus/events` is **410 Gone**, "replaced by
`/api/v1/streaming`" (`crates/api/src/nodus.rs:87`).

**The Caddy trap.** Both processes answer `/api/v1/meta` — the API with 42 names, the feed with 3.
Put that path in the feed's matcher and the origin hands every same-origin client (shell, SSR
host, e2e) three names, so the instance looks like it does nothing. Hence
`integration/Caddyfile:49-55`, where the omission is deliberate:

```text
@feed path /api/v1/feed/* /api/v1/browse /api/v1/events /api/v1/feedback/* /api/v1/me /api/v1/sync/*
# /api/v1/meta is deliberately absent: listing it made every client believe we serve 3 things
```

`assert_meta_contract` (`integration/scripts/common.sh:252`, from `integration/scripts/up.sh:66`)
compares three answers for one URL: the origin through Caddy, the API on its own socket, and
`FEATURES` parsed out of `crates/api/src/meta.rs`. Disagreement fails `up.sh` and names the
cause — three names means the feed won the path, a larger mismatch a stale image.

## 4. Per protocol: a probed baseline, not documentation

Mastodon and Misskey publish nothing, and "no answer" must not read as "nothing". The baseline
comes from live probes (`sdk/crates/nodus/src/baseline.rs:1-30`): **404 = absent**; **401/403 =
present but refused** (a 403 proves the route exists; calling it absent hides working UI from the
one user who could use it — this mistake was made and fixed); **200/204/400/422 = present** (400
= a rejected parameter list). Whether *this session* may then call a surface is the token's
business, not the baseline's.

Probed 2026-11-22 against Mastodon `v4.6.3` and Misskey `2026.11.0`; row-by-row evidence in
`sdk/crates/nodus/src/baseline/decision.rs:1-47`, pinned by `baseline.rs::the_matrix_pins_every_row_as_probed`.

| | Mastodon 4.6.3 | Misskey 2026.11.0 |
| --- | --- | --- |
| served | 20 of 42 | 18 of 42 |
| both | `admin`, `moderation`, `remote_blocks`, `polls`, `instance_rules`, `remote_accounts`, `favourites`, `lists`, `notifications`, `announcements`, `search`, `directory`, `streaming` | same |
| one only | `bookmarks`, `conversations`, `filters`, `scheduled_statuses`, `markers`, `preferences`, `tags` | `report_forwarding`, `account_deletion`, `drive`, `drive_share`, `drive_attach` |

| Feature | Verdict | Why |
| --- | --- | --- |
| `appeals` | false on both | Mastodon `404 GET /api/v1/appeals` — appeals are a web flow only |
| `warnings` | false on both | `404 GET /api/v1/admin/warnings`; Misskey has no concept |
| `moderation_rules` | false on both | Mastodon's `admin/rules` **is** the instance rules, already `instance_rules` |
| `block_lists` | false on both | `/api/v1/blocks`, `i/export-blocking` are the caller's own list |
| `moderation_stats` | false on both | `admin/measures`, `admin/get-index-stats` are instance statistics |
| `streaming` | true on both | Mastodon `301` (process not started here); Misskey `503` without a websocket upgrade |
| `bookmarks` | Mastodon yes, Misskey no | `i/favorites` is favourites; `i/bookmarks` 404s |

Nodus's own column is `false` everywhere on purpose: it publishes and never guesses.

## 5. The compile-time guard

`Feature` is closed: `#[repr(u8)]` (`sdk/crates/nodus/src/feature.rs:17`), `COUNT = 42` (`:112`),
`ALL: [Self; COUNT]`. Answers are a `Copy`, allocation-free `ActiveFeatures(u64)` bitset
(`sdk/crates/nodus/src/active.rs:18`) with `const _: () = assert!(Feature::COUNT <= u64::BITS as
usize)` (`:20`). `pub(super) const fn decision(feature: Feature) -> [bool; 3]` orders the columns
`[nodus, mastodon, misskey]` with a bare `match` and no wildcard
(`sdk/crates/nodus/src/baseline/decision.rs:67`), so a new variant does not compile until it is
decided for all three:

```text
error[E0004]: non-exhaustive patterns: `Feature::NewSurface` not covered
  --> sdk/crates/nodus/src/baseline/decision.rs:67:11
67 |     match feature {
   |           ^^^^^^^ pattern `Feature::NewSurface` not covered
```

Then `feature/wire.rs`, `feature/index.rs` and the pinned matrix follow.

## 6. The error rule: a 404 is an answer only when it was predicted

```rust
// sdk/crates/nodus/src/unsupported.rs:25-40
if matches!(status, 404 | 501) && !capabilities.supports(feature) {
    Some(Error::UnsupportedCapability { feature: feature.as_str(), verb })
} else { None }
```

`Error::UnsupportedCapability { feature, verb }` (`sdk/crates/client-core/src/lib.rs:63`) reads
*"{verb} is not served: this server does not support {feature}"*, raised **only** for 404/501 on
a verb the answer says is unsupported: prediction and failure agree, so the client degrades
silently. A 404 on a **supported** verb stays `Error::Status` — a broken instance must not
masquerade as a limited one. 401, 403, 429 and 5xx are never converted.

The recommender says the same, never a retry
(`recommender/crates/calculator/src/handlers/mod.rs:88`):
`JobError::permanent("this instance does not serve {feature}: {verb} is unavailable")`, wired at
`.../sync_user/follows.rs:220`, pinned by
`.../sync_user/tests.rs::a_refused_capability_is_permanent_rather_than_retried`.

## 7. What a client does with the answer

A staff door needs three parts, all holding before it is drawn
(`web/crates/web-client/src/app.rs:551`, `:559`):

```rust
extensions.get() && moderation.get() && role.get().is_some()   // and the admin twin
```

| Third | Question | Source |
| --- | --- | --- |
| `extensions` | is this the Nodus protocol, with a contract we know? | `provider == Nodus && !contract.is_empty()`, `sdk/crates/nodus/src/capabilities.rs:119` |
| `capability` | does *this server* serve the surface? | `Surface` → `Feature` → bit test (`web/crates/ui/src/capabilities/surface.rs:16-47`) |
| `role` | may *this account* walk through? | `/api/v1/nodus/account/role` (`crates/api/src/nodus.rs:30`, §8) |

No third may draw a door alone, and each was earned: `extensions` because Mastodon's baseline
serves `admin` — its route does exist — while *Nodus*'s admin screens are a different surface;
`capability` because Misskey serves the drive; `role` because an administrator elsewhere is
nobody here.

First paint does not wait for a request. A server-painted page carries the answer in `#nodus-page`
under `capabilities`, read before probing (`web/crates/web-client/src/state/bridge/capabilities.rs:36-50`);
a page without the island — static deploy, client route, failed render — falls back to negotiating
`/api/v1/meta` once (`:1-20`). `None` means "no answer yet" and `admits` draws on it: a missing
answer is not a refusal (`web/crates/ui/src/capabilities.rs:40-56`).

Six published names have **no** `Surface`, on purpose: `preferences`, `streaming`, `tags`, `polls`,
`appeals`, `warnings` — no door to draw, so a variant would gate a row nothing queries (`Surface`
holds 15 variants, `web/crates/ui/src/capabilities/surface.rs:16-47`).

## 8. Staff is readable without an admin scope

Every account document carries Mastodon's `role` — public, `{ "name": "Admin" }` or `"Moderator"`,
absent for `none` (`crates/api/src/dto.rs:100-107`, `:202`); the token's own document also carries
nodus's `staff_role` (`:207-217`), which `verify_credentials` answers with.

The dead end this replaced: the shell probed `/api/v2/admin/accounts` for the Administration door.
That route is `admin:read`-scoped (`crates/api/src/admin/accounts.rs:822`) and the SPA's grant is
`read write follow` (`web/crates/web-client/src/state/oauth/mod.rs:33`), so it answered 403 for
every account, including the bootstrap administrator: nobody was ever staff as far as the shell
was concerned. The role is now a read of the subject the token names, needing no scope
(`crates/api/tests/account_role.rs:1-36`). `/api/v2/admin/accounts` stays admin-scoped on purpose —
it lists *other* accounts; role opens the door, scope limits what the token does past it
(`crates/api/src/auth.rs:40`).

## What to change when you add a surface

1. **Name it** in `FEATURES` (`crates/api/src/meta.rs:32`) with a comment naming its first path.
2. **Table it**: a `Capability` row (name, probe path, owner) at `crates/api/tests/capabilities.rs:60+`
   **and** a covering `SurfaceGroup` in `SURFACE_GROUPS` (`:974`).
3. **Type it**: `Feature` variant, then `COUNT`, `ALL`, `feature/wire.rs`, `feature/index.rs`.
4. **Decide it** in `baseline/decision.rs:67` for all three protocols, and add its probe row to §4.
5. **Pin it** in `sdk/crates/nodus/src/baseline.rs::the_matrix_pins_every_row_as_probed`.
6. **Draw it** if it is a door: a `Surface` variant with `capability()`, `name()`, `title()`, `absent()`.
7. **Handle the refusal** with `nodus_protocol::unsupported::capability_error`, and in the
   recommender with `JobError::permanent` (`.../handlers/mod.rs:88`).
8. **Rebuild the lab and run `integration/scripts/up.sh`**: `assert_meta_contract` catches a stale
   image before the e2e suite tests a binary nobody edits.
