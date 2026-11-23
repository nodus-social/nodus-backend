# Capabilities: one question, three vocabularies

Before paint a client answers one question: *what does this server actually serve?* Three
vocabularies answer it — the API's list (`crates/api/src/meta.rs:39`, 62 names), the SDK's typed
`Feature` set baselined per protocol (`sdk/crates/nodus/src/baseline.rs`), and the shell's doors
(`web/crates/ui/src/capabilities.rs:56` `admits`). One name means one surface everywhere.

The 62 names are not only routes: thirteen administration pages and eight moderation sections are
names of their own, while `admin` and `moderation` went on meaning the *area* (§5). An area bit
says the room exists; a page name says which screens inside it answer.

## 1. The publication rule

A surface is **named** when it is a user-facing door whose absence a client must handle — a panel
it should not draw, a command it should not offer. Naming is not "the route exists":
`/api/v1/instance` is a route every client calls either way.

`crates/api/tests/capabilities.rs::every_routed_surface_group_is_named_in_both_directions`
(`:1757`) parses the router's `.route(...)` literals, groups them by prefix in `SURFACE_GROUPS`
(`:1198`), and refuses:

| It fails when | Why that is a bug |
| --- | --- |
| a registered route falls under no group | a surface no console can draw — how favourites, notifications and eleven more shipped unreachable |
| a named prefix covers zero routes | the name advertises a door onto a 404 |
| an allowlisted (unnamed) prefix covers zero routes | a stale allowlist row, left by a retired route |
| a group's feature is absent from `FEATURES` | the group and the published list disagree |

An advertised API name with no group fails too, as does a group claiming one of the feed's three
names (§3); the allowlist is no silencer — an unnamed group needs a `reason` over 20 characters,
a named one none (`:1816-1825`). Renaming is breaking, adding is safe. `/api/v1/meta` and
`/api/v1/nodus/capabilities` both answer from `features(share_links)`
(`crates/api/src/meta.rs:150-154`), so the two documents cannot disagree
(`crates/api/tests/capabilities.rs::the_handshake_and_the_protocol_screen_publish_one_vocabulary`).

A page name cannot be proved by its prefix alone when a sibling page shares the route family, so
page names have a second table and a second test — §5.

### Not yet a capability: `notification_settings`

The settings strip wants a Notifications tab, but this backend serves no notification policy to
put behind it, so no name is published and the tab stays hidden on purpose. The inbox is a
reader, not a setting: `GET /api/v1/notifications`, `/clear`, `/{id}` and `/{id}/dismiss`
(`crates/api/src/notifications.rs:483-486`) read and acknowledge rows written by the follow,
favourite, reblog and mention paths. `GET /api/v1/preferences`
(`crates/api/src/preferences.rs:15-35`) answers Mastodon's posting and reading defaults only —
no notification kind, no email channel. The closest thing is the `notifications` flag on one
account's mute (`crates/api/src/accounts.rs:421-424`), which chooses whether that relationship's
events reach the inbox: a per-relationship fact, not an account-wide policy. No migration stores
one either. A `notification_settings` name with no route group would be a door onto a 404, and
`FEATURES` is the promise, so it is withheld until a route group exists to answer it.

## 2. The one conditional name: `drive_share`

61 names are published unconditionally; `drive_share` is not.

```rust
// crates/api/src/meta.rs:150-154
FEATURES.iter().filter(|name| **name != "drive_share" || share_links)
```

`POST /api/v1/drive/files/{id}/share` signs its link with `NODUS_DRIVE_SHARE_SECRET`
(`crates/api/src/drive.rs:970-972`) and refuses without one (`:600-605`), so an instance with no
secret must not advertise a button that can only fail: **withheld, not advertised**. A client sees
no name, draws no control, and a call made anyway reaches `Error::UnsupportedCapability` (§7). The
secret is read once and passed as a `bool` (`crates/api/src/state.rs:268-280`), so replicas and
tests answer alike.

## 3. Three names the API does not serve

`feed_accounts`, `events` and `sync_token` belong to `nodus-feed` on the same origin
(`/api/v1/feed/accounts`, `/api/v1/events`, `/api/v1/sync/token`;
`recommender/crates/feeds/src/routes/meta.rs:19`). The API asserts they are advertised and *not
shadowed* by its router, and the lab's live check proves the sibling answers them
(`crates/api/tests/capabilities.rs:20-24`). `/api/v1/nodus/events` is **410 Gone**, "replaced by
`/api/v1/streaming`" (`crates/api/src/nodus.rs:87`).

**The Caddy trap.** Both processes answer `/api/v1/meta` — the API with 62 names, the feed with 3.
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
`sdk/crates/nodus/src/baseline/decision.rs:1-75`, pinned by
`baseline.rs::the_matrix_pins_every_row_as_probed` (`:150`).

| served | Mastodon 4.6.3 | Misskey 2026.11.0 |
| --- | --- | --- |
| served on | 33 of 62 | 28 of 62 |
| both (22) | `admin`, `moderation`, `remote_blocks`, `polls`, `instance_rules`, `remote_accounts`, `favourites`, `lists`, `notifications`, `announcements`, `search`, `directory`, `streaming`, `admin_overview`, `admin_announcements`, `admin_audit`, `admin_rules`, `admin_settings`, `moderation_accounts`, `moderation_federation`, `moderation_registrations`, `moderation_reports` | same |
| Mastodon only (11) | `bookmarks`, `conversations`, `filters`, `scheduled_statuses`, `markers`, `preferences`, `tags`, `admin_domains`, `admin_email`, `admin_replies`, `moderation_appeals` | — |
| Misskey only (6) | — | `report_forwarding`, `account_deletion`, `drive`, `drive_share`, `drive_attach`, `admin_federation` |
| neither (23) | 23 names | 23 names |

| Feature | Verdict | Why |
| --- | --- | --- |
| `appeals` | false on both | Mastodon `404 GET /api/v1/appeals` — appeals are a web flow only |
| `warnings` | false on both | `404 GET /api/v1/admin/warnings`; Misskey has no concept |
| `moderation_rules` | false on both | Mastodon's `admin/rules` **is** the instance rules, already `instance_rules`. The page name predates the split and is reused (§5), it is not a second API |
| `block_lists` | false on both | `/api/v1/blocks`, `i/export-blocking` are the caller's own list |
| `moderation_stats` | false on both | `admin/measures`, `admin/get-index-stats` are instance statistics |
| `streaming` | true on both | Mastodon `301` (process not started here); Misskey `503` without a websocket upgrade |
| `bookmarks` | Mastodon yes, Misskey no | `i/favorites` is favourites; `i/bookmarks` 404s |
| `admin_audit` | true on both | Mastodon's `/admin/action_logs` is a DECLARED web route (`GET /api/v1/admin/audit` is not routed); Misskey answers `admin/show-moderation-logs` |
| `admin_protocol` | false on both | no protocol API to serve: the page renders `/api/v1/nodus/capabilities` itself |

Nodus's own column is `false` everywhere on purpose: it publishes and never guesses.

## 5. An area is not its pages

The vocabulary grew from 42 to 62 when the administration and moderation screens became names of
their own: thirteen `admin_*` names and seven new `moderation_*` names. It is 62, not 63, because
`moderation_rules` was already published for the rules engine and is reused as the moderation
rules page. One page must not answer two names, or a door would light on evidence about something
else (`sdk/crates/nodus/src/baseline/decision.rs:9-11` says the same at the table); the twenty new
names are appended after the original forty-two (`sdk/crates/nodus/src/feature.rs:158`), so no
existing bit moved.

Two rules govern the split, and they point in opposite directions on purpose:

1. **`admin` and `moderation` mean the area exists.** They are the room, not the screens in it.
   Each page inside has its own name, and a page whose name is absent draws a named explanation
   at its own address ("This instance does not serve the topology view."). The area is never hidden
   because one page is missing: a server that serves reports but not appeals still has an
   administration area, and the shell still draws it.
2. **The rail door keys on the account's role, and refuses without one.** A served area is
   necessary and not sufficient: the door is drawn only when the account's own credentials report
   a staff role (nodus `staff_role`, Mastodon `role`). A refused, absent or unread role means no
   door — fail closed. A direct visit to the address still explains itself page by page, so fail
   closed hides a door, never content.

Which fact each decision keys on:

| Decision | Keys on |
| --- | --- |
| the area's rail door is drawn | extension + area served + positive role evidence (`staff_door`, `web/crates/ui/src/capabilities.rs:74`) |
| a page's tab is shown | that page's name is served (`web/crates/web-client/src/routes/admin/mod.rs:146`) |
| a page's content is drawn | that page's name is served; otherwise the page renders `UnservedPage` (`web/crates/ui/src/capabilities.rs:139`) |
| an ordinary API call works | the account's accepted grant (`admin/meta`) carries the scope |
| a write panel is offered | that grant says `write` |

Those are three different facts, and the shell must not conflate them: *the server serves the area*
(a capability name), *the account could request access* (role evidence from its own credentials),
and *the account holds a working grant* (a scope). Only the last one lets a command through.

The account's credentials are the "could ask" fact, not the grant: `may_enter()` is true for
`Staff::Yes` and `Staff::NeedsGrant`
(`web/crates/web-client/src/state/bridge/admin.rs:196`) — a nodus account whose `staff_role` is
admin or moderator still gets the door, and the grant request is what follows. `Staff::Refused`,
`Staff::Unknown` and `Staff::NotStaff` draw no door.

**How a page name is proved.** Nine of the twenty-one pages have no prefix that belongs to the
page alone: either a sibling page reads the same route family, or the route is already named by an
existing API capability (`instance_rules`, `settings_transfer`, `protocol`, `escalation`). The
router-wide test cannot tell those pages apart, so `ADMIN_PAGES`
(`crates/api/tests/capabilities.rs:1591`) holds one row per page — 21 rows for 20 new names plus
the reused `moderation_rules` — and
`every_admin_page_capability_is_backed_by_a_route_or_a_declared_module` (`:889`) requires of each
row either:

- **a page-only prefix (12 names)**: `prefix: Some("/api/v1/admin/overview")`. The prefix must be
  claimed by a `SURFACE_GROUPS` group that names this page, and the router must serve it. These
  are `admin_overview`, `admin_announcements`, `admin_audit`, `admin_email`, `admin_replies`,
  `admin_scanners`, `admin_topology`, `moderation_appeals`, `moderation_flags`,
  `moderation_media`, `moderation_reports`, `moderation_rules`.
- **a declared module and a reason (9 names)**: `prefix: None`, `modules` naming the module that
  mounts the page, and a note over 20 characters explaining what a prefix would overclaim. These
  are `admin_domains`, `admin_escalation`, `admin_federation`, `admin_protocol`, `admin_rules`,
  `admin_settings`, `moderation_accounts`, `moderation_federation`,
  `moderation_registrations`. Every module must exist in `ROUTE_SOURCES`, so the declaration is
  checked against the tree, not trusted.

A name with neither fails the test: "`{name}` has neither a page-only prefix nor a declared module
with a reason". Every page must also be in `FEATURES` and in the test's `CAPABILITIES` table, and
every module must name at least one feature
(`every_admin_module_names_at_least_one_feature`, `:970`). The umbrella `/api/v1/admin` and
`/api/v2/admin` groups keep claiming `ADMIN_FEATURES` (`:1138`), which is what stops the
router-wide test from demanding a separate group per page.

The shell mirrors the table: 13 administration pages and 8 moderation sections are `Surface` rows
(`web/crates/ui/src/capabilities/surface/admin.rs`, `.../moderation.rs`) — 21 rows for the 20 new
names, with `ModerationRules` reused. Each route checks its own page's row and renders
`UnservedPage` when it is absent (`web/crates/web-client/src/routes/admin/mod.rs:146`,
`.../routes/moderation/mod.rs`). Scanners and mail-domain blocks additionally require an
administrator; that is a role question, so it sits in the route beside the capability check, not
inside the page name.

## 6. The compile-time guard

`Feature` is closed: `#[repr(u8)]` (`sdk/crates/nodus/src/feature.rs:17`), `COUNT = 62` (`:152`),
`ALL: [Self; COUNT]` with `const _: () = assert!(Feature::COUNT == Feature::ALL.len())` (`:227`).
The twenty new names are appended after the original forty-two, so the first 42 variants keep
their bits. Answers are a `Copy`, allocation-free `ActiveFeatures(u64)` bitset
(`sdk/crates/nodus/src/active.rs:18`) with `const _: () = assert!(Feature::COUNT <= u64::BITS as
usize)` (`:20`). `pub(super) const fn decision(feature: Feature) -> [bool; 3]` orders the columns
`[nodus, mastodon, misskey]` with a bare `match` and no wildcard
(`sdk/crates/nodus/src/baseline/decision.rs:90`), so a new variant does not compile until it is
decided for all three:

```text
error[E0004]: non-exhaustive patterns: `Feature::NewSurface` not covered
  --> sdk/crates/nodus/src/baseline/decision.rs:91:11
91 |     match feature {
   |           ^^^^^^^ pattern `Feature::NewSurface` not covered
```

Then `feature/wire.rs`, `feature/index.rs` and the pinned matrix follow.

## 7. The error rule: a 404 is an answer only when it was predicted

```rust
// sdk/crates/nodus/src/unsupported.rs:27-41
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

## 8. What a client does with the answer

A staff door needs three parts, all holding before it is drawn
(`web/crates/ui/src/capabilities.rs:74`):

```rust
pub const fn staff_door(extensions: bool, served: bool, eligible: bool) -> bool { … }
```

called for each area in `extra_doors` (`web/crates/web-client/src/app.rs:467-488`).

| Part | Question | Source |
| --- | --- | --- |
| `extensions` | is this the Nodus protocol, with a contract we know? | `provider == Nodus && !contract.is_empty()`, `sdk/crates/nodus/src/capabilities.rs:119` |
| `served` | does *this server* serve the area at all? | `Surface::Admin` / `Surface::Moderation` → the `admin` / `moderation` bit (`web/crates/ui/src/capabilities/surface.rs:112`) |
| `eligible` | may *this account* walk through? | positive role evidence from the account's own credentials: `Staff::Yes` or `Staff::NeedsGrant` (`web/crates/web-client/src/state/bridge/admin.rs:196`, §9) |

No part may draw a door alone, and each was earned: `extensions` because Mastodon's baseline
serves `admin` — its route does exist — while *Nodus*'s admin screens are a different surface;
`served` because Misskey serves the drive but a Mastodon session must not see Nodus's rooms;
`eligible` because an administrator elsewhere is nobody here.

Once inside an area, the pages are gated by their own rows, not by the area bit: a page whose name
is absent renders `UnservedPage(surface)` (`web/crates/ui/src/capabilities.rs:139`) on the address
itself, and the page's tab is filtered from the strip by the same answer
(`web/crates/web-client/src/routes/admin/mod.rs:146-160`). Scanners and mail-domain blocks also
require an administrator role, checked beside the row.

First paint does not wait for a request. A server-painted page carries the answer in `#nodus-page`
under `capabilities`, read before probing (`web/crates/web-client/src/state/bridge/capabilities.rs:36-50`);
a page without the island — static deploy, client route, failed render — falls back to negotiating
`/api/v1/meta` once (`:1-20`). `None` means "no answer yet" and `admits` draws on it: a missing
answer is not a refusal (`web/crates/ui/src/capabilities.rs:40-56`).

Twenty-six published names have **no** `Surface`, on purpose: no page, panel or rail door is keyed
on them, so a variant would gate a row nothing queries. They are `events`, `sync_token`,
`scanners`, `topology`, `protocol`, `remote_blocks`, `polls`, `batch`, `appeals`, `instance_rules`,
`media_quarantine`, `block_lists`, `moderation_stats`, `remote_accounts`, `warnings`, `escalation`,
`federation_delivery`, `domain_pauses`, `settings_transfer`, `report_forwarding`,
`account_deletion`, `drive_share`, `drive_attach`, `preferences`, `streaming`, `tags` (`Surface`
holds 36 rows: 15 areas and 21 pages, `web/crates/ui/src/capabilities/surface.rs:208`).

## 9. Staff is readable without an admin scope

Every account document carries Mastodon's `role` — public, `{ "name": "Admin" }` or `"Moderator"`,
absent for `none` (`crates/api/src/dto.rs:103`, `:202`); the token's own document also carries
nodus's `staff_role` (`:207-217`), which `verify_credentials` answers with.

The two protocols are read from those two fields, and the third is not read yet: a nodus session
reports `staff_role` and a Mastodon session reports `role`, but Misskey has no such document — its
`/api/i` carries `isAdmin` / `isModerator`, which this console does not read yet
(`web/crates/web-client/src/state/bridge/session/staff.rs:1-16`). A Misskey session therefore
reports no role and draws no staff doors: fail closed. Its pages still explain themselves at a
direct address, and the fix is a read of `/api/i`, not a capability name.

The dead end this replaced: the shell probed `/api/v2/admin/accounts` for the Administration door.
That route is `admin:read`-scoped (`crates/api/src/admin/accounts.rs:822`) and the SPA's grant is
`read write follow` (`web/crates/web-client/src/state/oauth/mod.rs:33`), so it answered 403 for
every account, including the bootstrap administrator: nobody was ever staff as far as the shell
was concerned. The role is now a read of the subject the token names, needing no scope
(`crates/api/tests/account_role.rs:1-36`). `/api/v2/admin/accounts` stays admin-scoped on purpose —
it lists *other* accounts; role opens the door, scope limits what the token does past it
(`crates/api/src/auth.rs:34-40`).

## What to change when you add a surface

1. **Name it** in `FEATURES` (`crates/api/src/meta.rs:39`) with a comment naming its first path.
2. **If it is a page inside an area**, add an `AdminPage` row (`crates/api/tests/capabilities.rs:1591`)
   and a `Surface` row: a page-only prefix claimed by a group, or the modules plus a reason over
   20 characters (§5).
3. **Table it**: a `Capability` row (name, probe path, owner) at `crates/api/tests/capabilities.rs:57`
   **and** a covering `SurfaceGroup` in `SURFACE_GROUPS` (`:1198`).
4. **Type it**: `Feature` variant, then `COUNT`, `ALL`, `feature/wire.rs`, `feature/index.rs`.
5. **Decide it** in `sdk/crates/nodus/src/baseline/decision.rs:90` for all three protocols, and add
   its probe row to §4.
6. **Pin it** in `sdk/crates/nodus/src/baseline.rs::the_matrix_pins_every_row_as_probed`.
7. **Draw it** if it is a door: a `Surface` variant with `capability()`, `name()`, `title()`, `absent()`.
8. **Handle the refusal** with `nodus_protocol::unsupported::capability_error`, and in the
   recommender with `JobError::permanent` (`.../handlers/mod.rs:88`).
9. **Rebuild the lab and run `integration/scripts/up.sh`**: `assert_meta_contract` catches a stale
   image before the e2e suite tests a binary nobody edits.
