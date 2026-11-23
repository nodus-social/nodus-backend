# 18 — Sharding the store

Status: design note. This is the classification that decides which future schema changes are
cheap: which tables already have a single owner and can be moved behind it, which must be
replicated whole, and which are cross-shard by design. It is not a plan to shard now.
Scope: the `nodus-backend` tree at the commit this landed on. Every `file:line` citation below
was re-checked against that tree by opening the cited line (264 citation occurrences, 197
distinct cites; see "Verification" at the end).

This document answers one question: **if this data had to live on more than one Postgres
database, what breaks, and which of those breaks can be removed today by changing schema
and query shape only?**

It is not a plan to shard now. It is the classification that decides which future changes
are cheap and which are expensive.

## Target

One instance, a few hundred thousand monthly actives, growing by one machine at a time.
X-scale is explicitly out of scope. Nothing here asks for a second shard to exist: the point
is that **no data moves onto a shard until a second shard exists for a reason**, and that the
changes which make a move possible later are the same changes that make the queries honest
now (one owner per statement, no cross-account joins outside a written list). Everything
below is judged against that scale: a k-way merge over 4 shards is fine, a distributed
transaction across them is not.

## Method and its limits

- The roster of tables, every foreign key, and every index cited below was read out of
  `crates/store/migrations/*.sql` and `crates/store/src/*.rs`, not recalled. Each citation is
  `file:line`.
- The roster of tables, every foreign key, and every index cited below was read out of
  `crates/store/migrations/*.sql` and `crates/store/src/*.rs`, not recalled. Each citation is
  `file:line`, and each was opened again after the first draft: the survey was written by eye
  and then checked mechanically, so the cited lines are observed, not estimated.
- The FK list in §3.2 is **exhaustive over `crates/store/migrations`**: 72 `CREATE TABLE`
  statements (69 plain, 3 `IF NOT EXISTS`) were enumerated, and every inline `REFERENCES` was
  checked against the roster. Nothing outside those files adds a constraint.
- Line numbers are counted from the file as it stands in this tree. Where a statement spans
  several lines I cite the range; a table row cites its `CREATE TABLE` line. The
  `0051_cloud_drive.sql` composite foreign keys are cited by constraint name instead of line.
- Anything that depends on runtime behaviour is marked **ASSUMED** with the observation that
  would settle it; the Verification section at the end records which of those were settled
afterwards.
- Migration numbering has gaps at `0046` and `0049`. `crates/store/migrations/` contains no
  such files (the listing runs 0045 → 0047 → 0048 → 0050), so they never landed in this tree
  and the gaps hold no tables.

---

## 1. Shard key

**Recommendation: `account.id` — the local account's ULID — as the shard key, with one
rule: `shard(row) = shard(owner_account_id)`, where the owner is the account that *is* the
row (its profile, its posts, its drive, its preferences) or the account that *holds* it
(its timeline entries, its notifications, its bookmarks).**

Remote accounts (`account.domain IS NOT NULL`) are not routed by membership; they are
pinned by `hash(account.uri)`. This is not a detail. If remote rows land on the shard of
whoever fetched them first, the same remote post exists twice, `status.uri UNIQUE`
(`crates/store/migrations/0001_init.sql:57`) stops holding, and every counter that counts
`status` rows double-counts. A deterministic function of the URI keeps ingest idempotent
with no coordination: any shard can compute where a remote actor belongs.

### What it buys

1. **Every affine read stays one-shard, unchanged.** Outbox (`statuses.rs::account_page`),
   profile by id (`profile_rows`), export (`export_page`), drive (`drive.rs`, and
   `0051_cloud_drive.sql`'s header comment already states this design intent explicitly),
   preferences, filters, lists, markers, notification inbox, scheduled posts, tag follows.
   That is most of the request surface, and it is already written as `WHERE account_id = $1`.
2. **The single-writer invariant composes.** `writer.rs:1-30` is "one actor, one connection,
   one transaction per batch — the actor is the lock". One writer per shard is the same
   design, repeated; no lock protocol has to be invented. A shard key that is *not* the
   account (say, `status.id`) would break this, because a batch would mix shards.
3. **The home cache is already keyed by it.** `crates/api/src/home.rs` keys its Valkey ZSET
   by account id, and `invalidate.rs:1-24` sends `{"account_id": …, "kind": …}`. Choosing
   the account id as the shard key means the invalidation channel and the shard map are the
   same function — one less thing that can disagree.
4. **It matches the natural ownership of the data.** `status.account_id`,
   `media_attachment.account_id`, `drive_object.account_id`, `marker.account_id` already
   exist on every affine table. No new column is needed anywhere to route.
5. **It is granular enough at this scale.** A few hundred thousand monthly actives is a few
   tens of GB of statuses plus media pointers — one shard's worth for years. The key is
   chosen for the *shape* of the move, not the timing of it.

### What it costs

1. **No cross-shard transaction.** Today several operations are one transaction over rows
   that belong to two accounts: `social.rs:98-111` locks both accounts `FOR UPDATE`,
   `social.rs:114-132` recomputes both counters, `statuses.rs:1298-1321` fans a new post
   into every follower's `timeline_entry` inside the author's transaction. All of these
   become either (a) a queue-mediated projection through the existing `job` table
   (`0001_init.sql:185`), or (b) a dual-write with a documented reconciliation. Counters
   that today are exact (`followers_count`, `favourites_count`, `replies_count`,
   `reblogs_count`) become eventually consistent. That is the single largest semantic loss.
2. **Fan-out on write becomes fan-out on network.** Home timelines, notifications, and
   mention alerts are all "write one row per affected account". Under one database that is
   one `INSERT … SELECT`. Under shards it is one insert per destination shard, batched.
3. **A global read becomes a k-way merge.** `public_page` (`statuses.rs:490-518`) and
   `tag_page` (`statuses.rs:849-889`) are `ORDER BY s.id` over every account. Sharded, they
   are merges of per-shard pages with the same cursor. This works *because* ids are ULIDs
   whose lexicographic order is creation order (see below), but the merge is code that does
   not exist.
4. **Global uniqueness becomes per-shard uniqueness.** The full list is in §3.4. Handle
   uniqueness is the one that hurts: `account_local_username_idx` /
   `account_remote_username_idx` (`0001_init.sql:36-37`) are what stop two accounts being
   `@alice@example.social`. Sharded, that needs a replicated handle index or a directory
   lookup on registration.

### Do ids need to encode their shard?

**No, and I would refuse to do it.** Routing is by account, not by id: every read that
matters already carries `account_id`, either as the predicate (outbox, home, drive) or as
the authenticated viewer (public timeline personalisation via `account_domain_block`,
`account_relation`). Prefixing a ULID with a shard number buys nothing for those.

The one honest exception, and it should be stated rather than waved away:

- **Id-addressed reads have no routing key.** `statuses.rs::by_id` is
  `SELECT … FROM status s WHERE s.id = $1 AND s.deleted_at IS NULL`
  (`crates/store/src/statuses.rs:68-74`) — no account predicate, by design, because the
  caller is `GET /api/v1/statuses/{id}` or a federation fetch by URI. Same shape:
  `external_ids::resolve` (`crates/store/src/external_ids.rs:10-24`, table `0005`, no
  account column anywhere) and the `uri`-keyed writes `delete_remote` /
  `update_remote_content`. These must either fan out (ask every shard, take the hit) or go
  through a directory. A directory is the cheaper answer and it already exists in embryo:
  `external_id` is a table whose whole job is "given an id I did not mint, tell me the
  local row". Growing it into `(kind, external_id) → (shard, local_id)` is one nullable
  column, not a re-encoding of every id in the system.

- **Sortability is load-bearing; a prefix in the leading bytes would destroy it.**
  `docs/04-storage.md` fixes the contract: a 26-character Crockford base32 ULID, monotonic
  within a millisecond, lexicographic order equals creation order, so `id > cursor ORDER BY
  id` is a correct `since_id` query. `ORDER BY s.id` with `id > $cursor` appears in
  `public_page`, `tag_page`, `account_page`, `profile_rows`, `list_page`, `home_page` and
  `notifications()`; the whole paging model is that ordering. A shard prefix must sit in
  the *most significant* characters to be readable without a lookup, and that reorders
  every page by shard first and time second — the timeline would be grouped by shard.
  Encoding it in the random tail instead would preserve timestamp ordering, but the tail is
  where "monotonic within a millisecond" comes from (a monotonic counter), so stealing bits
  from it weakens the uniqueness/monotonicity property that the cursor rule depends on.
  Either way the cost is real and the benefit is nil, because the account already routes.

So: routing is by account. Ids stay opaque. The only thing that must become routable is the
*lookup path from a foreign id to an account*, and that is one directory table.

---

## 2. Table classification

72 tables, each with the migration that creates it. The tiebreak rule, stated so it can be
argued with:

- **SHARD-AFFINE** — the row belongs to exactly one account; its primary read and its
  primary write both key on that account; no other account's request path reads its rows.
  The row ships with its account and is unreachable from anywhere else.
- **GLOBAL-REPLICATED** — the row is an instance fact: a domain, a remote actor URI, a
  scanner, a rule, a config singleton, or a queue every worker polls. Small, read from
  everywhere, written rarely. Replicating it to every shard is cheaper than routing to it.
- **CROSS-SHARD-BY-DESIGN** — the row names two accounts, or one account plus another
  account's row. It cannot be affine without lying, and it cannot be replicated without
  becoming a distributed write. These are the tables that need a mechanism.

Any table where this rule gives an uncomfortable answer is marked `UNRESOLVED` or called out
under §2.4 rather than quietly filed.

### 2.1 SHARD-AFFINE (28)

| table | created | why (≤12 words) |
|---|---|---|
| `account` | `0001_init.sql` | The anchor row itself; the shard key's home. |
| `account_credential` | `0003:5` | Login material for one account, read only at login. |
| `account_domain_block` | `0056` | Reader's own domain mutes; already `(account_id, host)` unique. |
| `account_preference` | `0059` | One row per account, read on every request. |
| `account_style_public` | `0060` | Owner's page layout; served only to that account's token. |
| `auth_session` | `0003:13` | Browser session for one account. |
| `drive_folder` | `0051` | Owner's namespace; `PRIMARY KEY (account_id, id)`. |
| `drive_object` | `0051` | Same; `0051` states the design intent in its header. |
| `featured_tag` | `0024:16` | Owner's pinned tags. |
| `federation_delivery` | `0028:8` | One local actor's outbound work queue. Caveat §3.4. |
| `filter` | `0018:21` | Owner's filters. |
| `filter_keyword` | `0018:34` | Child of a filter; same shard by construction. |
| `list` | `0018:2` | Owner's list. |
| `marker` | `0023:5` | Owner's read positions; `last_read_id` already has no FK. |
| `media_attachment` | `0001:100` | Author's media; `status_id` is the author's own post. |
| `media_variant` | `0008:6` | Child of `media_attachment`; same shard. |
| `moderation_strike` | `0044:13` | Keyed by affected account, read on that account's write path. |
| `notification_policy` | `0057` | One row per (account, kind), read when writing its notifications. |
| `oauth_code` | `0003:24` | One account's authorization code. |
| `oauth_token` | `0001:170` | One account's token; `app_id` points at a replicated table. |
| `poll` | `0033:9` | Lives with its status, i.e. with the author. |
| `poll_tally` | `0034` | Aggregate per poll option; same shard. |
| `scheduled_status` | `0024:4` | Owner's queued post. |
| `status` | `0001:54` | Authored by one account; three foreign refs leave it (§3.2). |
| `status_edit` | `0052:7` | Revision of one post; affine only via `status_id`. |
| `status_emoji` | `0034` | Custom emoji used by one post; same shard. |
| `status_tag` | `0001:92` | Tag of one post; row ships with the author. |
| `tag_follow` | `0053` | Owner's tag subscriptions; indexed by tag for the follower read. |

### 2.2 GLOBAL-REPLICATED (26)

| table | created | why (≤12 words) |
|---|---|---|
| `admin_alert` | `0011` | Instance-wide alert stream; `account_id` is a pointer, not an owner. |
| `announcement` | `0020` | Instance announcement, staff-written, read by everyone. |
| `audit_log` | `0017:23` | Instance audit trail; `actor_id` nullable. |
| `collection_state` | `0006` | Root hash per event-log collection. |
| `custom_emoji` | `0004:6` | Instance emoji set, keyed `(shortcode, host)`. |
| `domain_block_subscription` | `0038` | Subscribed blocklists fetched over HTTP. |
| `domain_pause` | `0045:12` | Domain-keyed, evaluated on every read; names no local account. |
| `email_domain_block` | `0026` | Registration policy keyed by domain. |
| `escalation_policy` | `0044` | Singleton config row (`id boolean PRIMARY KEY DEFAULT true`). |
| `event_log` | `0006` | Hash-chained log; `seq bigserial` is a global sequence (§5.14). |
| `external_id` | `0005` | Foreign-id → local-id map; the routing directory in embryo. |
| `instance_allow` | `0017` | Domain allowlist. |
| `instance_block` | `0017` | Domain blocklist (severity, reject_media, …). |
| `instance_rule` | `0024:31` (+`0040`) | Published instance rules; `0040` explains why ids stay text. |
| `job` | `0001:185` | The queue every worker polls; polymorphic `subject_id`, no FK. |
| `media_node` | `0050` | Placement member list; deliberately no per-object placement table. |
| `miauth_session` | `0007` | `UNRESOLVED` by the rule — exists before the account is known; `account_id` is nullable, `0007_miauth.sql:6` (§2.4). |
| `moderation_rule` | `0041` | Keyword/regex rules; `id uuid DEFAULT gen_random_uuid()`. |
| `oauth_app` | `0001:159` | Registered client applications. |
| `remote_block` | `0029` | Keyed by remote `actor_uri`. |
| `remote_moderation` | `0035` | Decision keyed by remote `actor_uri`, evaluated on every read. |
| `scan` | `0027:56` | Scanner queue over arbitrary subjects (`subject_id` text, no FK). |
| `scanner` | `0027` | Scanner endpoint config. |
| `scanner_asset` | `0027` | Hashes/weights/wordlists as `bytea`. |
| `scanner_rule` | `0027` | Per-scanner label thresholds. |
| `warning_preset` | `0026` | Staff-authored preset text. |

### 2.3 CROSS-SHARD-BY-DESIGN (18)

| table | created | why (≤12 words) |
|---|---|---|
| `account_relation` | `0019` | Two accounts; blocks must be readable from both sides. |
| `announcement_read` | `0020:15` | Reader's receipt for a global announcement: affine child, replicated parent. |
| `appeal` | `0039:8` | Global moderation queue; subject one account, decider another. |
| `bookmark` | `0001:126` | Reader's marker on someone else's status. |
| `conversation_mute` | `0024:24` | Reader's mute on a root that may be a foreign post. |
| `conversation_read` | `0023:14` | Reader's read position on a root that may be foreign. |
| `favourite` | `0001:118` | Two accounts: who favourited, whose post. |
| `follow` | `0001:40` | Two accounts; the edge is read from both directions. |
| `list_account` | `0018:14` | List owner's membership of another account. |
| `moderator_note` | `0026:15` | Staff author, subject account: two accounts on a global record. |
| `notification` | `0001:145` | Recipient's row about another account's action. |
| `poll_vote` | `0033:23` | Voter on someone else's poll. |
| `report` | `0017:6` | Reporter, target, and `status_ids text[]` with no FK by design. |
| `report_forward` | `0047` | Delivery state of a forwarded report to another instance. |
| `scan_flag` | `0027` | Moderator queue row naming a status, an account, a resolver. |
| `status_mention` | `0001:86` | Mentioned account on someone else's post. |
| `status_reaction` | `0004:16` | Reactor and author. |
| `timeline_entry` | `0001:135` | Reader's timeline holding another account's status. |

### 2.4 Tables I could not place cleanly (the interesting ones)

1. **`miauth_session`** (`0007`) — `UNRESOLVED`, and it is the important one. `account_id` is
   *nullable* (`crates/store/migrations/0007_miauth.sql:6`, no `NOT NULL`), because the row exists from the moment the MiAuth handshake starts, before
   anyone knows who the account is. A session row therefore cannot be routed by account at
   all; it must be reachable by `session.id` alone, i.e. from any shard. Filed as global by
   necessity. **This is the table that proves the routing layer needs a "not yet known"
   case** — either the login handshake pins a shard in the cookie, or pre-account rows live
   in a small global database.
2. **`external_id`** (`0005`). No account column; looked up by `(kind, external_id)` — it
   answers "which local row is this?" from an id the instance never minted. Either it stays
   global (correct and cheap: small, append-mostly) or it grows a `shard` column and becomes
   the directory for `by_id` too (§1).
3. **`status_edit`** (`0052`). Affine through its parent but with no `account_id` of its own,
   and it carries the only `bigint GENERATED ALWAYS AS IDENTITY` in the schema (`0052:8`). A
   per-shard identity is fine here (ordering is `created_at DESC, id DESC` *within* one
   `status_id`, which never crosses shards), but it is worth naming: the "everything is an
   app-minted ULID" story that makes sharding easy is not literally true.
4. **`moderator_note`, `appeal`, `report_forward`, `scan_flag`.** All four are moderation
   work items: a global queue whose subject lives on a shard. CROSS-SHARD is right, but the
   mechanism is "global queue, soft reference", not "co-locate with the subject" — a
   moderator's queue must not become a union of N work lists behind N cursors.
5. **`federation_delivery`.** Affine to the local actor, so filed affine. But its
   `UNIQUE (inbox_url, activity_id)` (`0028:21-22`) is a global dedupe claim, and `0047`
   attaches a trigger that updates `report_forward` when a delivery row changes state — a
   cross-table coupling that assumes both rows are in one database (§5.13).
6. **`job` / `scan`.** Global queues with polymorphic `subject_id` and no FK. The subjects
   are on shards, the queue is not. Correct as designed, but every job payload must be
   readable without a join, because the worker may be on a different shard from the subject.

---

## 3. Foreign keys

### 3.1 The rule

A foreign key needs its parent in the same database. So:

- **STAYS** — parent is on the same shard by construction (the child is owned by the same
  account), or the parent is a replicated table (a copy exists on every shard, so the FK is
  locally valid).
- **SOFT** — the FK must be dropped, the id column kept, and the constraint replaced by an
  application invariant plus (optionally) a reconciliation job.
  `media_attachment.stored_object_id` (`0051`) is the existing precedent: `uuid` with no FK,
  and the migration comment explains that neither cascade nor block is acceptable because a
  post outlives the file. That is exactly the argument that will apply to every FK below.
- **MOVE** — not just soft: the child needs a *copy* of a parent column (author id, handle,
  domain, actor URI) so the read that used to join does not have to. Candidates:
  `timeline_entry` (store `author_id`), `notification` (store the actor's handle/domain at
  write time, because rendering the inbox otherwise joins a foreign account row).

Dropping an FK also drops `ON DELETE CASCADE`, and cascade is what makes deletion cheap today.
Purge is **not** cascade, though — this was checked, and it changes the shape of the problem:
`accounts::purge_due` (`crates/store/src/accounts.rs:268`) is an explicit sweep. It selects due
tombstones in one statement (`:269-288`), then per id, in one transaction, scrubs the `account`
row's profile columns (`:292-303`) and deletes from exactly five tables —
`account_credential`, `auth_session`, `oauth_code`, `oauth_token`, `media_attachment`
(`:304-323`). The `account` row itself survives as a tombstone. No foreign row is touched by
the sweep at all: `favourite`, `bookmark`, `timeline_entry`, `notification`, `status_mention`,
`follow`, `account_relation`, `poll_vote`, `status_reaction`, `list_account`,
`conversation_read`, `conversation_mute` rows are left in place and filtered out by
`deleted_at` on the join, or wait for cascade when a row is finally removed. Under shards the
sweep becomes a job that must reach those tables on other shards — the five it already names
are affine and stay put.

### 3.2 Every FK that crosses the shard key

"Crosses" means: child row's owner is account A, parent row's owner is account B (or a
status authored by B). Exhaustive over the migrations I could read; §3.3 lists the
deliberate non-FKs, and §3.4 the unique constraints that fail the same way.

| # | child.column → parent | cite | verdict | why |
|---|---|---|---|---|
| 1 | `follow.account_id → account` | `0001_init.sql:42` | **STAYS** | Follower owns the row. |
| 2 | `follow.target_account_id → account` | `0001_init.sql:43` | **SOFT** | Target on another shard; edge must also be readable from its side. |
| 3 | `status.account_id → account` | `0001_init.sql:56` | **STAYS** | Author owns the row. |
| 4 | `status.in_reply_to_id → status` | `0001_init.sql:63` | **SOFT** | Parent post is usually another author's; thread walking is per-hop. |
| 5 | `status.in_reply_to_account_id → account` | `0001_init.sql:64` | **SOFT** | Denormalised reply target; keep — it makes "reply to you" cheap. |
| 6 | `status.reblog_of_id → status` | `0001_init.sql:65` | **SOFT** | Foreign post; `reblog_status` takes `FOR UPDATE` on it today. |
| 7 | `status_mention.status_id → status` | `0001_init.sql:87` | **STAYS** | Written with the post on the author's shard. |
| 8 | `status_mention.account_id → account` | `0001_init.sql:88` | **SOFT + projection** | The mentioned account's read needs rows on *their* shard; dual-write or fan out. |
| 9 | `status_tag.status_id → status` | `0001_init.sql:93` | **STAYS** | Written with the post. |
| 10 | `media_attachment.account_id → account` | `0001_init.sql:102` | **STAYS** | Author owns it. |
| 11 | `media_attachment.status_id → status` | `0001_init.sql:103` | **STAYS** | Author's own post. |
| 12 | `favourite.account_id → account` | `0001_init.sql:119` | **STAYS** | Favouriter owns the row. |
| 13 | `favourite.status_id → status` | `0001_init.sql:120` | **SOFT** | Foreign post; its counter is on another shard (§4.6). |
| 14 | `bookmark.account_id → account` | `0001_init.sql:127` | **STAYS** | Reader owns it. |
| 15 | `bookmark.status_id → status` | `0001_init.sql:128` | **SOFT** | Foreign post; the list becomes a fetch-by-id gather. |
| 16 | `timeline_entry.account_id → account` | `0001_init.sql:136` | **STAYS** | Reader owns the row — why the home timeline is cheap. |
| 17 | `timeline_entry.status_id → status` | `0001_init.sql:137` | **SOFT / MOVE** | Foreign post; store `author_id` on the entry or gather per shard. |
| 18 | `notification.account_id → account` | `0001_init.sql:147` | **STAYS** | Recipient owns the row. |
| 19 | `notification.from_account_id → account` | `0001_init.sql:149` | **SOFT / MOVE** | Actor on another shard; store handle/domain at write time. |
| 20 | `notification.status_id → status` | `0001_init.sql:150` | **SOFT** | Foreign post. |
| 21 | `oauth_token.app_id → oauth_app` | `0001_init.sql:172` | **STAYS** | Parent replicated. |
| 22 | `oauth_token.account_id → account` | `0001_init.sql:173` | **STAYS** | Owner. |
| 23 | `status_reaction.status_id → status` | `0004:17` | **SOFT** | Foreign post. |
| 24 | `status_reaction.account_id → account` | `0004:18` | **STAYS** | Reactor owns it. |
| 25 | `list_account.list_id → list` | `0018:15` | **STAYS** | List is the owner's. |
| 26 | `list_account.account_id → account` | `0018:16` | **SOFT** | Member on another shard; list read is a fan-out. |
| 27 | `account_relation.account_id → account` | `0019:2` | **STAYS** | Owner. |
| 28 | `account_relation.target_account_id → account` | `0019:3` | **SOFT + mirror** | "I block them" is local; "they block me" is another shard. |
| 29 | `announcement_read.account_id → account` | `0020:16` | **STAYS** | Reader owns it. |
| 30 | `announcement_read.announcement_id → announcement` | `0020:17` | **STAYS** | Parent replicated. |
| 31 | `conversation_read.account_id → account` | `0023:15` | **STAYS** | Reader owns it. |
| 32 | `conversation_read.root_id → status` | `0023:16` | **SOFT** | Root may be a foreign post. |
| 33 | `conversation_mute.account_id → account` | `0024:25` | **STAYS** | Reader owns it. |
| 34 | `conversation_mute.root_id → status` | `0024:26` | **SOFT** | Root may be a foreign post. |
| 35 | `poll.status_id → status` | `0033:11` | **STAYS** | Author's post. |
| 36 | `poll_vote.poll_id → poll` | `0033:24` | **SOFT** | Poll lives with the author. |
| 37 | `poll_vote.account_id → account` | `0033:25` | **STAYS** | Voter owns the row. |
| 38 | `moderation_strike.account_id → account` | `0044:15` | **STAYS** | Affine by decision (§2.1). |
| 39 | `moderation_strike.rule_id → moderation_rule` | `0044:18` | **STAYS** | Parent replicated. |
| 40 | `status_edit.status_id → status` | `0052:9` | **STAYS** | Same shard as the post. |
| 41 | `drive_folder (account_id, parent_id) → drive_folder` | `0051`, `drive_folder_parent_fk` | **STAYS** | Composite key includes the owner — the model to copy. |
| 42 | `drive_object (account_id, folder_id) → drive_folder` | `0051`, `drive_object_folder_fk` | **STAYS** | Same. |
| 43 | `federation_delivery.account_id → account` | `0028:10` | **STAYS** | Affine by decision. |
| 44 | `report.account_id → account` (reporter) | `0017:8` | **SOFT** | Global queue; nullable since `0036`. |
| 45 | `report.target_account_id → account` | `0017:9` | **SOFT** | Subject on a shard. |
| 46 | `report.assigned_account_id → account` | `0026:5` | **SOFT** | Staff account. |
| 47 | `report.action_taken_by_account_id → account` | `0026:6` | **SOFT** | Staff account. |
| 48 | `audit_log.actor_id → account` | `0017:25` | **SOFT** | Global table, shard account. |
| 49 | `admin_alert.account_id → account` | `0011:11` | **SOFT** | Global table, shard account. |
| 50 | `admin_alert.acknowledged_by → account` | `0011:15` | **SOFT** | Staff account. |
| 51 | `appeal.account_id → account` | `0039:10` | **SOFT** | Global queue, shard subject. |
| 52 | `appeal.decided_by → account` | `0039:17` | **SOFT** | Staff account. |
| 53 | `moderator_note.account_id → account` | `0026:17` | **SOFT** | Global record, shard subject. |
| 54 | `moderator_note.author_id → account` | `0026:18` | **SOFT** | Staff account. |
| 55 | `scan_flag.scan_id → scan` | `0027:84` | **STAYS** | Both global. |
| 56 | `scan_flag.status_id → status` | `0027:85` | **SOFT** | Three-way: scan global, status on a shard. |
| 57 | `scan_flag.account_id → account` | `0027:86` | **SOFT** | Shard subject. |
| 58 | `scan_flag.resolved_by → account` | `0027:94` | **SOFT** | Staff account. |
| 59 | `domain_pause.created_by → account` | `0045:17` | **SOFT** | Global policy row, staff account. |
| 60 | `escalation_policy.updated_by → account` | `0044:52` | **SOFT** | Singleton config, staff account. |
| 61 | `report_forward.report_id → report` | `0047` | **STAYS** | Both in the moderation bucket. |
| 62 | `scanner.asset_id → scanner_asset` | `0027:31` | **STAYS** | Both global. |
| 63 | `scanner_rule.scanner_id → scanner` | `0027:45` | **STAYS** | Both global. |
| 64 | `scan.scanner_id → scanner` | `0027:58` | **STAYS** | Both global. |
| 65 | `filter_keyword.filter_id → filter` | `0018:36` | **STAYS** | Same owner. |
| 66 | `account_credential.account_id` (`0003:6`), `auth_session.account_id` (`0003:15`), `oauth_code.account_id` (`0003:27`), `oauth_code.app_id` (`0003:26`) | as cited | **STAYS** | Owner, or replicated parent. |
| 67 | `list.account_id → account` | `0018:4` | **STAYS** | Owner. |
| 68 | `filter.account_id → account` | `0018:23` | **STAYS** | Owner. |
| 69 | `scheduled_status.account_id` (`0024:6`), `featured_tag.account_id` (`0024:18`) | as cited | **STAYS** | Owner. |

Count: **60 foreign keys cross the shard key** (every SOFT / SOFT+MOVE row above), of which
**9 need a mirrored or denormalised copy** to avoid a cross-shard read:
`follow.target_account_id`, `status_mention.account_id`, `account_relation.target_account_id`,
`timeline_entry.status_id`, `notification.from_account_id`, `favourite.status_id`,
`bookmark.status_id`, `conversation_read.root_id`, `conversation_mute.root_id`.

### 3.3 Deliberately absent foreign keys (the pattern already in use)

These already practise the soft reference and are the precedent to point at:

- `job.subject_id` — polymorphic text, no FK (`0001_init.sql:185` block).
- `scan.subject_id` — polymorphic text, no FK (`0027:61`).
- `report.status_ids` — `text[]`, no FK (`0017:10`): a report names posts that may be gone.
- `external_id.local_id` — no FK (`0005`): the row outlives what it points at.
- `media_attachment.stored_object_id` — `uuid`, no FK, rationale written in `0051`.
- `marker.last_read_id` — plain text, no FK (`0023`).

### 3.4 Unique constraints that are global today and become per-shard

| constraint | cite | what breaks |
|---|---|---|
| `account_local_username_idx` | `0001_init.sql:36` | Two shards can mint `@alice`. Needs a replicated handle index. |
| `account_remote_username_idx` | `0001_init.sql:37` | Same per `(domain, username)`; protected only by URI pinning (§1). |
| `account.uri UNIQUE` | `0001_init.sql:19` | One remote actor, one row — depends on deterministic placement. |
| `status.uri UNIQUE` | `0001_init.sql:57` | One remote post, one row. Same dependency. |
| `follow (account_id, target_account_id)` | `0001_init.sql:51` | Per-shard unique suffices only if the edge has one home. |
| `favourite` / `bookmark` PKs | `0001_init.sql:123`, `0001:130` | Fine per-shard (the actor owns the row). |
| `notification_poll_group_idx` | `0037` | Grouping per (account, status); recipient's shard, so fine. |
| `federation_delivery UNIQUE (inbox_url, activity_id)` | `0028:21-22` | Global dedupe claim; per-shard unique lets two shards deliver twice. |
| `external_id UNIQUE (kind, external_id)` | `0005` | Must stay global, or two shards answer the same foreign id. |
| `report_forward.activity_uri` / `report_id` | `0047` | Fine while the moderation bucket is one database. |

---

## 4. Cross-shard operations inventory

### 4.1 Home timeline fan-out — **exists**

`statuses.rs::fan_out_home` (`crates/store/src/statuses.rs:1298-1321`) is one
`INSERT INTO timeline_entry … SELECT $author, $status UNION SELECT f.account_id, … FROM
follow f … WHERE a.followers_count < BIG_ACCOUNT_THRESHOLD ON CONFLICT DO NOTHING`,
executed *inside* the author's post transaction (`create_with_poll`, `statuses.rs:1344-1404`).
Accounts above `BIG_ACCOUNT_THRESHOLD` are merged at read time by lane 2 of `home_page`
(`statuses.rs:721-773`). A Valkey ZSET mirrors it (`crates/api/src/home.rs`), keyed by account,
falling back to `home_page` on a miss ("There is no second implementation").

Shard behaviour: the author writes into readers' rows. Under shards that is one statement per
destination shard and it cannot live in the author's transaction. The comment on
`fan_out_home` ("Fan-out is immediate here because a local follower timeline is a single
indexed insert") is true only while there is one database. `docs/07-decisions.md` D5 already
says fan-out belongs in the worker; the code does the local part inline, which is the gap.

### 4.2 Notifications — **exists, recipient-addressed**

`social.rs::notify` → `notify_with_note` (`social.rs:365-373`, `:382-450`) inserts into `notification` with
`account_id = recipient`, applies `notification_policy` at write time, honours the `filtered`
flag, and skips self-notification. `notifications()` (`social.rs:479-513`) and
`filtered_count` (`social.rs:514`) are recipient-scoped reads. The row belongs to the
recipient; the event belongs to the actor.

Shard behaviour: a cross-shard insert on the actor's request path. Two acceptable answers:
write to the recipient's shard directly (single-row cross-shard write, no transaction beyond
the actor's own), or enqueue through `job`. The favourite path already issues several
statements on the pool rather than one transaction, so it is *already* non-atomic — that
weakness is an asset here.

### 4.3 Follow edges — **exists, but only half-mirrored**

`social.rs::follow` (`social.rs:132+`) takes `lock_account_pair` (`social.rs:95-110`), which
`SELECT id FROM account WHERE id = $1 FOR UPDATE`s both accounts in sorted id order, then
inserts the edge and recomputes both counters (`social.rs:114-132`). Read from both sides:
`follow_target_idx` (`0001_init.sql:52`), the `account_relation` index on `target_account_id`
(`0019`), and `social.rs::relationship` (`social.rs:43-72`) which ORs four directions
(following, followed-by, muting, blocking) per target account.

Shard behaviour: a distributed lock and a distributed transaction today (`FOR UPDATE` on two
accounts on two shards is not a lock you can take). Reads: "who I follow" is local; "who
follows me" is a fan-out; "do they block me" is a fan-out per page (§4.8).

### 4.4 Conversation assembly — **exists, derived on read**

`conversations.rs::page` (`crates/store/src/conversations.rs:23-72`) is a `RECURSIVE` CTE
walking `status.in_reply_to_id` to the root with a depth counter, filtered to
`visibility = 'direct'` plus a `status_mention` EXISTS for the viewer; `participants()`
(`conversations.rs:74-105`) does `DISTINCT ON (account)` over the same thread. The module doc
says there is deliberately no conversation table.

Shard behaviour: a direct thread's posts are authored by different accounts, so they are on
different shards by construction. The recursion becomes one point lookup per hop across the
network (depth is already bounded) and the participants read becomes a merge. Sharding
degrades an already-expensive path rather than breaking it.

### 4.5 `external_id` lookups — **exists, unroutable by account**

`external_ids::resolve` (`crates/store/src/external_ids.rs:13-24`):
`SELECT local_id FROM external_id WHERE kind = $1 AND external_id = $2`. No account column
exists anywhere in the table (`0005`). The one lookup that cannot be routed by the
recommended key, because the caller only has a foreign id.

Shard behaviour: keep it global, or grow it into the directory (`+ shard`). Do **not** solve
this by encoding the shard in local ids (§1).

### 4.6 Counter maintenance — **exists, and is the main casualty**

| counter | how it is maintained | cite |
|---|---|---|
| `account.statuses_count` | `UPDATE account SET statuses_count = … WHERE id = $1` in the author's own transaction | `statuses.rs:1039-1040`, `:1389-1392`; backfill `0054` |
| `status.replies_count` | `UPDATE status SET replies_count = (SELECT count(*) FROM status WHERE in_reply_to_id = $1 …)` | `statuses.rs:1149-1161` |
| `status.reblogs_count` | same, `reblog_of_id` | `statuses.rs:1164-1175`, `:1504-1509` |
| `status.favourites_count` | `UPDATE status SET favourites_count = (SELECT count(*) FROM favourite …)` | `social.rs` favourite/unfavourite |
| `account.followers_count` / `following_count` | recomputed for **both** accounts inside the follow transaction, counting `follow` in both directions | `social.rs:114-132` |

Shard behaviour: `statuses_count` is fine (author's own row). The other four are
read-modify-write across shards, and `followers_count` is worse: the rows it counts
(`follow WHERE target_account_id = me`) are on the *followers'* shards, so it cannot be
computed locally at all. Either the `follow` edge is mirrored onto both shards (each shard
holding the edge from its own perspective) or the count becomes a distributed aggregate.
This decision determines whether counters stay exact.

### 4.7 Admin / report surfaces — **exist, global on purpose**

`stats.rs` (`activity()` `:19`, `reports()` `:51`, `decisions()` `:85`,
`median_time_to_decision()` `:114`), the report queue (`report`, `report_forward`,
`scan_flag`, `appeal`, `moderator_note`), and `audit_log`. Global because staff work one
queue. Sharded, each is a fan-out plus a merge, and `median_time_to_decision()`'s
`percentile_cont` over `DISTINCT ON` per report cannot be merged from per-shard percentiles —
it needs the per-report durations gathered, not the per-shard median.

### 4.8 Relationship decoration on every page — **exists**

`hydrate::Batch` / `EssentialOp::Relationships(viewer, ids)`
(`crates/store/src/hydrate.rs:47-56`): one page is one viewer × N authors. Today one query;
tomorrow one per shard, per page.

---

## 5. What blocks today, ordered by cost

Cost means "how much design has to change", not lines of code.

1. **`Store` is one database, by construction.** `Store { pool: PgPool }`
   (`crates/store/src/lib.rs:68-70`); `pool()` (`lib.rs:107`) with "No new caller may be
   added"; `write_pool()` (`lib.rs:128`) deriving a `max_connections(1)` pool from the *same*
   connect options — "not a tuning knob — it is the single writer"; `migrate()` (`lib.rs:149`)
   and `ready()` (`lib.rs:157`) each assume one `_sqlx_migrations` table. Everything else is
   downstream of this. A shard-aware store needs `HashMap<ShardId, PgPool>` plus a routing
   function, and a per-shard writer actor so `writer.rs:1-30`'s "the actor is the lock" holds.

2. **`follow()` is a two-account distributed transaction.** `social.rs:98-111` (`FOR UPDATE`
   on both accounts) + `social.rs:114-132` (recompute both counters from `follow` rows) +
   insert, in one transaction. On shards that is a lock across databases and a count over
   rows that are not there. Highest-value design work in this document.

3. **Fan-out, delete, reblog and recipient enumeration all write or scan other accounts'
   rows.** `fan_out_home` (`statuses.rs:1298-1321`) and `create_with_poll`
   (`statuses.rs:1344-1404`) commit `timeline_entry` rows for every follower with the post;
   `home_fanout_accounts` (the keyset-paged "accounts this status is materialised into"
   reader, doc comment at `statuses.rs:886`, fn at `statuses.rs:896`) is how the worker enumerates recipients in
   batches; `cleanup_deleted_status` (`statuses.rs:1179-1205`) deletes them for every reader;
   `reblog_status` (`statuses.rs:1420-1470`) takes `FOR UPDATE` on the original and fans out
   again. All of this assumes "the entry and the status commit together" (`lib.rs:1-9`), the
   exact guarantee sharding removes. The fix is a design change, not a query rewrite:
   per-shard batching plus an idempotent projection (`ON CONFLICT DO NOTHING` is already
   there, which helps).

4. **Reads that join across accounts and order by id.** In descending cost:
   - `statuses.rs::home_page` (`:721-773`), the `UNION` of the materialised lane and the
     big-account lane, `ORDER BY id` — a k-way merge where one lane is a live query against
     other accounts' shards.
   - `statuses.rs::public_page` (`:490-518`) and `statuses.rs::tag_page` (`:849-889`) —
     `ORDER BY s.id` over every account; become merges of per-shard pages (correct because
     ULIDs sort by creation time, §1). `tag_page` additionally joins `status_tag` by tag,
     i.e. a global scan of one tag's posts.
   - `statuses.rs::list_page` (`:794-831`) — `JOIN list_account l ON l.account_id =
     s.account_id AND l.list_id = $2`; the members are on other shards.
   - `statuses.rs::profile_rows` (`:633-675`) and `profile_page_by_handle` (`:612-630`) —
     **these are fine**: the `REPEATABLE READ` snapshot spans `account` + `status` for the
     same account, which is the same shard. Worth noting as evidence the pattern works.
   - `discovery.rs::search_accounts` (`crates/store/src/discovery.rs:15-55`) and status
     search (`:56+`) — `ILIKE '%term%'` plus `ORDER BY followers_count DESC`: a fan-out with
     a global sort, multiplying an already sequential scan rather than creating a new cost.

5. **Counters computed from foreign rows** (`statuses.rs:1164-1175`, `:1504-1509`, the
   favourite path, `social.rs:111-131`) — see §4.6.

6. **Global uniqueness that one database currently enforces** — handle indexes
   (`0001_init.sql:36-37`), `status.uri`, `external_id`, `federation_delivery`
   `(inbox_url, activity_id)` (`0028:21-22`). See §3.4.

7. **Conversation assembly** (`conversations.rs:23-72`, `:74-105`) — network-recursive.

8. **`hydrate::Batch::Relationships(viewer, ids)`** (`hydrate.rs:47-56`) — §4.8.

9. **`statuses.rs::by_id` (`:68-74`) and the `uri`-keyed remote writes** — id-addressed, no
   routing key (§1). Needs the directory or a fan-out.

10. **Aggregates over everything** — `stats.rs:19, :51, :85, :114` (§4.7).

11. **Migrations and readiness** — `lib.rs:149` (`sqlx::migrate!`) and `lib.rs:157`
    (`ready()` counting `_sqlx_migrations`) assume one schema. Sharded, a partial rollout
    leaves shards on different schemas; a per-shard readiness count is the minimum, a schema
    handshake before serving is the real requirement.

12. **Account deletion and purge** (`0048_account_deletion.sql` + every `ON DELETE CASCADE`
    in §3.2) — the cascade only reaches the account's own shard. There *is* an explicit sweep
    today, but it is narrower than the cascade: `accounts::purge_due`
    (`crates/store/src/accounts.rs:268`) erases the profile columns of the tombstone and
    deletes from five affine tables (`:304-323`); it names no foreign table, so under shards
    the foreign-row half of purge has to be built, not moved. §3.1.

13. **The `report_forward` trigger on `federation_delivery`** (`0047`: `AFTER INSERT OR
    UPDATE OF state, attempts, last_error … UPDATE report_forward WHERE activity_uri =
    NEW.activity_id`) — a cross-table trigger coupling a delivery queue row to a report row.
    If deliveries move to the actor's shard the trigger fires in the wrong database.

14. **Database-assigned keys.** `status_edit.id` (`0052:8`, identity) is per-shard and
    harmless — ordering is within one `status_id`. `event_log.seq` (`0006:4`, `bigserial`)
    is genuinely global: a shard cannot mint it, so that table stays global while it is a
    hash chain. `appeal.id` (`0039:9`) and `moderation_rule.id` (`0041:13`) are
    `gen_random_uuid()` and never cited by a client, so they are free.
    (`escalation_policy.id boolean DEFAULT true` is a singleton marker, not an identity.)

15. **`job`'s dedupe index** (`0001_init.sql:185` block: unique partial on
    `(kind, subject_id) WHERE finished_at IS NULL`) — a single queue across shards either
    becomes per-shard (dedupe weakens) or stays global (fine, but then the queue is a
    cross-shard write path for everything).

---

## 6. The guard test

**Name:** `crates/store/tests/shard_key.rs`.
**Model:** `crates/api/tests/capabilities.rs` — const tables, `include_str!` of the sources,
and an assertion in **both** directions (a declaration without a code fact fails, and a code
fact without a declaration fails). The capabilities test's own limitation is the model's
limitation: its file lists are hand-maintained string slices, so a new module must be added
by hand. Copy that weakness deliberately — a guard test that silently ignores new files is
worse than none.

### Shape

```rust
// 1. Every table, its bucket, and the column that owns the row (None = global).
struct Table { name: &'static str, bucket: Bucket, owner: Option<&'static str> }

// 2. Every store source file, by hand, so a new file is a deliberate act.
const SOURCES: &[&str] = &[
    include_str!("../src/statuses.rs"),
    include_str!("../src/social.rs"),
    // … one line per file in crates/store/src
];

// 3. Every statement allowed to touch a cross-shard table, with a written reason.
struct Exemption {
    file: &'static str,
    needle: &'static str,   // a substring of the statement, unique in that file
    tables: &'static [&'static str],
    mechanism: Mechanism,   // Merge | Projection | SoftRef | GlobalQueue
    reason: &'static str,   // must be non-empty
}
```

Rules, each its own `#[test]`:

1. `every_cross_shard_statement_is_declared` — for each SQL literal in `SOURCES`, extract
   the tables it names (after `FROM`, `JOIN`, `UPDATE`, `INSERT INTO`, `DELETE FROM`) and
   the columns it predicates on; if two named tables have different owners, the statement
   must match an `Exemption`. Failure message prints the statement.
2. `every_exemption_still_exists` — the opposite direction: each `needle` must still appear
   in its file. A query rewritten into shard-safety must lose its exemption, otherwise the
   list rots into a permission slip.
3. `every_exemption_has_a_reason` — reuse the capabilities idiom that an empty string is not
   an absent field: `reason.is_empty()` fails and `mechanism` must be set, so "keep the queue
   global" is a decision rather than a shrug.
4. `every_store_module_is_in_sources` — compare the `pub mod` list parsed out of
   `lib.rs:12-55` against the file list backing `SOURCES`. This is what stops the test going
   blind when someone adds `crates/store/src/threads.rs`.
5. `every_pool_caller_is_accounted_for` — parse `lib.rs`'s `pool()` doc block (which already
   enumerates the remaining direct-pool holders, `lib.rs:84-104`) and assert that list
   only shrinks against a checked-in baseline, in the spirit of capabilities' `total > 50`
   sanity assertion.

### What it can see

- Every SQL literal that is a literal. This codebase builds SQL as string literals with
  `format!` around const column lists (`STATUS_COLUMNS`, `ACCOUNT_COLUMNS`), so table names
  and predicates are visible in the source text.
- Which tables co-occur in one statement, and which columns are predicates.
- Files added to the store crate, if rule 4 is implemented.

### What it cannot see

- **Transaction boundaries.** `social.rs`'s two-account lock and counter recompute are three
  statements in one transaction; each is individually unremarkable. A statement-level check
  cannot flag them. A separate rule ("no `FOR UPDATE` on `account` in a statement that also
  names another account") catches the worst case only.
- **Cross-shard reads assembled in Rust.** `hydrate::Batch` issues several queries and joins
  them in memory; if the split happens in Rust the SQL looks clean.
- **Queries outside `crates/store`.** `pool()` still has holders in `crates/api/src/*`,
  `crates/media`, `crates/prune` (`lib.rs:84-104`). Rule 5 can only count them.
- **Whether a join is *on the shard key*.** A text scan can see `ON a.id = s.account_id` but
  cannot prove the join is keyed by owner. Heuristic only.
- **Trigger bodies in migrations.** `0047`'s trigger is SQL inside a `.sql` file and would
  need `include_str!` of the migrations plus its own parse rule.
- **Runtime placement.** Nothing here proves a row is where the routing function says it is;
  that needs a separate consistency check, which on one shard would pass trivially.

### How an exception is written down

```rust
Exemption {
    file: "statuses.rs",
    needle: "FROM timeline_entry e JOIN status s ON s.id = e.status_id",
    tables: &["timeline_entry", "status"],
    mechanism: Mechanism::Merge,
    reason: "home page lane 1: entry is the reader's, status is the author's; merged by id \
             cursor. See docs/18-sharding.md §4.1.",
}
```

The `reason` points at the section of this document that argues the mechanism. The test does
not decide whether cross-shard reads are allowed; it decides that each one is *named*,
*justified*, and still *there*.

---

## 7. What I would not do

**Nothing here is a reason to move data onto a second shard.** No data moves until a second
shard exists for a reason — capacity, blast radius, or a maintenance window that one machine
cannot absorb. Until then these are the tempting changes to refuse:

1. **Do not add a `shard` column to tables.** The shard is a pure function of the owner
   account id. A stored shard id is a second source of truth that must be rewritten on every
   rebalance, and it will disagree with the routing function exactly once — during the move,
   when the data is in flight. `0051_cloud_drive.sql` already shows the alternative:
   `PRIMARY KEY (account_id, id)` makes the owner part of the key, so the table can be moved
   by that column alone with no query changes.

2. **Do not build a routing layer or a shard map before there is a second shard.** `Store`
   with one `PgPool` (`lib.rs:68-70`) is what makes "the entry and the status commit
   together" (`lib.rs:1-9`) checkable. A router in front of one database is a distributed
   system with none of the benefits: every query gains an indirection and nothing gains
   capacity. Write the *queries* shard-shaped (single-owner predicates, no cross-account
   joins outside the documented list) and keep one pool until a second one is a real
   deployment.

3. **Do not re-encode ids with a shard prefix.** §1. The paging contract in
   `docs/04-storage.md` (lexicographic order = creation order, `id > cursor`) is used by
   `public_page`, `tag_page`, `account_page`, `profile_rows`, `list_page`, `home_page` and
   `notifications()`. A leading prefix reorders every page by shard; a trailing one weakens
   the within-millisecond monotonicity that makes the cursor strict. Routing is by account,
   so the prefix buys nothing.

4. **Do not drop the foreign keys today.** Every FK marked SOFT in §3.2 is still doing real
   work: it is what keeps counters and cascades honest on one database. The time to drop one
   is the moment the query that would have joined it is rewritten, not before — otherwise the
   schema gets weaker than the code.

5. **Do not reach for declarative partitioning (`PARTITION BY account_id`) as a rehearsal
   for sharding.** It changes index shape, lock behaviour and `ON CONFLICT` handling for zero
   routing benefit, and the queries it forces you to write are not the queries sharding
   forces you to write. Partitioning is a tool for one big table; sharding is a tool for one
   big instance.

6. **Do not chase "one id scheme everywhere".** `0052:8`'s identity is per-shard and only
   ordered within one `status_id`; `0039:9`'s and `0041:13`'s uuids are never cited by a client.
   Converting rows to a new id scheme would invent ids for data clients already hold — the
   argument `0040_instance_rules.sql` makes for keeping rule ids as text.

7. **Do not build cross-shard 2PC.** The `job` table (`0001_init.sql:185`) is already the
   outbox; fan-out, notifications and counters want to become idempotent projections through
   it (`ON CONFLICT DO NOTHING` is already the idiom in `fan_out_home`). Two-phase commit
   buys exactness with availability, and this system already accepts eventual consistency for
   remote delivery.

8. **Do not shard `external_id`, `event_log`, or the moderation queues first.** They are the
   three things that *want* to be global; moving them early converts a small global table
   into a distributed problem while the affine tables — the ones that actually grow — stay
   untouched.

---

## Missing evidence

The first draft listed seven things it could not check. Each was checked against the tree
afterwards; the answers are kept here because three of them changed the analysis above.

- **`0046` and `0049` do not exist.** `crates/store/migrations/` runs 0045 → 0047 → 0048 →
  0050. The roster below is complete: 72 tables, 69 plain `CREATE TABLE` plus 3
  `IF NOT EXISTS`, matching the operator's count. Settled.
- **Purge is an explicit sweep, not cascade.** `accounts::purge_due`
  (`crates/store/src/accounts.rs:268`), called from `crates/prune/src/run.rs:111`, selects due
  tombstones, scrubs the `account` row's profile columns, and deletes from exactly five tables
  (`:304-323`) — `account_credential`, `auth_session`, `oauth_code`, `oauth_token`,
  `media_attachment`. No foreign table is swept, and the `account` row is kept as a tombstone.
  This narrowed §3.1 and §5 item 12. Settled.
- **`status_mention`'s read path: narrowed.** There is no `WHERE account_id = $1` mention
  timeline. The reads are `SELECT account_id FROM status_mention WHERE status_id = $1`
  (`crates/store/src/statuses.rs:105`), a delete by `status_id` (`:119`), and `is_mentioned`'s
  `EXISTS (… WHERE status_id = $1 AND account_id = $2)` (`crates/store/src/statuses.rs:1525`).
  The account-scoped read does exist, but it is viewer-scoped through a status id — which is
  exactly what §3.2 item 8's projection argument assumes. Settled, in the weaker form.
- **`home_fanout_accounts` starts at `crates/store/src/statuses.rs:896`** (doc comment `:886`).
  The earlier name, `home_rows`, was wrong. Settled.
- **`BIG_ACCOUNT_THRESHOLD` is `50_000`** (`crates/core/src/limits.rs:28`), bound at
  `crates/store/src/statuses.rs:780` and `:1320`. Settled.
- **`pool()`'s doc list is a module-family list, not a call-site list** (`lib.rs:84-104`): it
  names `crates/api/src` module by module but `crates/media/src/serve.rs` and
  `crates/prune/src/run.rs` as whole crates. §6 rule 5 can therefore assert that the list does
  not grow, not that it enumerates every call. Partly settled — the rule still parses prose.
- **`0047`'s trigger is as described**: `CREATE FUNCTION report_forward_sync()`
  (`crates/store/migrations/0047_forwarded_reports.sql:35`), `UPDATE report_forward` (`:37`),
  `CREATE TRIGGER federation_delivery_report_forward` (`:50`), `FOR EACH ROW EXECUTE FUNCTION
  report_forward_sync()` (`:52`). Settled.

## Contradictions

All three were re-checked against the tree and stand.

- **The brief lists "remote moderation" under cross-shard-by-design; I classify it GLOBAL.**
  `remote_moderation` (`0035`) and `remote_block` (`0029`) are keyed by remote `actor_uri` and
  name no local account, so there is nothing to route by account. The *effects* are
  cross-shard (a suspension hides rows on every shard); the *rows* are instance policy.
  Filed global, with the reasoning written down rather than left implicit.
- **"Exactly one database-assigned key in the whole schema."** I found four, with citations:
  `status_edit.id` (`0052:8`, identity), `event_log.seq` (`0006:4`, `bigserial`),
  `appeal.id` (`0039:9`, `gen_random_uuid()`), `moderation_rule.id` (`0041:13`,
  `gen_random_uuid()`), plus `escalation_policy.id boolean DEFAULT true` (`0044`) which is a
  singleton marker rather than an identity. The *conclusion* stands — the schema is
  shard-friendly — but the premise needs the caveat, because `event_log.seq` is a genuinely
  global sequence that no shard can mint, and `status_edit.id` is a per-shard identity, not a
  ULID. This is the one place where a flat "everything else is a ULID in a text column" would
  put a false statement into the brief.
- **`docs/07-decisions.md` D5 says fan-out belongs in the worker; `statuses.rs:1298-1321`
  does the local fan-out inline in the request's transaction.** Both are deliberate (the
  comment explains the local case is one indexed insert), but under sharding the inline part
  is the expensive part. Recorded, not resolved: whether a post's transaction should wait for
  its followers' shards is a product decision.

---

## Verification

Every `file:line` citation in this document was opened against the tree at the commit this
landed on — in batches, with a script that extracted the citations and printed the cited lines:
264 citation occurrences over 197 distinct cites.

**56 of the 197 distinct cites were wrong** (28%, more than one in five) and are corrected here.
The first draft's citations were plentiful and individually unreliable, which is worse than
being sparse, because a reader will trust them. What was wrong:

- **Off by one line, in the §2 roster.** 14 rows pointed at a column or a closing paren instead
  of the `CREATE TABLE` line (`filter` `0018:22` → `0018:21`, `oauth_code` `0003:20` → `0003:24`,
  `instance_rule` `0024:20` → `0024:31`, and eleven more). Harmless to the argument; fixed.
- **Off by a block** — the largest corrections:
  - `public_page` cited as `statuses.rs:~405-430`; the function is `crates/store/src/statuses.rs:490-518`.
  - `instance_rule` cited as `0024:20`; it is created at `0024:31`.
  - `home_rows` at `statuses.rs:885` does not exist — the function is `home_fanout_accounts` at
    `crates/store/src/statuses.rs:896` (doc comment `:886`).
  - `stats.rs` aggregates cited at `:43, :61, :74, :87`; they are at `:19, :51, :85, :114`.
  - `Store { pool }` cited as `lib.rs:56-59`; it is `lib.rs:68-70`, `pool()` is `:107` not `:106`,
    `write_pool()` is `:128`, `migrate()` `:149`, `ready()` `:157`.
- **Migration cited, line missing** — `escalation_policy.updated_by` (`0044` → `0044:52`),
  `moderation_rule.id` (`0041` → `0041:13`), `appeal.id` (`0039` → `0039:9`).
- **Names that did not match the code** — `social.rs::notify` is `notify_with_note`
  (`crates/store/src/social.rs:365-373`, `:382-450`); `home_rows` is `home_fanout_accounts`.
- **One wrong cross-reference** — the guard-test example pointed at `docs/17-sharding.md`; this
  document is `docs/18-sharding.md`.

Checked and found **correct** (no edit): §3.2's FK table apart from four rows; §3.4's
`UNIQUE`/`PRIMARY KEY` list apart from five entries; `0047`'s trigger function and trigger
(`:35`, `:37`, `:50`, `:52`); `0028:21-22`'s `UNIQUE (inbox_url, activity_id)`; the username
indexes at `0001_init.sql:36-37`; the `invalidate.rs:1-24` payload; `hydrate.rs:47-56`;
`lib.rs:12-55`'s `pub mod` list; `writer.rs:1-30`; `0033:9-11` and `:23-25`; `0039:8-9`;
`0052:7-9`; `0017:6-10`; `0006:4`; and all 22 migrations cited by number alone — every file
exists.

Not checked: the analysis itself. The classification, the verdicts in §3.2, and the blocker
ordering were not re-derived; only the citations that support them.
