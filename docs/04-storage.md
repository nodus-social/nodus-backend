# 04 — Storage

Status: draft · Last revised: 2026-11-07

Postgres owns everything except media blobs. Timelines are materialised in a table,
not computed at read time, because a home timeline is read far more often than it is
written and must page deterministically with `max_id`.

## Ids

26-character Crockford base32 ULIDs, lowercase, generated in-process with a
monotonic component inside the same millisecond.

- **Lexicographic order equals creation order**, so `id > $cursor ORDER BY id` is a
  correct `since_id` query without a second index.
- **No autoincrement**, so ids are mintable by any replica and by the worker.
- **Opaque to clients**; nothing outside `crates/core/src/id.rs` parses them.

Remote objects keep their own URI as the foreign key (`status.uri`, unique), because
a remote status must be addressable by the id its origin gave it. Local statuses have
`uri NULL` and are addressed by our id.

## Tables

```text
account(id, username, domain NULL, display_name, note, avatar_ref, header_ref,
        fields jsonb, locked, bot, created_at, suspended_at, silenced_at,
        last_status_at, followers_count, following_count, statuses_count,
        private_key_ref, public_key_pem, inbox_url, shared_inbox_url, uri)
follow(id, account_id, target_account_id, uri, created_at, reblogs, notify)
status(id, account_id, uri NULL, content, content_html, spoiler_text, visibility,
       sensitive, in_reply_to_id, in_reply_to_account_id, reblog_of_id NULL,
       edited_at, created_at, local, deleted_at, language,
       favourites_count, reblogs_count, replies_count)
status_mention(status_id, account_id)
status_tag(status_id, tag)
media_attachment(id, status_id NULL, account_id, digest, content_type, size,
                 width, height, blurhash, description, meta jsonb, created_at)
timeline_entry(account_id, status_id, kind, created_at, PRIMARY KEY (account_id, status_id, kind))
favourite(account_id, status_id, created_at, uri NULL, PRIMARY KEY (account_id, status_id))
bookmark(account_id, status_id, created_at, PRIMARY KEY (account_id, status_id))
notification(id, account_id, kind, from_account_id, status_id, created_at, seen_at)
oauth_app(id, client_id, client_secret_hash, redirect_uris text[], scopes, name, website)
oauth_token(id, app_id, account_id, token_hash, scopes, created_at, revoked_at, last_used_at)
session / invite / report / instance_block / account_domain_block
job(id, kind, priority, payload jsonb, subject_id, attempts, earliest_at,
    locked_by, locked_until, last_error, created_at, finished_at)
```

`timeline_entry.kind` is `home` or `list`; `public` and `tag` timelines are queries
over `status` (they are global and cannot be materialised per user), with the
`(visibility, created_at DESC)` index doing the work.

## Fan-out: the big-account problem

Fan-out-on-write makes every post a `followers_count`-row insert. At 100 000
followers that is a 100 000-row write in a worker, and the status is invisible to
most followers for minutes.

We therefore use **two lanes**:

| Follower count | Lane | Mechanism |
| --- | --- | --- |
| < 50 000 | materialised | worker inserts `timeline_entry(home)` for each follower in batches of 5 000 |
| ≥ 50 000 | merged at read | no fan-out; `GET /timelines/home` unions the materialised slice with `status WHERE account_id IN (followed big accounts) AND id < cursor` |

The threshold is `BIG_ACCOUNT_THRESHOLD = 50_000` in `crates/core`, one constant for
producer and reader. A status that crosses the threshold keeps its already-written
entries; the reader's union dedupes by `status_id`, so a transition never shows a
post twice or drops it.

## Deletion

`DELETE /api/v1/statuses/:id` sets `deleted_at`, deletes `timeline_entry` rows for
that status in the same transaction, and enqueues `deliver(Delete)` for remote
followers. Rows are kept (tombstoned) for 30 days so a late `Announce` or reply can
be rejected instead of resurrecting content the author deleted. `prune` removes them.

## Media

Blobs are content-addressed: `sha256(digest)` is the storage key, so the same upload
twice costs one object. Storage is an object store (S3-compatible) with a local
filesystem backend for development, behind `trait BlobStore`. Variants are produced by
`media_process`, not in the request: upload answers `202` with a `media_attachment`
whose `url` is null until the worker finishes, exactly as Mastodon's async flow does.

## Migrations

`sqlx` migrations, forward-only, one directory, numbered. Every migration runs inside
a transaction and must be additive within a release (add column, backfill, then a
later release drops the old one), because the rollout runs migrations before the new
pods start and a worker from the previous release keeps running during it.
