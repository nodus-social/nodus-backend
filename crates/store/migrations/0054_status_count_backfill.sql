-- `account.statuses_count` is a stored counter. `statuses::create` and
-- `statuses::upsert_remote` increment it and the retract paths decrement it, but rows
-- written before a4e0281 were never counted: an upgraded instance reports 0 for a remote
-- author whose posts it already stores. This recomputes the column once.
--
-- Which rows count is exactly the predicate `statuses::delete_owned` uses to decide
-- whether a tombstone subtracts one. A row counts when it is live and is not a plain
-- boost:
--
--     deleted_at IS NULL
--     AND (reblog_of_id IS NULL OR content_source IS NOT NULL OR content <> '')
--
-- The three disjuncts are not redundant:
--   * `reblog_of_id IS NULL` — an ordinary post;
--   * `content_source IS NOT NULL` — a Misskey note or renote, which is written through
--     `statuses::create` and therefore counts even when it reblogs another status;
--   * `content <> ''` — a local post carrying text, for the same reason.
-- A Mastodon-style boost (`statuses::reblog`) has an empty body, no source and a
-- `reblog_of_id`, so it never increments and must not be counted here.
--
-- The same set is what `upsert_remote` increments (a remote row is always a note with no
-- `reblog_of_id`) and what `delete_remote` / `delete_remote_actor` subtract (non-boosts
-- only). If this predicate and those paths drift apart, the backfill becomes wrong the
-- first time a post is deleted.
--
-- `last_status_at` is a high-water mark, not `max(created_at)` of the live rows: no
-- retract path lowers it and `upsert_remote` writes `GREATEST(last_status_at, created_at)`.
-- Recomputing it from live rows would lower it after a delete, so this migration only
-- fills a NULL from the newest counted row and otherwise leaves it alone.
--
-- Cost: one read of every live status through `status_account_idx`, plus one row write
-- per account whose counter disagrees. It takes no lock on `status` (MVCC read) and locks
-- only the account rows it changes. Batching inside this transaction would not shorten
-- the lock window, so the statement stays single and atomic. On an instance with a very
-- large status table this is a one-time startup cost proportional to that table.
--
-- The SET takes an absolute value from a fresh aggregate, so running it again is a no-op:
-- the predicate recomputes the same number and the `<>` guard excludes unchanged rows.
UPDATE account AS a
   SET statuses_count = c.n,
       last_status_at = COALESCE(a.last_status_at, c.last_at)
  FROM account AS src,
       LATERAL (
           SELECT count(*)::bigint AS n,
                  max(s.created_at) AS last_at
             FROM status AS s
            WHERE s.account_id = src.id
              AND s.deleted_at IS NULL
              AND (s.reblog_of_id IS NULL
                   OR s.content_source IS NOT NULL
                   OR s.content <> '')
       ) AS c
 WHERE a.id = src.id
   AND (a.statuses_count <> c.n
        OR (a.last_status_at IS NULL AND c.last_at IS NOT NULL));
