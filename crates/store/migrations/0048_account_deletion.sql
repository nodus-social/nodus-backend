-- Leaving is a request, not a wipe: a deleted account keeps its row and its URI as a
-- tombstone so a stale Follow or Undo naming it cannot mint a live account in its place.
-- The row stays hidden by `deleted_at`, and the purge erases what the profile held once
-- the grace period named by `purge_at` has passed.
ALTER TABLE account ADD COLUMN deleted_at timestamptz;
ALTER TABLE account ADD COLUMN purge_at timestamptz;

-- The purge worker asks one question every hour: which tombstones are due?
CREATE INDEX account_purge_idx ON account (purge_at)
    WHERE deleted_at IS NOT NULL AND purge_at IS NOT NULL;
