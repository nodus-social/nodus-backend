-- A `filter` policy stores the notification but keeps it out of the ordinary list; a
-- `drop` policy never writes the row at all. The flag is the only trace a filtered row
-- leaves, so the default list can exclude it while `?filtered=true` and a separate count
-- can still find it.
ALTER TABLE notification
    ADD COLUMN filtered boolean NOT NULL DEFAULT false;

-- The ordinary list scans the existing (account_id, id DESC) index and discards filtered
-- rows; the filtered list is the rarer query, so it gets its own partial index.
CREATE INDEX notification_filtered_idx
    ON notification (account_id, id DESC)
    WHERE filtered;
