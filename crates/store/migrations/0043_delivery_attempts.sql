-- What happened to every outbound delivery.
--
-- The queue already recorded that something was owed and when to try again, but a delivery
-- that failed looked exactly like one that had never been tried, and a peer that answered
-- 401 looked the same as one that was simply down. A moderator could not tell whether a
-- follow went out or whether a peer rejected our signature, so the row now carries its own
-- state, the host it is going to, the kind of activity, and what the last attempt answered.
--
-- `state` is the lifecycle of one delivery: pending (written down, never tried or requeued),
-- failed (last attempt failed, another is scheduled), gave_up (no further automatic attempt),
-- delivered (2xx). Rows are still kept after delivery so the history is readable.

ALTER TABLE federation_delivery
    ADD COLUMN host text NOT NULL DEFAULT '',
    ADD COLUMN activity_kind text,
    ADD COLUMN state text NOT NULL DEFAULT 'pending',
    ADD COLUMN last_status_code integer;

-- Existing rows predate the state column; their `delivered_at` is the only evidence of what
-- happened, so it decides between delivered and pending. `host` is derived here with the
-- same shape `blocks::host_of` parses, so the admin filter works for history too.
UPDATE federation_delivery
   SET state = CASE WHEN delivered_at IS NULL THEN 'pending' ELSE 'delivered' END,
       host = COALESCE(
           substring(inbox_url FROM '^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:]+)'), ''),
       activity_kind = activity ->> 'type';

ALTER TABLE federation_delivery
    ADD CONSTRAINT federation_delivery_state_valid
    CHECK (state IN ('pending', 'failed', 'gave_up', 'delivered'));

-- The admin list is newest first, filtered by state and host; the worker reads due rows by
-- time. Both get an index of their own rather than sharing one that fits neither.
CREATE INDEX federation_delivery_list_idx
    ON federation_delivery (state, host, created_at DESC);

CREATE INDEX federation_delivery_due_state_idx
    ON federation_delivery (next_attempt_at)
    WHERE state IN ('pending', 'failed');
