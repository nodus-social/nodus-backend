-- A poll with twenty voters must read as one line, not twenty: the notification is the
-- event "someone voted on your poll", and the line names the latest voter. `group_count`
-- carries the tally behind that name; every other kind keeps the default of one.
ALTER TABLE notification
    ADD COLUMN group_count integer NOT NULL DEFAULT 1
        CONSTRAINT notification_group_count_positive CHECK (group_count > 0);

-- The aggregation key. A partial index keeps one poll line per (reader, poll), while
-- favourite/mention/status rows stay one per event as before.
CREATE UNIQUE INDEX notification_poll_group_idx
    ON notification (account_id, status_id)
    WHERE kind = 'poll';
