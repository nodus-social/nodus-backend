-- Web Push delivery queue: one row per notification that may reach a browser.
--
-- The notification write path inserts this row after the notification itself commits,
-- exactly as `email_outbox` separates a request from an SMTP round trip. The sender is a
-- loop in the API process, so a slow or dead push service can only delay this table, never
-- the favourite or mention that caused the row.
--
-- `attempts` and `last_error` are for an operator looking at a queue that is not draining.
-- A row is sent at most once per process lifetime: delivery is at-least-once after a crash
-- between the HTTP call and `sent_at`, which a notification client tolerates better than a
-- dropped event.
CREATE TABLE push_outbox (
    id              text        PRIMARY KEY,
    account_id      text        NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    notification_id text        NOT NULL REFERENCES notification (id) ON DELETE CASCADE,
    kind            text        NOT NULL,
    attempts        integer     NOT NULL DEFAULT 0,
    last_error      text,
    sent_at         timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT push_outbox_attempts_nonnegative CHECK (attempts >= 0)
);

-- The sender's only query is "what is still owed", oldest first.
CREATE INDEX push_outbox_pending_idx ON push_outbox (created_at) WHERE sent_at IS NULL;
