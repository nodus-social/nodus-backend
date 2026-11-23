-- What an account wants done with each kind of notification.
--
-- A row exists only for a kind the reader has overridden. A missing row means the default
-- `accept` for that kind, so a new account needs no backfill and a kind added later reads
-- as accepted until someone writes a row. One row per (account, kind) rather than one wide
-- row per account: a partial update touches only the kinds it names.
CREATE TABLE notification_policy (
    account_id text        NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    kind       text        NOT NULL,
    policy     text        NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, kind),
    CONSTRAINT notification_policy_kind_allowed CHECK (
        kind IN (
            'mention', 'favourite', 'reblog', 'follow',
            'follow_request', 'report', 'pending_request', 'status'
        )
    ),
    CONSTRAINT notification_policy_policy_allowed CHECK (
        policy IN ('accept', 'filter', 'drop')
    )
);
