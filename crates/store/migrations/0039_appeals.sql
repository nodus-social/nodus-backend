-- A restriction is a decision, and a decision can be wrong. An appeal is the account
-- asking a person to look again; without one, a suspended or silenced account has no way
-- to speak and a moderator has no record of what was asked or answered.
--
-- `action` is the restriction being appealed, not the action the moderator eventually
-- takes: the row has to say what the person was under when they wrote it, because the
-- restriction may have changed by the time somebody reads the queue.
CREATE TABLE appeal (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id    text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    action        text NOT NULL
        CONSTRAINT appeal_action_check CHECK (action IN ('suspend', 'silence', 'reject')),
    reason        text NOT NULL,
    status        text NOT NULL DEFAULT 'pending'
        CONSTRAINT appeal_status_check CHECK (status IN ('pending', 'accepted', 'rejected')),
    decision_note text,
    decided_by    text REFERENCES account (id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    decided_at    timestamptz
);

-- One open appeal per account. A second attempt while the first is pending is refused
-- and points at the open row, but the index is what makes two simultaneous requests
-- agree on which one that is.
CREATE UNIQUE INDEX appeal_one_pending_idx ON appeal (account_id) WHERE status = 'pending';

-- The console reads the queue newest-first within a state, and the person's own page
-- reads newest-first without a state filter.
CREATE INDEX appeal_status_idx ON appeal (status, created_at DESC);
CREATE INDEX appeal_account_idx ON appeal (account_id, created_at DESC);

-- A decided appeal reaches the owner through the notification machinery like any other
-- event. `note` is the decision note the person is told; every other kind leaves it null.
ALTER TABLE notification ADD COLUMN note text;

ALTER TABLE notification DROP CONSTRAINT notification_kind_valid;
ALTER TABLE notification ADD CONSTRAINT notification_kind_valid
    CHECK (kind IN ('follow', 'favourite', 'reblog', 'mention', 'poll', 'status', 'appeal'));
