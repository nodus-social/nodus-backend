-- Memory.
--
-- A moderator decides each case by hand, so an account that keeps breaking the same rule is
-- silenced once, unsilenced, and silenced again with nothing recording that this is the third
-- time. Every silence, suspension or warning now leaves a strike: the account, the rule when a
-- rule decided, the action, the moderator's words, and the moment after which the strike no
-- longer counts.
--
-- The window is not on the row. A strike keeps the expiry it was written with, so widening the
-- policy later does not resurrect history that had already aged out — the row says when it was
-- live, the policy only says how many of the live ones matter.

CREATE TABLE moderation_strike (
    id         text PRIMARY KEY,
    account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    -- A rule can be deleted; the strike that cites it stays, with the citation gone. The name
    -- it was caught by is kept on the audit row and on the person's notification.
    rule_id    uuid REFERENCES moderation_rule (id) ON DELETE SET NULL,
    action     text NOT NULL CHECK (action IN ('warn', 'flag', 'silence', 'suspend')),
    reason     text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    -- When this strike stops counting. Always set: a strike with no end would escalate
    -- forever, which is the behaviour this table exists to replace.
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > created_at)
);

-- Counting an account's live strikes is the write path: it happens inside every silence.
CREATE INDEX moderation_strike_account_idx
    ON moderation_strike (account_id, expires_at DESC);

-- The sweep that prunes aged-out rows reads by expiry alone.
CREATE INDEX moderation_strike_expiry_idx ON moderation_strike (expires_at);

-- One row, edited by an administrator, never created by a request: the instance that has
-- never opened the policy still has one, with the defaults below. `id boolean` is what makes
-- "there is exactly one policy" a constraint rather than a convention.
CREATE TABLE escalation_policy (
    id          boolean PRIMARY KEY DEFAULT true CHECK (id),
    -- The name the audit trail cites, so "which policy did this" has an answer even when an
    -- operator later edits the steps.
    name        text NOT NULL DEFAULT 'default' CHECK (btrim(name) <> ''),
    enabled     boolean NOT NULL DEFAULT true,
    -- How long a strike stays live. What was written on a strike wins; this is what new ones
    -- are given.
    window_days integer NOT NULL DEFAULT 90 CHECK (window_days BETWEEN 1 AND 3650),
    -- `[{"strikes": 3, "action": "silence", "duration_days": 7}, ...]`, ascending. The shape is
    -- validated on write in `store::escalation` as well as read here, because a policy that
    -- cannot be understood must not be applied.
    steps       jsonb NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text REFERENCES account (id) ON DELETE SET NULL
);

-- The defaults an untouched instance runs on: a first offence never escalates, a third
-- silence inside ninety days becomes a week-long silence, a fifth is a suspension. Stated in
-- the row rather than in the reader so an operator who has never opened the page can still be
-- told what the instance does.
INSERT INTO escalation_policy (id, enabled, window_days, steps)
VALUES (
    true,
    true,
    90,
    '[{"strikes": 3, "action": "silence", "duration_days": 7},
      {"strikes": 5, "action": "suspend"}]'::jsonb
);
