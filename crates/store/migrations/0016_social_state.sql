-- Follow requests need a state distinct from an accepted follow. A locked account
-- keeps the row pending until it approves, so every relationship query reads one table.

ALTER TABLE follow
    ADD COLUMN state text NOT NULL DEFAULT 'accepted'
    CHECK (state IN ('pending', 'accepted'));

CREATE INDEX follow_account_state_idx ON follow (account_id, state);
CREATE INDEX follow_target_state_idx ON follow (target_account_id, state);

-- Feeds and profile pages sort by the last accepted follow activity.
CREATE INDEX follow_created_idx ON follow (created_at DESC);
