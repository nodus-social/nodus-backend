CREATE TABLE IF NOT EXISTS account_relation (
    account_id text NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    target_account_id text NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('block', 'mute')),
    notifications boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, target_account_id, kind)
);

CREATE INDEX IF NOT EXISTS account_relation_target_idx
    ON account_relation (target_account_id, kind);
