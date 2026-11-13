-- Moderation is instance policy about people and domains, separate from the
-- protocol surfaces that expose it.
ALTER TABLE account
    ADD COLUMN approved boolean NOT NULL DEFAULT true;

CREATE TABLE report (
    id                text PRIMARY KEY,
    account_id        text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    target_account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    status_ids        text[] NOT NULL DEFAULT '{}',
    category          text NOT NULL DEFAULT 'other',
    comment           text NOT NULL DEFAULT '',
    state             text NOT NULL DEFAULT 'open'
        CHECK (state IN ('open', 'resolved')),
    action_taken      boolean NOT NULL DEFAULT false,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX report_state_idx ON report (state, created_at DESC);
CREATE INDEX report_target_idx ON report (target_account_id, created_at DESC);

CREATE TABLE audit_log (
    id          text PRIMARY KEY,
    actor_id    text REFERENCES account (id) ON DELETE SET NULL,
    action      text NOT NULL,
    target_type text NOT NULL,
    target_id   text,
    detail      jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_created_idx ON audit_log (created_at DESC);

CREATE TABLE instance_block (
    id             text PRIMARY KEY,
    domain         citext NOT NULL UNIQUE,
    severity       text NOT NULL DEFAULT 'suspend'
        CHECK (severity IN ('silence', 'suspend')),
    reject_media   boolean NOT NULL DEFAULT false,
    reject_reports boolean NOT NULL DEFAULT false,
    obfuscate      boolean NOT NULL DEFAULT false,
    public_comment text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE instance_allow (
    id         text PRIMARY KEY,
    domain     citext NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);
