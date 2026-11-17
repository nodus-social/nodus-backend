-- Moderation tooling: a report becomes work someone owns and closes, an account
-- carries a private record of why, and policy covers registrations as well as
-- federation.
ALTER TABLE report
    ADD COLUMN assigned_account_id text REFERENCES account (id) ON DELETE SET NULL,
    ADD COLUMN action_taken_by_account_id text REFERENCES account (id) ON DELETE SET NULL,
    ADD COLUMN action_taken_at timestamptz,
    ADD COLUMN rule_ids text[] NOT NULL DEFAULT '{}',
    ADD COLUMN action_taken_note text NOT NULL DEFAULT '';

CREATE INDEX report_assigned_idx ON report (assigned_account_id)
    WHERE assigned_account_id IS NOT NULL;
CREATE INDEX report_reporter_idx ON report (account_id, created_at DESC);

CREATE TABLE moderator_note (
    id         text PRIMARY KEY,
    account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    author_id  text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    body       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX moderator_note_account_idx ON moderator_note (account_id, created_at DESC);

CREATE TABLE warning_preset (
    id         text PRIMARY KEY,
    title      text NOT NULL,
    text       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- A registration decision by email domain: allow_registration=false blocks sign-up,
-- true exempts a domain from a broader block further up the domain tree.
CREATE TABLE email_domain_block (
    id                 text PRIMARY KEY,
    domain             citext NOT NULL UNIQUE,
    allow_registration boolean NOT NULL DEFAULT false,
    created_at         timestamptz NOT NULL DEFAULT now()
);
