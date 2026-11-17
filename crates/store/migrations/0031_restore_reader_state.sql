-- Reader state, remote profile pictures and scheduled posts.
--
-- 0028 dropped these objects because, on the branch it was written for, nothing read them.
-- This branch does: markers, conversations, featured tags, instance rules and scheduled
-- posts back the reader-facing endpoints, and the two `account` columns carry the pictures
-- a remote actor advertised. The definitions are the ones 0023, 0024 and 0025 introduced,
-- restated after the drop rather than rewritten, so the shape stays the one already
-- deployed and the versions those migrations recorded in `_sqlx_migrations` stay valid.

CREATE TABLE IF NOT EXISTS marker (
    account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    timeline text NOT NULL,
    last_read_id text NOT NULL,
    version integer NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, timeline)
);

CREATE TABLE IF NOT EXISTS conversation_read (
    account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    root_id text NOT NULL REFERENCES status (id) ON DELETE CASCADE,
    last_read_id text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, root_id)
);

CREATE TABLE IF NOT EXISTS featured_tag (
    id text PRIMARY KEY,
    account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    name citext NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, name)
);

CREATE TABLE IF NOT EXISTS instance_rule (
    id text PRIMARY KEY,
    text text NOT NULL,
    hint text,
    ord integer NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scheduled_status (
    id text PRIMARY KEY,
    account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    scheduled_at timestamptz NOT NULL,
    params jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS scheduled_status_due_idx ON scheduled_status (scheduled_at);
CREATE INDEX IF NOT EXISTS scheduled_status_account_idx
    ON scheduled_status (account_id, scheduled_at DESC);

CREATE TABLE IF NOT EXISTS conversation_mute (
    account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    root_id text NOT NULL REFERENCES status (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, root_id)
);

ALTER TABLE account ADD COLUMN IF NOT EXISTS avatar_url text;
ALTER TABLE account ADD COLUMN IF NOT EXISTS header_url text;
