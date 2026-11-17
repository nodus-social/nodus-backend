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

-- The tables above are guarded by name, so a table a person recreated by hand wins. These
-- guards make that table usable rather than merely present: a hand-made `marker` without
-- `version`, or a `scheduled_status` whose `params` arrived as text, would otherwise fail
-- at the first read instead of at this migration.
ALTER TABLE marker ADD COLUMN IF NOT EXISTS last_read_id text;
ALTER TABLE marker ADD COLUMN IF NOT EXISTS version integer NOT NULL DEFAULT 1;
ALTER TABLE marker ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE conversation_read ADD COLUMN IF NOT EXISTS last_read_id text;
ALTER TABLE conversation_read
    ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE featured_tag ADD COLUMN IF NOT EXISTS name citext;
ALTER TABLE featured_tag ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE instance_rule ADD COLUMN IF NOT EXISTS text text;
ALTER TABLE instance_rule ADD COLUMN IF NOT EXISTS hint text;
ALTER TABLE instance_rule ADD COLUMN IF NOT EXISTS ord integer NOT NULL DEFAULT 0;
ALTER TABLE scheduled_status ADD COLUMN IF NOT EXISTS scheduled_at timestamptz;
ALTER TABLE scheduled_status ADD COLUMN IF NOT EXISTS params jsonb;
ALTER TABLE scheduled_status
    ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE conversation_mute ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();

-- `ON CONFLICT` needs a unique constraint or a unique index, and a table a person made by
-- hand may have neither. These are the same keys the creates above declare, restated as
-- indexes so the guarded form works on both kinds of table.
CREATE UNIQUE INDEX IF NOT EXISTS marker_account_timeline_key ON marker (account_id, timeline);
CREATE UNIQUE INDEX IF NOT EXISTS conversation_read_account_root_key
    ON conversation_read (account_id, root_id);
CREATE UNIQUE INDEX IF NOT EXISTS conversation_mute_account_root_key
    ON conversation_mute (account_id, root_id);
CREATE UNIQUE INDEX IF NOT EXISTS featured_tag_account_name_key
    ON featured_tag (account_id, name);
CREATE UNIQUE INDEX IF NOT EXISTS instance_rule_id_key ON instance_rule (id);
CREATE UNIQUE INDEX IF NOT EXISTS scheduled_status_id_key ON scheduled_status (id);
