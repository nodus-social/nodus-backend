-- Storage for the remaining reader-facing features: posts waiting to go out, tags a
-- profile highlights, muted conversations, and the rules an instance publishes.

CREATE TABLE scheduled_status (
    id text PRIMARY KEY,
    account_id text NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    scheduled_at timestamptz NOT NULL,
    -- The composed post, exactly as the client sent it. `jsonb` rather than columns
    -- because a schedule outlives changes to what a post can contain.
    params jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX scheduled_status_due_idx ON scheduled_status (scheduled_at);
CREATE INDEX scheduled_status_account_idx ON scheduled_status (account_id, scheduled_at DESC);

CREATE TABLE featured_tag (
    id text PRIMARY KEY,
    account_id text NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    name citext NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, name)
);

CREATE TABLE conversation_mute (
    account_id text NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    root_id text NOT NULL REFERENCES status(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, root_id)
);

CREATE TABLE instance_rule (
    id text PRIMARY KEY,
    text text NOT NULL,
    hint text,
    ord integer NOT NULL DEFAULT 0
);
