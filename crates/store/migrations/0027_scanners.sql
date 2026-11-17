-- Scanners are headless: a service reports labels and confidence, and nothing else.
--
-- Three rules shape this schema.
--
-- A scanner with no rules does nothing. Severity lives in `scanner_rule`, one row per
-- label, so an instance decides for itself that `nsfw` at 0.7 means "mark sensitive" and
-- `is-anime` means "ignore". Nothing here has a default that acts on content.
--
-- A scanner with no content set does nothing either. `scanner_asset` holds the hashes,
-- word list or weights an administrator supplies; the service fetches them from the
-- instance, which keeps every scanner of a kind reading the same set.

CREATE TABLE scanner_asset (
    id           text PRIMARY KEY,
    name         text NOT NULL,
    kind         text NOT NULL CHECK (kind IN ('hashes', 'weights', 'words')),
    digest       text NOT NULL UNIQUE,
    size         bigint NOT NULL,
    content_type text NOT NULL DEFAULT 'application/octet-stream',
    content      bytea NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE scanner (
    id          text PRIMARY KEY,
    name        text NOT NULL,
    kind        text NOT NULL CHECK (kind IN ('image', 'video', 'text')),
    endpoint    text NOT NULL,
    secret      text,
    enabled     boolean NOT NULL DEFAULT true,
    asset_id    text REFERENCES scanner_asset (id) ON DELETE SET NULL,
    contract    integer NOT NULL DEFAULT 1,
    labels      text[] NOT NULL DEFAULT '{}',
    manifest    jsonb NOT NULL DEFAULT '{}'::jsonb,
    manifest_at timestamptz,
    timeout_ms  integer NOT NULL DEFAULT 5000,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX scanner_enabled_idx ON scanner (kind) WHERE enabled;

CREATE TABLE scanner_rule (
    id         text PRIMARY KEY,
    scanner_id text NOT NULL REFERENCES scanner (id) ON DELETE CASCADE,
    label      text NOT NULL,
    threshold  real NOT NULL DEFAULT 0.5 CHECK (threshold >= 0 AND threshold <= 1),
    severity   text NOT NULL DEFAULT 'flag'
        CHECK (severity IN ('ignore', 'flag', 'sensitive', 'block')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scanner_id, label)
);

-- One row per (scanner, subject): the queue is durable, so a restart loses nothing and a
-- scanner that is down retries until it answers or runs out of attempts.
CREATE TABLE scan (
    id           text PRIMARY KEY,
    scanner_id   text NOT NULL REFERENCES scanner (id) ON DELETE CASCADE,
    kind         text NOT NULL,
    subject_type text NOT NULL CHECK (subject_type IN ('status', 'media')),
    subject_id   text NOT NULL,
    url          text,
    text         text,
    mime         text,
    state        text NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'running', 'done', 'failed')),
    score        real,
    labels       text[] NOT NULL DEFAULT '{}',
    detail       jsonb NOT NULL DEFAULT '{}'::jsonb,
    error        text,
    attempts     integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz
);

CREATE UNIQUE INDEX scan_subject_idx ON scan (scanner_id, subject_type, subject_id);
CREATE INDEX scan_pending_idx ON scan (created_at) WHERE state IN ('pending', 'running');

-- What a moderator reviews: one row per thing a scanner judged badly, kept separately
-- from the report queue because nobody filed it.
CREATE TABLE scan_flag (
    id          text PRIMARY KEY,
    scan_id     text NOT NULL REFERENCES scan (id) ON DELETE CASCADE,
    status_id   text REFERENCES status (id) ON DELETE CASCADE,
    account_id  text REFERENCES account (id) ON DELETE CASCADE,
    reason      text NOT NULL,
    score       real,
    labels      text[] NOT NULL DEFAULT '{}',
    severity    text NOT NULL DEFAULT 'flag'
        CHECK (severity IN ('flag', 'sensitive', 'block')),
    state       text NOT NULL DEFAULT 'open'
        CHECK (state IN ('open', 'dismissed', 'actioned')),
    resolved_by text REFERENCES account (id) ON DELETE SET NULL,
    resolved_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX scan_flag_open_idx ON scan_flag (state, created_at DESC);
