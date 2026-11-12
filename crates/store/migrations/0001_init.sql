-- The M0 schema. Columns that only federation needs (uri, keys, inbox) exist from
-- the start because adding them later would mean backfilling every account row.

CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE account (
    id                text PRIMARY KEY,
    username          citext NOT NULL,
    domain            citext,
    display_name      text NOT NULL DEFAULT '',
    note              text NOT NULL DEFAULT '',
    avatar_ref        text,
    header_ref        text,
    fields            jsonb NOT NULL DEFAULT '[]'::jsonb,
    locked            boolean NOT NULL DEFAULT false,
    bot               boolean NOT NULL DEFAULT false,
    local             boolean NOT NULL DEFAULT true,
    uri               text UNIQUE,
    inbox_url         text,
    shared_inbox_url  text,
    public_key_pem    text,
    private_key_ref   text,
    followers_count   bigint NOT NULL DEFAULT 0,
    following_count   bigint NOT NULL DEFAULT 0,
    statuses_count    bigint NOT NULL DEFAULT 0,
    last_status_at    timestamptz,
    suspended_at      timestamptz,
    silenced_at       timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT account_local_has_no_domain CHECK ((local AND domain IS NULL) OR NOT local)
);

-- A local username is unique per instance; a remote one is unique per domain.
CREATE UNIQUE INDEX account_local_username_idx ON account (username) WHERE domain IS NULL;
CREATE UNIQUE INDEX account_remote_username_idx ON account (domain, username) WHERE domain IS NOT NULL;
CREATE INDEX account_username_trgm_idx ON account USING gin (username gin_trgm_ops);

CREATE TABLE follow (
    id                text PRIMARY KEY,
    account_id        text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    target_account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    uri               text UNIQUE,
    reblogs           boolean NOT NULL DEFAULT true,
    notify            boolean NOT NULL DEFAULT false,
    created_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT follow_not_self CHECK (account_id <> target_account_id)
);

CREATE UNIQUE INDEX follow_pair_idx ON follow (account_id, target_account_id);
CREATE INDEX follow_target_idx ON follow (target_account_id);

CREATE TABLE status (
    id                     text PRIMARY KEY,
    account_id             text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    uri                    text UNIQUE,
    content                text NOT NULL DEFAULT '',
    content_html           text NOT NULL DEFAULT '',
    spoiler_text           text NOT NULL DEFAULT '',
    visibility             text NOT NULL,
    sensitive              boolean NOT NULL DEFAULT false,
    in_reply_to_id         text REFERENCES status (id) ON DELETE SET NULL,
    in_reply_to_account_id text REFERENCES account (id) ON DELETE SET NULL,
    reblog_of_id           text REFERENCES status (id) ON DELETE CASCADE,
    language               text,
    local                  boolean NOT NULL DEFAULT true,
    edited_at              timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    deleted_at             timestamptz,
    favourites_count       bigint NOT NULL DEFAULT 0,
    reblogs_count          bigint NOT NULL DEFAULT 0,
    replies_count          bigint NOT NULL DEFAULT 0,
    CONSTRAINT status_visibility_valid
        CHECK (visibility IN ('public', 'unlisted', 'private', 'direct'))
);

-- The public timeline is a query, not a table: `(visibility, created_at)` with the
-- author joining in. Local-only is the default view, so `local` participates.
CREATE INDEX status_public_idx ON status (created_at DESC, id DESC)
    WHERE deleted_at IS NULL AND visibility = 'public';
CREATE INDEX status_account_idx ON status (account_id, created_at DESC, id DESC)
    WHERE deleted_at IS NULL;
CREATE INDEX status_replies_idx ON status (in_reply_to_id) WHERE in_reply_to_id IS NOT NULL;

CREATE TABLE status_mention (
    status_id  text NOT NULL REFERENCES status (id) ON DELETE CASCADE,
    account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    PRIMARY KEY (status_id, account_id)
);

CREATE TABLE status_tag (
    status_id text NOT NULL REFERENCES status (id) ON DELETE CASCADE,
    tag       citext NOT NULL,
    PRIMARY KEY (status_id, tag)
);

CREATE INDEX status_tag_tag_idx ON status_tag (tag);

CREATE TABLE media_attachment (
    id           text PRIMARY KEY,
    account_id   text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    status_id    text REFERENCES status (id) ON DELETE SET NULL,
    digest       text NOT NULL,
    content_type text NOT NULL,
    size         bigint NOT NULL,
    width        integer,
    height       integer,
    blurhash     text,
    description  text NOT NULL DEFAULT '',
    meta         jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX media_digest_idx ON media_attachment (digest);
CREATE INDEX media_status_idx ON media_attachment (status_id);

CREATE TABLE favourite (
    account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    status_id  text NOT NULL REFERENCES status (id) ON DELETE CASCADE,
    uri        text UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, status_id)
);

CREATE TABLE bookmark (
    account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    status_id  text NOT NULL REFERENCES status (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, status_id)
);

-- Materialised home/list timeline. Big accounts skip this table entirely; the reader
-- unions both lanes and dedupes by status_id.
CREATE TABLE timeline_entry (
    account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    status_id  text NOT NULL REFERENCES status (id) ON DELETE CASCADE,
    kind       text NOT NULL DEFAULT 'home',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, status_id, kind)
);

CREATE INDEX timeline_entry_page_idx ON timeline_entry (account_id, status_id DESC);

CREATE TABLE notification (
    id              text PRIMARY KEY,
    account_id      text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    kind            text NOT NULL,
    from_account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    status_id       text REFERENCES status (id) ON DELETE CASCADE,
    seen_at         timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT notification_kind_valid
        CHECK (kind IN ('follow', 'favourite', 'reblog', 'mention', 'poll', 'status'))
);

CREATE INDEX notification_account_idx ON notification (account_id, id DESC);

CREATE TABLE oauth_app (
    id                 text PRIMARY KEY,
    client_id          text NOT NULL UNIQUE,
    client_secret_hash text NOT NULL,
    name               text NOT NULL,
    website            text,
    redirect_uris      text[] NOT NULL,
    scopes             text[] NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE oauth_token (
    id           text PRIMARY KEY,
    app_id       text NOT NULL REFERENCES oauth_app (id) ON DELETE CASCADE,
    account_id   text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    token_hash   text NOT NULL UNIQUE,
    scopes       text[] NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz
);

CREATE INDEX oauth_token_account_idx ON oauth_token (account_id) WHERE revoked_at IS NULL;

-- The queue (docs/05-workers.md). `subject_id` participates in a partial unique index
-- so an outstanding job cannot be enqueued twice.
CREATE TABLE job (
    id          text PRIMARY KEY,
    kind        text NOT NULL,
    priority    smallint NOT NULL DEFAULT 0,
    payload     jsonb NOT NULL DEFAULT '{}'::jsonb,
    subject_id  text,
    attempts    integer NOT NULL DEFAULT 0,
    earliest_at timestamptz NOT NULL DEFAULT now(),
    locked_by   text,
    locked_until timestamptz,
    last_error  text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    CONSTRAINT job_kind_valid CHECK (
        kind IN ('fan_out', 'deliver', 'media_process', 'ingest_remote', 'prune')
    )
);

CREATE UNIQUE INDEX job_outstanding_subject_idx ON job (kind, subject_id)
    WHERE finished_at IS NULL AND subject_id IS NOT NULL;
CREATE INDEX job_ready_idx ON job (priority DESC, earliest_at)
    WHERE finished_at IS NULL;
