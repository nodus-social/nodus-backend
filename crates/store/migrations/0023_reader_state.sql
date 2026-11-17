-- Two kinds of reader state have no home yet: where a reader stopped reading a
-- timeline, and which direct messages they have already opened. Both are properties of
-- the reader, so both are keyed by the account rather than hanging off the status.

CREATE TABLE IF NOT EXISTS marker (
    account_id   text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    timeline     text NOT NULL,
    last_read_id text NOT NULL,
    version      integer NOT NULL DEFAULT 1,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, timeline)
);

CREATE TABLE IF NOT EXISTS conversation_read (
    account_id   text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    root_id      text NOT NULL REFERENCES status (id) ON DELETE CASCADE,
    last_read_id text NOT NULL,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, root_id)
);
