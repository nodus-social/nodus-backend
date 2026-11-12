-- The append-only log behind state sync. A client sends the hash of the last event it
-- applied; the server answers with everything after it, or says the history diverged.
CREATE TABLE event_log (
    seq           bigserial PRIMARY KEY,
    id            text NOT NULL UNIQUE,
    collection    text NOT NULL,
    kind          text NOT NULL,
    payload       jsonb NOT NULL,
    previous_hash text,
    hash          text NOT NULL UNIQUE,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX event_log_collection_seq_idx ON event_log (collection, seq);

-- The current root for each collection, kept in the same transaction as the append so a
-- reader never sees a root that has no matching log entry.
CREATE TABLE collection_state (
    collection text PRIMARY KEY,
    root       text,
    updated_at timestamptz NOT NULL DEFAULT now()
);
