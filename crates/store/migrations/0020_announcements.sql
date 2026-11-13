CREATE TABLE announcement (
    id text PRIMARY KEY,
    content text NOT NULL,
    published boolean NOT NULL DEFAULT false,
    all_day boolean NOT NULL DEFAULT false,
    starts_at timestamptz,
    ends_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX announcement_published_idx
    ON announcement (published, starts_at, ends_at);

CREATE TABLE announcement_read (
    account_id text NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    announcement_id text NOT NULL REFERENCES announcement(id) ON DELETE CASCADE,
    read_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, announcement_id)
);
