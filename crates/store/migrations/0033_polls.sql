-- Polls are an attachment of a status, like media: a status has at most one poll, and
-- the poll lives beside the status rather than inside its text.
--
-- `options` is a JSON array of titles in display order. A vote is one row per account per
-- option, so the primary key makes a retried vote the same vote instead of a second one.
-- `multiple` decides whether a voter may hold more than one option; `hide_totals` is kept
-- because clients send it, even though this surface does not hide counts yet.

CREATE TABLE poll (
    id text PRIMARY KEY,
    status_id text NOT NULL UNIQUE REFERENCES status (id) ON DELETE CASCADE,
    options jsonb NOT NULL
        CONSTRAINT poll_options_shape CHECK (jsonb_typeof(options) = 'array'),
    multiple boolean NOT NULL DEFAULT false,
    hide_totals boolean NOT NULL DEFAULT false,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    -- Mastodon's compose limits, enforced where a poll is written rather than only in the
    -- handler that happens to write it today.
    CONSTRAINT poll_options_count CHECK (jsonb_array_length(options) BETWEEN 1 AND 4)
);

CREATE TABLE poll_vote (
    poll_id text NOT NULL REFERENCES poll (id) ON DELETE CASCADE,
    account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    option_index integer NOT NULL CHECK (option_index >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (poll_id, account_id, option_index)
);

-- "Who voted for this poll" and "what did this account pick" are the two reads; the
-- primary key serves the second, this index the first.
CREATE INDEX poll_vote_account_idx ON poll_vote (account_id, poll_id);
