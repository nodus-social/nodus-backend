-- Transactional mail: the row is written with the state change that justifies it, and a
-- background task is the only thing that talks to a mail server.
--
-- The outbox separates a request from an SMTP round trip. Registration commits an account,
-- a credential and the confirmation token in one transaction and returns; a send failure
-- can then only mark this row, never the account. `attempts` plus `last_error` are the
-- visible failure count: an operator can see a message that will never leave without
-- reading a log file.

CREATE TABLE email_outbox (
    id          text PRIMARY KEY,
    recipient   citext NOT NULL,
    subject     text NOT NULL,
    body_text   text NOT NULL,
    body_html   text NOT NULL DEFAULT '',
    attempts    integer NOT NULL DEFAULT 0,
    last_error  text,
    sent_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT email_outbox_attempts_nonnegative CHECK (attempts >= 0),
    CONSTRAINT email_outbox_sent_has_no_error CHECK (sent_at IS NULL OR last_error IS NULL)
);

-- The worker's only query is "what is still owed", oldest first.
CREATE INDEX email_outbox_pending_idx ON email_outbox (created_at) WHERE sent_at IS NULL;

-- Confirmation links are stored hashed, like sessions and OAuth codes: a database reader
-- must not be able to turn a row back into a working link. `used_at` makes a link
-- single-use even within its lifetime.
CREATE TABLE email_confirmation (
    token_hash  text PRIMARY KEY,
    account_id  text NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX email_confirmation_account_idx ON email_confirmation (account_id);

-- Accounts created before this migration have no proof either way; NULL is the honest
-- value. A confirmed address records when the link was followed, and a future flow that
-- gates on verification can start from here without a second column.
ALTER TABLE account_credential ADD COLUMN confirmed_at timestamptz;
