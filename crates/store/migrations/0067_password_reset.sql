-- A password reset is a single-use bearer link, stored hashed for the same reason as a
-- confirmation or a session: reading this table must not hand someone a working link.
-- It is separate from `email_confirmation` because completing it changes a credential and
-- revokes sessions, while confirming an address only records `confirmed_at`; overloading
-- one table would make every reader ask which kind of token it was looking at.
CREATE TABLE password_reset (
    token_hash  text PRIMARY KEY,
    account_id  text NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX password_reset_account_idx ON password_reset (account_id);

-- One row per address, not per account: an unknown address must be rate limited exactly
-- like a known one, otherwise the limiter itself answers "does this address exist?".
-- `window_started_at` makes this a fixed window so a caller cannot extend the budget by
-- waiting between requests.
CREATE TABLE password_reset_attempt (
    email             citext PRIMARY KEY,
    attempts          integer NOT NULL DEFAULT 0,
    window_started_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT password_reset_attempt_attempts_nonnegative CHECK (attempts >= 0)
);
