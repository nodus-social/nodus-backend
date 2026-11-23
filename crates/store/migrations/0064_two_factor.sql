-- A second factor for the local password login. `account_credential` already holds the
-- password; this table holds the TOTP secret it is paired with. `confirmed_at` is NULL
-- until the user proves an authenticator produces codes for the secret, so a half-finished
-- enrolment never gates a login.
CREATE TABLE account_totp (
    account_id     text PRIMARY KEY REFERENCES account (id) ON DELETE CASCADE,
    secret         text NOT NULL,
    confirmed_at   timestamptz,
    -- The last accepted RFC 6238 step. Accepting only a step greater than this one is what
    -- makes a code single-use: the same window can never be replayed.
    last_used_step bigint,
    created_at     timestamptz NOT NULL DEFAULT now()
);

-- Recovery codes are stored hashed, exactly like session tokens, and marked used rather
-- than deleted so a reused code is recognisably spent instead of merely unknown.
CREATE TABLE account_recovery_code (
    account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    code_hash  text NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, code_hash)
);

CREATE INDEX account_recovery_code_live_idx
    ON account_recovery_code (account_id) WHERE used_at IS NULL;

-- The short-lived proof that a password was accepted. It is keyed by account, so a second
-- login attempt replaces the first challenge instead of leaving two live.
CREATE TABLE auth_2fa_challenge (
    account_id text PRIMARY KEY REFERENCES account (id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX auth_2fa_challenge_expiry_idx ON auth_2fa_challenge (expires_at);
