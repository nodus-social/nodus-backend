-- Local credentials and browser sessions. OAuth apps/codes/tokens already exist in
-- 0001; this adds the password login used by the auth service and the short-lived
-- authorization-code row consumed by /oauth/token.

CREATE TABLE account_credential (
    account_id   text PRIMARY KEY REFERENCES account (id) ON DELETE CASCADE,
    email        citext NOT NULL UNIQUE,
    password_hash text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE auth_session (
    id         text PRIMARY KEY,
    account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX auth_session_account_idx ON auth_session (account_id);
CREATE INDEX auth_session_expiry_idx ON auth_session (expires_at);

CREATE TABLE oauth_code (
    id             text PRIMARY KEY,
    app_id         text NOT NULL REFERENCES oauth_app (id) ON DELETE CASCADE,
    account_id     text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    code_hash      text NOT NULL UNIQUE,
    redirect_uri   text NOT NULL,
    scopes         text[] NOT NULL,
    code_challenge text NOT NULL,
    expires_at     timestamptz NOT NULL,
    consumed_at    timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX oauth_code_expiry_idx ON oauth_code (expires_at) WHERE consumed_at IS NULL;
