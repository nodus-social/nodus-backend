CREATE TABLE miauth_session (
    id         text PRIMARY KEY,
    app_name   text NOT NULL,
    callback   text,
    scopes     text[] NOT NULL DEFAULT '{}',
    account_id text REFERENCES account (id) ON DELETE CASCADE,
    token      text,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT now() + interval '1 hour'
);
