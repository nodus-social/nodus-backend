-- Client-owned organisation: lists group follows, filters hide matching posts.
CREATE TABLE list (
    id             text PRIMARY KEY,
    account_id     text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    title          text NOT NULL,
    replies_policy text NOT NULL DEFAULT 'list'
        CHECK (replies_policy IN ('followed', 'list', 'none')),
    exclusive      boolean NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX list_account_idx ON list (account_id, created_at DESC);

CREATE TABLE list_account (
    list_id    text NOT NULL REFERENCES list (id) ON DELETE CASCADE,
    account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (list_id, account_id)
);

CREATE TABLE filter (
    id         text PRIMARY KEY,
    account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    title      text NOT NULL,
    context    text[] NOT NULL DEFAULT '{home,notifications,public,thread}',
    action     text NOT NULL DEFAULT 'warn'
        CHECK (action IN ('warn', 'hide')),
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX filter_account_idx ON filter (account_id, created_at DESC);

CREATE TABLE filter_keyword (
    id         text PRIMARY KEY,
    filter_id  text NOT NULL REFERENCES filter (id) ON DELETE CASCADE,
    keyword    text NOT NULL,
    whole_word boolean NOT NULL DEFAULT false
);

CREATE INDEX filter_keyword_filter_idx ON filter_keyword (filter_id);
