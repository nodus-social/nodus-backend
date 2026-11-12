ALTER TABLE status ADD COLUMN content_source text;
ALTER TABLE status ADD COLUMN content_format text NOT NULL DEFAULT 'html';
ALTER TABLE status ADD CONSTRAINT status_content_format_check
    CHECK (content_format IN ('html', 'mfm', 'markdown'));

CREATE TABLE custom_emoji (
    shortcode text NOT NULL,
    host text NOT NULL DEFAULT '',
    url text NOT NULL,
    category text,
    visible_in_picker boolean NOT NULL DEFAULT true,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (shortcode, host)
);

CREATE TABLE status_reaction (
    status_id text NOT NULL REFERENCES status(id) ON DELETE CASCADE,
    account_id text NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    reaction text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (status_id, account_id)
);

CREATE INDEX status_reaction_status_idx ON status_reaction (status_id);
