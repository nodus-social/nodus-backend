-- Following a tag is a reader's subscription, not a moderation record. The tag itself has
-- no table: it exists wherever a post used it, so the subscription stores the name the
-- reader picked and survives an unfollow/re-follow cycle without duplicating a row.
CREATE TABLE tag_follow (
    account_id text        NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    tag        citext      NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, tag)
);

-- A tag page asks who follows it.
CREATE INDEX tag_follow_tag_idx ON tag_follow (tag);
