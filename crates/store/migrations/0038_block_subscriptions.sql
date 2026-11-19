-- A block list is something an administrator carries between instances, and something an
-- instance subscribes to and keeps in step. Neither is a one-off import, so the peer's
-- identity, its validators and its last result have to live somewhere durable.
--
-- `reject_follows` completes the block: Mastodon has carried it since 3.0 and a list
-- written there names it, so a round trip through this instance would silently drop the
-- one flag that decides whether follows are refused. It follows the same default as the
-- other rejections — off — because a block that silently stopped follows would be a
-- surprise, not a policy.
ALTER TABLE instance_block
    ADD COLUMN reject_follows boolean NOT NULL DEFAULT false;

-- One row per peer list. `format` is what we asked for, not what we got: the sync sends the
-- matching Accept header, so a peer that answers CSV to a JSON request is an error worth
-- recording rather than guessing about.
--
-- `etag` and `last_modified` are the peer's validators, echoed back verbatim. `last_error`
-- is the reason the last sync failed, cleared by the next success; a peer that is down for
-- a week must not leave the console saying everything is fine, and a sync that panics
-- would take the whole worker with it.
CREATE TABLE domain_block_subscription (
    id             text PRIMARY KEY,
    url            text NOT NULL UNIQUE,
    format         text NOT NULL
        CONSTRAINT domain_block_subscription_format_check CHECK (format IN ('csv', 'json')),
    enabled        boolean NOT NULL DEFAULT true,
    etag           text,
    last_modified  text,
    last_synced_at timestamptz,
    last_error     text,
    created_at     timestamptz NOT NULL DEFAULT now()
);

-- The sweep asks "which enabled subscriptions have waited longest", so the index answers
-- that directly and skips the disabled rows entirely. `NULLS FIRST` puts a subscription
-- that has never synced ahead of one that has.
CREATE INDEX domain_block_subscription_due_idx
    ON domain_block_subscription (last_synced_at NULLS FIRST)
    WHERE enabled;
