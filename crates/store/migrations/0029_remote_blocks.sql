-- Actors that told us they block this instance.
--
-- An inbound `Block` is a delivery instruction, not a moderation decision: we keep the
-- peer's posts and account, and stop writing to its inboxes. One row per actor keeps a
-- repeated activity idempotent.

CREATE TABLE remote_block (
    id         text PRIMARY KEY,
    actor_uri  text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);
