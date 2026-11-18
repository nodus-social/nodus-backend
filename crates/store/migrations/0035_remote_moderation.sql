-- One hostile account on a friendly server, moderated without silencing the server.
--
-- A domain block is the whole instance; this is one actor on it. `silence` keeps the
-- account's posts out of public timelines and anonymous listings while a direct link
-- still resolves; `suspend` removes the account and its posts everywhere and refuses
-- new inbound activities from it.
--
-- `expires_at` is evaluated when the row is read, not when it is written: an expired row
-- stops applying and is kept as the record of what was done and why.
CREATE TABLE remote_moderation (
    actor_uri  text PRIMARY KEY,
    action     text NOT NULL CHECK (action IN ('silence', 'suspend')),
    reason     text,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by text
);

-- The read path asks "which of these actors are moderated right now", so the expiry is
-- part of the index that answers it.
CREATE INDEX remote_moderation_active_idx ON remote_moderation (expires_at);
