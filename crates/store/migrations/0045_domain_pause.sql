-- The middle of the moderation scale.
--
-- `instance_block` is the final word: a domain is silenced or suspended, permanently, and
-- the peer may never learn why. This is the reversible one: delivery to the domain stops,
-- its activities are still ingested (hidden from public timelines), its media is not
-- fetched, and the row expires on its own or is lifted without the peer ever being told.
--
-- A pause has no severity and no reject_* flags on purpose. Severity is what makes a block
-- permanent; expiry is what makes a pause temporary, and `expires_at` is evaluated on every
-- read rather than by a sweeper so an expired pause stops applying the moment it expires.

CREATE TABLE domain_pause (
    domain     text PRIMARY KEY CHECK (btrim(domain) <> ''),
    reason     text NOT NULL DEFAULT '',
    -- NULL means "until lifted"; anything else is a deadline the read path enforces.
    expires_at timestamptz,
    created_by text REFERENCES account (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Every read asks "which pauses are in force right now", so the expiry is part of the
-- index that answers it.
CREATE INDEX domain_pause_expiry_idx ON domain_pause (expires_at);
