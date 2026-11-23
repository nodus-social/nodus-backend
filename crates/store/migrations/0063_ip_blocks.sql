-- A source address that may not sign up, may sign up only for review, or may not reach
-- the instance at all.
--
-- `ip` is a CIDR, never a bare address, so matching is one containment test on the read
-- path. The API widens a single address to the prefix the session table records (a /24 for
-- IPv4, a /48 for IPv6) before it gets here: a block is a network decision, and widening it
-- is honest about the fact that a host is not what was stored.
--
-- `expires_at` is evaluated when a row is read, not when it is written. An expired block
-- stops applying the moment it lapses and is kept as the record of what was done and why;
-- deleting it on a clock would need a sweep and would erase the evidence.
CREATE TABLE ip_block (
    id         text PRIMARY KEY,
    ip         cidr NOT NULL UNIQUE,
    severity   text NOT NULL CHECK (severity IN ('sign_up_requires_approval', 'sign_up_block', 'no_access')),
    comment    text NOT NULL DEFAULT '',
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Every enforcement query asks "is this address contained in a live block", so the expiry
-- is part of the index that answers it.
CREATE INDEX ip_block_live_idx ON ip_block (severity, expires_at);
