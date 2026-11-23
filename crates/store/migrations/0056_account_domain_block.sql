-- A personal domain block: one account choosing not to read a host.
--
-- This is not `instance_block`: that is the instance's own policy, applies to everyone,
-- and bears a severity. A personal block hides the host from the reader who asked for it
-- and from nobody else. The pair is unique so a repeated add is a no-op, and the cascade
-- follows the account it belongs to.
CREATE TABLE account_domain_block (
    id             text PRIMARY KEY,
    account_id     text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    host           citext NOT NULL,
    reject_media   boolean NOT NULL DEFAULT false,
    reject_reports boolean NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX account_domain_block_account_host_idx
    ON account_domain_block (account_id, host);
