-- Actor identity is local to the account, not to a deployment. The keys are stored
-- beside the actor so a server can sign inbox requests after a restart without an
-- external secret store; `private_key_ref` remains for deployments that move them out.

ALTER TABLE account
    ADD COLUMN private_key_pem text,
    ADD COLUMN discoverable boolean NOT NULL DEFAULT true,
    ADD COLUMN indexable boolean NOT NULL DEFAULT true;

CREATE INDEX account_local_actor_idx ON account (id)
    WHERE local AND public_key_pem IS NOT NULL;
