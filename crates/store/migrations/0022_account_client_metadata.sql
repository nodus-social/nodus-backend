-- Universal per-account client metadata for styling, layout, and third-party client state.
ALTER TABLE account
    ADD COLUMN client_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD CONSTRAINT account_client_metadata_object CHECK (jsonb_typeof(client_metadata) = 'object');
