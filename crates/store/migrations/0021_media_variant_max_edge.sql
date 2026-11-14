ALTER TABLE media_variant
    ADD COLUMN max_edge bigint NOT NULL DEFAULT 0,
    DROP CONSTRAINT media_variant_pkey,
    ADD PRIMARY KEY (media_id, layer, max_edge);
