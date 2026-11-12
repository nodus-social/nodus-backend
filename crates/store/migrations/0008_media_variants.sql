ALTER TABLE media_attachment
    ADD COLUMN lossless boolean NOT NULL DEFAULT false,
    ADD COLUMN remote boolean NOT NULL DEFAULT false,
    ADD COLUMN last_accessed_at timestamptz;

CREATE TABLE media_variant (
    media_id       text NOT NULL REFERENCES media_attachment (id) ON DELETE CASCADE,
    layer          text NOT NULL CHECK (layer IN ('preview', 'compressed', 'lossless')),
    object_key     text NOT NULL,
    content_type   text NOT NULL,
    digest         text NOT NULL,
    size           bigint NOT NULL,
    width          integer,
    height         integer,
    expires_at     timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (media_id, layer)
);

CREATE INDEX media_variant_expiry_idx ON media_variant (expires_at)
    WHERE expires_at IS NOT NULL;
