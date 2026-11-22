-- Profile variants: an avatar and header, each with a still twin.
--
-- `layer` is text, but 0008 pinned its values with a CHECK constraint, so a new layer
-- name is a schema change even though the column type is unchanged. The primary key is
-- (media_id, layer, max_edge), which already separates the new rows from the post ones;
-- no other constraint has to move.
ALTER TABLE media_variant
    DROP CONSTRAINT media_variant_layer_check,
    ADD CONSTRAINT media_variant_layer_check CHECK (
        layer IN (
            'preview', 'compressed', 'lossless',
            'avatar', 'header', 'avatar_static', 'header_static'
        )
    );
