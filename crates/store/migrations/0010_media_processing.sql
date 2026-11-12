ALTER TABLE media_attachment
    ADD COLUMN processing_state text NOT NULL DEFAULT 'pending'
        CHECK (processing_state IN ('pending', 'processing', 'ready', 'failed')),
    ADD COLUMN processing_progress smallint NOT NULL DEFAULT 0
        CHECK (processing_progress BETWEEN 0 AND 100),
    ADD COLUMN processing_error text,
    ADD COLUMN posted_at timestamptz;

CREATE INDEX media_processing_idx ON media_attachment (processing_state)
    WHERE processing_state IN ('pending', 'processing');
