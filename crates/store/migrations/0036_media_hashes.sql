-- Inbound media, checked against the instance's own content sets.
--
-- A content set is a list of digests an administrator uploaded as `scanner_asset.kind =
-- 'hashes'`. Until now nothing ever compared anything to one, so the sets only existed to
-- be downloaded by a scanner service that was never pointed at federated media: a hostile
-- picture sat visible in a thread until a moderator happened to look.
--
-- The two columns below are the subject of that comparison. `content_hash` is the
-- SHA-256 of the bytes as they arrived; `perceptual_hash` is the 64-bit dHash of the
-- decoded image, so a re-encode or a resize still matches. Both are hex text, which is
-- also how they appear in a set file, so a row and a line read the same way.
ALTER TABLE media_attachment
    ADD COLUMN content_hash     text,
    ADD COLUMN perceptual_hash  text,
    -- 'none' until a set matches, 'quarantined' while hidden, 'released' once a moderator
    -- has cleared it. The release is kept on the row on purpose: `replace_remote` carries
    -- it over per URL, so a peer's `Update` cannot re-quarantine a picture a human cleared.
    ADD COLUMN quarantine_state text NOT NULL DEFAULT 'none'
        CHECK (quarantine_state IN ('none', 'quarantined', 'released')),
    -- Which set matched, so the decision screen can name the signal after the fact.
    ADD COLUMN quarantine_set   text;

-- Exact match is a lookup and the ingest path asks on every attachment it fetched.
CREATE INDEX media_attachment_content_hash_idx ON media_attachment (content_hash)
    WHERE content_hash IS NOT NULL;
CREATE INDEX media_attachment_quarantine_idx ON media_attachment (quarantine_state)
    WHERE quarantine_state <> 'none';

-- The post-level half of a quarantine. The public, outbox and home queries exclude a
-- quarantined status; `by_id` does not, so a link someone already has still resolves and a
-- moderator can open what the report is about. That is the same bargain silence makes.
ALTER TABLE status ADD COLUMN quarantined_at timestamptz;
CREATE INDEX status_quarantined_idx ON status (quarantined_at)
    WHERE quarantined_at IS NOT NULL;

-- A report opened by the instance itself — a content-set match, not a reader pressing
-- "report" — has no human reporter, and inventing one would put words in an account's
-- mouth. Everything that renders a report already treats its reporter as optional.
ALTER TABLE report ALTER COLUMN account_id DROP NOT NULL;
