DROP INDEX media_digest_idx;
CREATE INDEX media_digest_idx ON media_attachment (digest);
