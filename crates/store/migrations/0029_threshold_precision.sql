-- A threshold is compared against a confidence the scanner reports as a float, and the
-- comparison happens in Rust: a single-precision column forces a lossy round trip through
-- `real` on every write and fails to decode into the field that holds it.
ALTER TABLE scanner_rule ALTER COLUMN threshold TYPE double precision;
