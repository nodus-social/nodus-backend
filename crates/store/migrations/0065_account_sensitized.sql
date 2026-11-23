-- "Mark this account's media sensitive" is a moderation decision that is neither a silence
-- nor a suspension: the person keeps posting and federating, and clients merely warn before
-- showing what they posted. Mastodon's admin action list carries it as `sensitive` /
-- `unsensitive`, and our console had no column to record it in, so the decision was
-- unavailable. The timestamp is the whole state: present means marked, absent means not.
ALTER TABLE account ADD COLUMN sensitized_at timestamptz;
