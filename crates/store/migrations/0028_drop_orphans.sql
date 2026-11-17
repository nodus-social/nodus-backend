-- Objects this schema no longer describes, left behind by a build that carried reader state,
-- remote profiles and scheduled posts. They hold nothing the application reads, and every
-- remaining row is unreachable, so the cleanup is a drop rather than a migration of data.

DROP TABLE IF EXISTS conversation_mute;
DROP TABLE IF EXISTS conversation_read;
DROP TABLE IF EXISTS featured_tag;
DROP TABLE IF EXISTS instance_rule;
DROP TABLE IF EXISTS marker;
DROP TABLE IF EXISTS scheduled_status;

-- The account columns that duplicated the media refs, filled by the same build.
ALTER TABLE account DROP COLUMN IF EXISTS avatar_url;
ALTER TABLE account DROP COLUMN IF EXISTS header_url;
