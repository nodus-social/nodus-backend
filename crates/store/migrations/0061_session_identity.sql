-- A browser session that a reader can recognise, and trust afterwards.
--
-- `ip` is stored truncated, never whole: a /24 for IPv4 and a /48 for IPv6. The address
-- answers "which network did this session come from", which is what the settings page
-- shows; the host bits add nothing to that answer and would turn a thirty-day session row
-- into a precise location record that outlives its usefulness.

ALTER TABLE auth_session
    ADD COLUMN user_agent   text NOT NULL DEFAULT '',
    ADD COLUMN ip           text,
    ADD COLUMN last_used_at timestamptz;

-- Existing rows never had a device or a use time; the login that made them is the only
-- honest timestamp we can give them.
UPDATE auth_session SET last_used_at = created_at WHERE last_used_at IS NULL;

CREATE INDEX auth_session_last_used_idx ON auth_session (last_used_at);
