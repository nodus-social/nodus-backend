-- A remote account's pictures live on its own instance, not in our media store, so the
-- reference columns (`avatar_ref`, `header_ref`) cannot describe them: those name a file
-- we host. The URL columns carry what the actor document advertised instead, and the
-- DTO prefers them when they are set.

ALTER TABLE account
    ADD COLUMN IF NOT EXISTS avatar_url text,
    ADD COLUMN IF NOT EXISTS header_url text;
