-- The banner regions an account publishes for other readers to draw on its profile.
--
-- Only the three banners are here. The owner's navigation layout, rail modules and
-- categories stay in `account.client_metadata`, which is served only to that account's
-- own token; publishing a banner must not turn a private arrangement into a public one.
--
-- One row per account, replaced wholesale, so a picture its owner removed disappears for
-- every viewer instead of lingering behind a merge. The JSON document is validated at the
-- API boundary (`style_public` in the store crate owns the types); the two checks here are
-- a backstop for a write that bypassed that boundary, not the advertised budget.
CREATE TABLE account_style_public (
    account_id text PRIMARY KEY REFERENCES account (id) ON DELETE CASCADE,
    regions    jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT account_style_public_is_an_object
        CHECK (jsonb_typeof(regions) = 'object'),
    CONSTRAINT account_style_public_within_backstop
        CHECK (pg_column_size(regions) <= 16384)
);
