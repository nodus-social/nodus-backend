-- The nine preferences this instance reads and writes.
--
-- One row per account, created on the first write. A missing row means every column's
-- default, so a new account needs no backfill.
--
-- Mastodon v4.6.3's preferences serializer emits `posting:default:quote_policy` and no
-- notification keys. We keep the notification switches for round-tripping and add the
-- quote policy so a v4.6.3 client can PUT the map it just read without a 422. Mastodon's
-- unreleased main branch also has `posting:default:spoiler_field`; it is deliberately
-- absent until a release we claim to match emits it.
--
-- The notification switches are stored even though this instance runs no mailer and has
-- no report-notification policy: they have no effect here beyond round-tripping.
CREATE TABLE account_preference (
    account_id                   text PRIMARY KEY REFERENCES account (id) ON DELETE CASCADE,
    posting_default_visibility   text NOT NULL DEFAULT 'public',
    posting_default_sensitive    boolean NOT NULL DEFAULT false,
    posting_default_language     text,
    posting_default_quote_policy text NOT NULL DEFAULT 'public',
    reading_expand_media         text NOT NULL DEFAULT 'default',
    reading_expand_spoilers      boolean NOT NULL DEFAULT false,
    reading_autoplay_gifs        boolean NOT NULL DEFAULT false,
    notification_email           boolean NOT NULL DEFAULT true,
    notification_report          boolean NOT NULL DEFAULT true,
    updated_at                   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT account_preference_visibility_allowed CHECK (
        posting_default_visibility IN ('public', 'unlisted', 'private', 'direct')
    ),
    CONSTRAINT account_preference_quote_policy_allowed CHECK (
        posting_default_quote_policy IN ('public', 'followers', 'nobody')
    ),
    CONSTRAINT account_preference_expand_media_allowed CHECK (
        reading_expand_media IN ('default', 'show_all', 'hide_all')
    )
);
