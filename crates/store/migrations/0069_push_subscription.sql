-- A browser's Web Push subscription, as `POST /api/v1/push/subscription` receives it.
--
-- One row per (account, endpoint): a person may browse from several devices, and each
-- browser's PushManager endpoint is its own destination. The same endpoint posted twice
-- must update the keys in place rather than add a second row, or one event would be
-- delivered once per duplicate.
--
-- The three key columns are the payload the browser generated. A row without a non-empty
-- endpoint has nowhere to send, and a row without both `p256dh` and `auth` can never be
-- encrypted to, so the constraints make that garbage unrepresentable rather than leaving
-- the delivery slice (2) to discover it. `alerts` is the Mastodon 4.6 object form
-- (`{"mention": true, ...}`), not a bitmask: the serializer publishes an object and the
-- API accepts the same shape, so a row stores exactly what a client reads back.
--
-- `user_agent` is for the person, not the protocol: "Firefox on Linux" is how a stale
-- subscription is recognised in a browser list. `failure_count` and `last_success_at` are
-- what slice 2's sender will use to retire a dead endpoint; this slice only stores and
-- increments them.
CREATE TABLE push_subscription (
    id              text        PRIMARY KEY,
    account_id      text        NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    endpoint        text        NOT NULL,
    p256dh          text        NOT NULL,
    auth            text        NOT NULL,
    alerts          jsonb       NOT NULL,
    user_agent      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_success_at timestamptz,
    failure_count   integer     NOT NULL DEFAULT 0,
    CONSTRAINT push_subscription_endpoint_present CHECK (btrim(endpoint) <> ''),
    CONSTRAINT push_subscription_p256dh_present CHECK (btrim(p256dh) <> ''),
    CONSTRAINT push_subscription_auth_present CHECK (btrim(auth) <> ''),
    CONSTRAINT push_subscription_alerts_object CHECK (jsonb_typeof(alerts) = 'object'),
    CONSTRAINT push_subscription_failure_count_nonnegative CHECK (failure_count >= 0),
    CONSTRAINT push_subscription_endpoint_unique UNIQUE (account_id, endpoint)
);

-- `GET /api/v1/push/subscription` reads the account's subscriptions; the unique constraint
-- above already indexes (account_id, endpoint), whose leading column serves this read.
