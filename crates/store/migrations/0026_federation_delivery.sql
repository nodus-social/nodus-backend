-- Outbound federation deliveries.
--
-- An activity is written down before it is sent, because a peer that is down must not cost
-- us the activity: this table is the record of what we still owe other instances, and the
-- worker reads it in order. Rows are kept with `delivered_at` set instead of deleted so a
-- delivery that keeps failing can still be seen after the fact.

CREATE TABLE federation_delivery (
    id text PRIMARY KEY,
    account_id text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    activity_id text NOT NULL,
    inbox_url text NOT NULL,
    activity jsonb NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error text,
    delivered_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    -- The same activity addressed to the same inbox twice is one delivery: a retry of the
    -- request that enqueued it must not double-post to the peer.
    UNIQUE (inbox_url, activity_id)
);

CREATE INDEX federation_delivery_due_idx
    ON federation_delivery (next_attempt_at)
    WHERE delivered_at IS NULL;
