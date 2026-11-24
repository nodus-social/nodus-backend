-- Relay subscriptions: the instance following a relay actor, which is not an account's follow.
--
-- A relay is addressed the way Mastodon addresses one: the operator supplies the URL the
-- `Follow` is sent to, and that same URL is the `object` of the `Follow`. No actor document
-- is fetched at subscribe time, so that URL is also the only identity a pending row has and
-- is stored once, as `actor_uri`. The answer is matched by `follow_activity_id`, which the
-- relay echoes as the `object` of its `Accept` or `Reject`; matching an actor URL would be a
-- guess about which URL a relay calls itself.
--
-- `state` moves one way: `pending` until the relay answers, then `accepted` or `rejected`.
-- There is no `idle`: a row exists because a `Follow` was queued. `last_attempt_at` is for
-- an operator reading a subscription that never answered, not a retry schedule — the
-- delivery queue owns retries. `follow_activity_id` is kept because the `Undo` that
-- unsubscribes must name the exact activity the relay stored.
CREATE TABLE relay (
    id                 text        PRIMARY KEY,
    actor_uri          text        NOT NULL,
    state              text        NOT NULL,
    follow_activity_id text,
    last_attempt_at    timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT relay_actor_uri_present CHECK (btrim(actor_uri) <> ''),
    CONSTRAINT relay_state_known CHECK (state IN ('pending', 'accepted', 'rejected')),
    CONSTRAINT relay_actor_uri_unique UNIQUE (actor_uri)
);

-- The inbox matches an `Accept`/`Reject` by the `Follow` it answers, and an `Announce`
-- by the actor that sent it. Both are point lookups, and the unique index above already
-- serves the second; this one serves the first.
CREATE INDEX relay_follow_activity_idx ON relay (follow_activity_id)
    WHERE follow_activity_id IS NOT NULL;
