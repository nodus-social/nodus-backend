-- What we told a peer about its own user.
--
-- A report has always ended at our moderation queue: the peer that hosts the reported
-- account never learned that we had a problem, so its moderators could not act on their
-- side. Forwarding a report is the outbound half of that conversation, and this table is
-- the record of what we said, to whom, and what the peer answered.
--
-- The row is not a second delivery queue. `federation_delivery` stays the only thing that
-- retries, backs off or gives up, so a forwarded report inherits the admin delivery screen
-- for free. This table points at it by `activity_uri` and mirrors its lifecycle with the
-- trigger below: a peer that answers 4xx closes the delivery as `gave_up`, and the mirror
-- says the same thing without any new machinery.
CREATE TABLE report_forward (
    id            text PRIMARY KEY,
    -- One forward per report. Re-asking is idempotent: the first state is the answer.
    report_id     text NOT NULL UNIQUE REFERENCES report (id) ON DELETE CASCADE,
    target_domain text NOT NULL CHECK (btrim(target_domain) <> ''),
    activity_uri  text NOT NULL,
    state         text NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'delivered', 'failed', 'gave_up')),
    attempts      integer NOT NULL DEFAULT 0,
    last_error    text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- The console lists by state and by domain, newest first; both filters get an index.
CREATE INDEX report_forward_state_idx ON report_forward (state, created_at DESC);
CREATE INDEX report_forward_domain_idx ON report_forward (target_domain, created_at DESC);
-- The trigger resolves a delivery back to its forward by the activity we minted for it.
CREATE INDEX report_forward_activity_idx ON report_forward (activity_uri);

-- The queue is the source of truth for attempts and errors; this keeps the mirror honest.
-- `NULL` for the trigger function's return is allowed because it is an AFTER trigger.
CREATE FUNCTION report_forward_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE report_forward
       SET state = NEW.state,
           attempts = NEW.attempts,
           last_error = NEW.last_error,
           updated_at = now()
     WHERE activity_uri = NEW.activity_id
       AND (state IS DISTINCT FROM NEW.state
            OR attempts IS DISTINCT FROM NEW.attempts
            OR last_error IS DISTINCT FROM NEW.last_error);
    RETURN NULL;
END;
$$;

CREATE TRIGGER federation_delivery_report_forward
    AFTER INSERT OR UPDATE OF state, attempts, last_error ON federation_delivery
    FOR EACH ROW EXECUTE FUNCTION report_forward_sync();
