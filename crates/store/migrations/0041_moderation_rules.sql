-- Rules that act on their own.
--
-- `instance_rule` (0040) is the code of conduct a report is filed *against*; a person
-- still reads every wave and files the report. This table is the other half: a pattern,
-- a scope and an action, evaluated while a post is stored, so a moderator can say "spam
-- containing this phrase is flagged from now on" instead of reading it by eye.
--
-- Ids are uuid, unlike the ULID-in-text ids elsewhere in this schema, because a rule id
-- is never cited by a client and never typed by a person: it is minted by the database
-- and only travels back to the console. Nothing references it by value except the audit
-- row's `detail`, which keeps the id and the name as they were when the rule fired.
CREATE TABLE moderation_rule (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text NOT NULL CHECK (btrim(name) <> ''),
    -- The needle. Length is capped here as well as in the store: matching runs on the
    -- ingest path, so a pattern that could be a novel is refused at the door, not after
    -- it has been compiled on every delivery.
    pattern      text NOT NULL CHECK (btrim(pattern) <> '' AND octet_length(pattern) <= 512),
    pattern_kind text NOT NULL CHECK (pattern_kind IN ('keyword', 'regex', 'domain')),
    -- Which side of the fence the rule watches: work arriving from other instances, work
    -- our own accounts publish, or both.
    scope        text NOT NULL DEFAULT 'inbound' CHECK (scope IN ('inbound', 'local', 'both')),
    action       text NOT NULL DEFAULT 'flag' CHECK (action IN ('flag', 'silence', 'suspend')),
    enabled      boolean NOT NULL DEFAULT true,
    -- The administrator who wrote it. Deleting that account does not delete the rule;
    -- the policy outlives the person who typed it.
    created_by   text REFERENCES account (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    -- How many posts this rule has matched. Written with every application, so "is this
    -- rule still doing anything?" is a read of one column, not a scan of the audit log.
    hits         bigint NOT NULL DEFAULT 0
);

-- The only read the hot path makes: enabled rules for one scope, oldest first so the cap
-- is deterministic (a rule that falls off the end does so in a stable order).
CREATE INDEX moderation_rule_scope_idx
    ON moderation_rule (scope, created_at, id)
    WHERE enabled;

-- The queue reads a rule by id when a report names one; the primary key covers it.
