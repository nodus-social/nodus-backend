-- Instance rules become the document a report is actually about.
--
-- 0024 introduced `instance_rule` as a bare list (id text, text, hint, ord) with no
-- management surface. This migration makes a rule's position a first-class, unique,
-- contiguous column (`ordinal`), records when a rule was written and last changed, and
-- states the invariant the admin surface relies on: two rules can never share a
-- position.
--
-- Ids stay text, like every other id in this schema (a lowercase ULID), because
-- `report.rule_ids` (0026) already stores text ids that a client may have read from the
-- public endpoint; converting both to uuid would have to invent new ids for existing
-- reports and would lose the citation it is meant to preserve.

ALTER TABLE instance_rule RENAME COLUMN ord TO ordinal;
ALTER TABLE instance_rule ALTER COLUMN ordinal DROP DEFAULT;
ALTER TABLE instance_rule ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE instance_rule ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();

-- Rows written before the constraint may share a position. Renumber them in the order
-- they were already shown, so the list a reader saw yesterday is the list it sees today.
WITH ranked AS (
    SELECT id, (row_number() OVER (ORDER BY ordinal, id) - 1)::int AS position
      FROM instance_rule
)
UPDATE instance_rule AS rule
   SET ordinal = ranked.position
  FROM ranked
 WHERE rule.id = ranked.id;

ALTER TABLE instance_rule
    ADD CONSTRAINT instance_rule_ordinal_key UNIQUE (ordinal);
ALTER TABLE instance_rule
    ADD CONSTRAINT instance_rule_ordinal_nonnegative CHECK (ordinal >= 0);

-- The report keeps the ids it cited even after a rule is deleted: the history is the
-- point, and the moderation payload marks which cited ids no longer resolve. Nothing to
-- add here — `report.rule_ids` already exists as text[] from 0026 — but the invariant is
-- now exercised by admin CRUD, so it is stated where someone editing the schema reads it.
