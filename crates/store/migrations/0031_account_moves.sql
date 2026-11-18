-- A move is a redirect, not a deletion: the account and its statuses stay where they are,
-- and this column carries the actor the reader should follow instead.

ALTER TABLE account ADD COLUMN moved_to text;

-- The target actor's `alsoKnownAs`, kept so a Move can be checked against what the target
-- published without asking its server again on every delivery.

ALTER TABLE account ADD COLUMN also_known_as text[] NOT NULL DEFAULT '{}';
