-- A peer retries an activity when it never sees our answer, so a `Flag` carries its id into
-- the report it opened: the retry finds the id taken and does not open a second report.
ALTER TABLE report ADD COLUMN activity_uri text UNIQUE;
