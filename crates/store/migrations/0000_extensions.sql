-- Extensions must exist before the first migration that uses their types, and a migration
-- file is parsed as one statement: `CREATE EXTENSION` in the same file as `citext` columns
-- is too late for the parser. This file exists so a fresh database can be built by the
-- unprivileged application role, which is the only role a deployment usually has.

CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
