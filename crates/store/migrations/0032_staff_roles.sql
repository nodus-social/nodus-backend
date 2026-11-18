-- Permission was a boolean, so the console's moderator/administrator split had nowhere
-- to live: every grant was equally powerful. The role is the source of truth now.
--
-- `admin` stays, and stays in sync, because the OAuth grant check and a handful of
-- queries still read it as "is this account staff at all". Dropping it would be a
-- second migration in one change; mirroring it is one UPDATE inside each write.

ALTER TABLE account ADD COLUMN staff_role text NOT NULL DEFAULT 'none'
    CONSTRAINT account_staff_role_check CHECK (staff_role IN ('none', 'moderator', 'admin'));

-- Everyone who was an administrator keeps being one, and nobody silently loses access.
UPDATE account SET staff_role = 'admin' WHERE admin IS TRUE;

-- The staff list is small and asked for by name; a partial index keeps it cheap.
CREATE INDEX account_staff_role_idx ON account (staff_role) WHERE staff_role <> 'none';

-- A mirror that only one writer remembers to update is not a mirror. The trigger makes
-- "kept in sync" true at the storage layer: a writer that only knows the old boolean
-- (`UPDATE account SET admin = true`) still promotes the role, and a writer that sets the
-- role still sets the boolean. A statement that sets both is taken as already consistent.
CREATE FUNCTION account_staff_role_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.staff_role = 'none' AND NEW.admin THEN
            NEW.staff_role := 'admin';
        ELSIF NEW.admin <> (NEW.staff_role <> 'none') THEN
            NEW.admin := NEW.staff_role <> 'none';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.admin IS DISTINCT FROM OLD.admin
        AND NEW.staff_role IS NOT DISTINCT FROM OLD.staff_role THEN
        NEW.staff_role := CASE WHEN NEW.admin THEN 'admin' ELSE 'none' END;
    ELSIF NEW.staff_role IS DISTINCT FROM OLD.staff_role
        AND NEW.admin IS NOT DISTINCT FROM OLD.admin THEN
        NEW.admin := NEW.staff_role <> 'none';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER account_staff_role_sync BEFORE INSERT OR UPDATE ON account
    FOR EACH ROW EXECUTE FUNCTION account_staff_role_sync();
