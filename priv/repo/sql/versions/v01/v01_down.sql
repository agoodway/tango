-- Tango V01 Migration Rollback
-- Removes OAuth infrastructure tables and supporting functions
--
-- MANUAL EXECUTION NOTES:
-- If running this file directly with psql (outside of Ecto migrations), you must first
-- manually replace all instances of "$SCHEMA$" with your target schema name:
-- - For default schema: Replace "$SCHEMA$" with "public"
-- - For custom schema: Replace "$SCHEMA$" with your schema name (e.g., "oauth", "tenant_1")
-- Example: sed 's/\$SCHEMA\$/public/g' v01_down.sql | psql -d your_database

-- Remove tables in dependency order to avoid constraint violations
DROP TABLE IF EXISTS "$SCHEMA$".tango_audit_logs CASCADE;

--SPLIT--

DROP TABLE IF EXISTS "$SCHEMA$".tango_connections CASCADE;

--SPLIT--

DROP TABLE IF EXISTS "$SCHEMA$".tango_oauth_sessions CASCADE;

--SPLIT--

DROP TABLE IF EXISTS "$SCHEMA$".tango_providers CASCADE;

--SPLIT--

-- Remove custom schema when empty (fails if other objects exist)
DO $$
BEGIN
    IF '$SCHEMA$' != 'public' THEN
        EXECUTE 'DROP SCHEMA IF EXISTS "$SCHEMA$" CASCADE';
    END IF;
END
$$;