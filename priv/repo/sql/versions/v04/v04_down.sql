-- Tango V04 Migration Rollback
-- Removes retained token response fields from staged authorization candidates.
--
-- MANUAL EXECUTION NOTES:
-- If running this file directly with psql (outside of Ecto migrations), you must first
-- manually replace all instances of "$SCHEMA$" with your target schema name:
-- - For default schema: Replace "$SCHEMA$" with "public"
-- - For custom schema: Replace "$SCHEMA$" with your schema name (e.g., "oauth", "tenant_1")
-- Example: sed 's/\$SCHEMA\$/public/g' v04_down.sql | psql -d your_database
--
-- When applying by hand, also restore the version marker:
--   COMMENT ON TABLE "$SCHEMA$".tango_providers IS 'Tango version=3';

ALTER TABLE "$SCHEMA$".tango_authorizations
    DROP CONSTRAINT IF EXISTS tango_authorizations_provider_data_check;

--SPLIT--

ALTER TABLE "$SCHEMA$".tango_authorizations
    DROP COLUMN IF EXISTS provider_data;
