-- Tango V04 Migration
-- Retains configured, non-secret token response fields on staged authorization candidates.
--
-- MANUAL EXECUTION NOTES:
-- If running this file directly with psql (outside of Ecto migrations), you must first
-- manually replace all instances of "$SCHEMA$" with your target schema name:
-- - For default schema: Replace "$SCHEMA$" with "public"
-- - For custom schema: Replace "$SCHEMA$" with your schema name (e.g., "oauth", "tenant_1")
-- Example: sed 's/\$SCHEMA\$/public/g' v04_up.sql | psql -d your_database
--
-- When applying by hand, also stamp the version marker EctoEvolver would have
-- written, so Tango.Migration.migrated_version/1 agrees with the schema:
--   COMMENT ON TABLE "$SCHEMA$".tango_providers IS 'Tango version=4';

ALTER TABLE "$SCHEMA$".tango_authorizations
    ADD COLUMN IF NOT EXISTS provider_data JSONB NOT NULL DEFAULT '{}';

--SPLIT--

ALTER TABLE "$SCHEMA$".tango_authorizations
    ADD CONSTRAINT tango_authorizations_provider_data_check
        CHECK (jsonb_typeof(provider_data) = 'object');
