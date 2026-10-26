-- Tango V04 Migration
-- Retains token response metadata and binds the selected authorization completion mode.
--
-- MANUAL EXECUTION NOTES:
-- If running this file directly with psql (outside of Ecto migrations), you must first
-- manually replace all instances of "$SCHEMA$" with your target schema name:
-- - For default schema: Replace "$SCHEMA$" with "public"
-- - For custom schema: Replace "$SCHEMA$" with your schema name (e.g., "oauth", "tenant_1")
-- After substitution, review the SQL and include the version marker below at
-- the end of the same reviewed input before executing it. The entire input must
-- succeed in one transaction, including the marker, when applying by hand.
-- Example for a reviewed input saved as v04_up_reviewed.sql:
--   psql --single-transaction --set=ON_ERROR_STOP=1 --file=- -d your_database < v04_up_reviewed.sql
-- Include this marker in that input, with the same target schema substitution:
--   COMMENT ON TABLE "$SCHEMA$".tango_providers IS 'Tango version=4';

ALTER TABLE "$SCHEMA$".tango_authorizations
    ADD COLUMN IF NOT EXISTS provider_data JSONB NOT NULL DEFAULT '{}';

--SPLIT--

ALTER TABLE "$SCHEMA$".tango_authorizations
    ADD CONSTRAINT tango_authorizations_provider_data_check
        CHECK (jsonb_typeof(provider_data) = 'object');

--SPLIT--

ALTER TABLE "$SCHEMA$".tango_oauth_sessions
    ADD COLUMN completion_mode TEXT NOT NULL DEFAULT 'connection',
    ADD CONSTRAINT tango_oauth_sessions_completion_mode_check
        CHECK (completion_mode IN ('connection', 'consume')),
    ADD CONSTRAINT tango_oauth_sessions_consume_connection_check
        CHECK (completion_mode <> 'consume' OR expected_connection_id IS NULL);

--SPLIT--

ALTER TABLE "$SCHEMA$".tango_authorizations
    ADD COLUMN completion_mode TEXT NOT NULL DEFAULT 'connection',
    ADD CONSTRAINT tango_authorizations_completion_mode_check
        CHECK (completion_mode IN ('connection', 'consume')),
    ADD CONSTRAINT tango_authorizations_consume_connection_check
        CHECK (completion_mode <> 'consume' OR
            (expected_connection_id IS NULL AND verified_connection_id IS NULL));
