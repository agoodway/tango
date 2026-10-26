-- Tango V04 Migration Rollback
-- Refuses pending consume operations before removing completion mode and token response metadata.
--
-- MANUAL EXECUTION NOTES:
-- If running this file directly with psql (outside of Ecto migrations), you must first
-- manually replace all instances of "$SCHEMA$" with your target schema name:
-- - For default schema: Replace "$SCHEMA$" with "public"
-- - For custom schema: Replace "$SCHEMA$" with your schema name (e.g., "oauth", "tenant_1")
-- After substitution, review the SQL and include the version marker below at
-- the end of the same reviewed input before executing it. The entire input must
-- succeed in one transaction, including the marker, when rolling back by hand.
-- Example for a reviewed input saved as v04_down_reviewed.sql:
--   psql --single-transaction --set=ON_ERROR_STOP=1 --file=- -d your_database < v04_down_reviewed.sql
-- Include this marker in that input, with the same target schema substitution:
--   COMMENT ON TABLE "$SCHEMA$".tango_providers IS 'Tango version=3';

DO $$
BEGIN
    LOCK TABLE "$SCHEMA$".tango_oauth_sessions, "$SCHEMA$".tango_authorizations
        IN ACCESS EXCLUSIVE MODE;
    IF EXISTS (
        SELECT 1 FROM "$SCHEMA$".tango_oauth_sessions
        WHERE completion_mode = 'consume' AND exchanged_at IS NULL AND expires_at > now()
    ) OR EXISTS (
        SELECT 1 FROM "$SCHEMA$".tango_authorizations
        WHERE completion_mode = 'consume' AND consumed_at IS NULL AND expires_at > now()
    ) THEN
        RAISE EXCEPTION 'Pending consume authorizations prevent V04 rollback';
    END IF;
END $$;

--SPLIT--

ALTER TABLE "$SCHEMA$".tango_oauth_sessions
    DROP CONSTRAINT IF EXISTS tango_oauth_sessions_consume_connection_check,
    DROP CONSTRAINT IF EXISTS tango_oauth_sessions_completion_mode_check,
    DROP COLUMN IF EXISTS completion_mode;

--SPLIT--

ALTER TABLE "$SCHEMA$".tango_authorizations
    DROP CONSTRAINT IF EXISTS tango_authorizations_consume_connection_check,
    DROP CONSTRAINT IF EXISTS tango_authorizations_completion_mode_check,
    DROP COLUMN IF EXISTS completion_mode;

--SPLIT--

ALTER TABLE "$SCHEMA$".tango_authorizations
    DROP CONSTRAINT IF EXISTS tango_authorizations_provider_data_check;

--SPLIT--

ALTER TABLE "$SCHEMA$".tango_authorizations
    DROP COLUMN IF EXISTS provider_data;
