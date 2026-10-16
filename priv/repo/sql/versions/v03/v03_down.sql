-- Tango V03 Migration Rollback
-- Removes authorization candidates before their session and connection fields.
--
-- MANUAL EXECUTION NOTES:
-- If running this file directly with psql (outside of Ecto migrations), you must first
-- manually replace all instances of "$SCHEMA$" with your target schema name:
-- - For default schema: Replace "$SCHEMA$" with "public"
-- - For custom schema: Replace "$SCHEMA$" with your schema name (e.g., "oauth", "tenant_1")
-- Example: sed 's/\$SCHEMA\$/public/g' v03_down.sql | psql -d your_database
--
-- When applying by hand, also restore the version marker:
--   COMMENT ON TABLE "$SCHEMA$".tango_providers IS 'Tango version=2';

DROP TABLE IF EXISTS "$SCHEMA$".tango_authorizations;

--SPLIT--

ALTER TABLE "$SCHEMA$".tango_oauth_sessions
    DROP COLUMN IF EXISTS exchanged_at,
    DROP COLUMN IF EXISTS oauth_client_id,
    DROP COLUMN IF EXISTS auth_params,
    DROP COLUMN IF EXISTS intent_reference,
    DROP COLUMN IF EXISTS completion_origin,
    DROP COLUMN IF EXISTS expected_subject,
    DROP COLUMN IF EXISTS expected_connection_id;

--SPLIT--

ALTER TABLE "$SCHEMA$".tango_connections
    DROP COLUMN IF EXISTS oauth_client_id,
    DROP COLUMN IF EXISTS account_subject;
