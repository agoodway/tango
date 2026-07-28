-- Tango V02 Migration
-- Records provider rejections of stored credentials on a connection
--
-- MANUAL EXECUTION NOTES:
-- If running this file directly with psql (outside of Ecto migrations), you must first
-- manually replace all instances of "$SCHEMA$" with your target schema name:
-- - For default schema: Replace "$SCHEMA$" with "public"
-- - For custom schema: Replace "$SCHEMA$" with your schema name (e.g., "oauth", "tenant_1")
-- Example: sed 's/\$SCHEMA\$/public/g' v02_up.sql | psql -d your_database
--
-- When applying by hand, also stamp the version marker EctoEvolver would have
-- written, so Tango.Migration.migrated_version/1 agrees with the schema:
--   COMMENT ON TABLE "$SCHEMA$".tango_providers IS 'Tango version=2';

ALTER TABLE "$SCHEMA$".tango_connections
    ADD COLUMN IF NOT EXISTS auth_failures INTEGER DEFAULT 0 NOT NULL;

--SPLIT--

ALTER TABLE "$SCHEMA$".tango_connections
    ADD COLUMN IF NOT EXISTS last_auth_failure TEXT;

--SPLIT--

COMMENT ON COLUMN "$SCHEMA$".tango_connections.auth_failures IS
    'Consecutive rejections of these credentials by the provider (HTTP 401/403), reported by the consumer. Distinct from refresh_attempts: a connection with no refresh token and no expiry is never eligible for refresh, so its credentials can be rejected indefinitely while refresh_attempts stays at zero.';
