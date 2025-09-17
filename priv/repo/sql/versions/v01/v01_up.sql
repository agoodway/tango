-- Tango V01 Migration - OAuth provider infrastructure
-- Establishes provider configurations, authentication sessions, token storage, and audit logging
--
-- MANUAL EXECUTION NOTES:
-- If running this file directly with psql (outside of Ecto migrations), you must first
-- manually replace all instances of "$SCHEMA$" with your target schema name:
-- - For default schema: Replace "$SCHEMA$" with "public"
-- - For custom schema: Replace "$SCHEMA$" with your schema name (e.g., "oauth", "tenant_1")
-- Example: sed 's/\$SCHEMA\$/public/g' v01_up.sql | psql -d your_database

-- Create custom schema if not using public
CREATE SCHEMA IF NOT EXISTS "$SCHEMA$";

--SPLIT--

-- Providers table stores OAuth provider configurations
CREATE TABLE IF NOT EXISTS "$SCHEMA$".tango_providers (
    id BIGSERIAL PRIMARY KEY,
    slug VARCHAR NOT NULL,
    name VARCHAR NOT NULL,
    config JSONB DEFAULT '{}',
    client_secret BYTEA,
    default_scopes TEXT[] DEFAULT '{}',
    active BOOLEAN DEFAULT true NOT NULL,
    metadata JSONB DEFAULT '{}',
    inserted_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

--SPLIT--

CREATE UNIQUE INDEX IF NOT EXISTS tango_providers_slug_index ON "$SCHEMA$".tango_providers (slug);

--SPLIT--

CREATE INDEX IF NOT EXISTS tango_providers_active_index ON "$SCHEMA$".tango_providers (active);

--SPLIT--

-- OAuth sessions table manages temporary OAuth authorization flows
CREATE TABLE IF NOT EXISTS "$SCHEMA$".tango_oauth_sessions (
    id BIGSERIAL PRIMARY KEY,
    provider_id BIGINT NOT NULL REFERENCES "$SCHEMA$".tango_providers(id) ON DELETE CASCADE,
    tenant_id VARCHAR NOT NULL,
    session_token VARCHAR NOT NULL,
    state VARCHAR NOT NULL,
    code_verifier VARCHAR,
    redirect_uri TEXT,
    scopes TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    inserted_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

--SPLIT--

CREATE UNIQUE INDEX IF NOT EXISTS tango_oauth_sessions_session_token_index ON "$SCHEMA$".tango_oauth_sessions (session_token);

--SPLIT--

CREATE UNIQUE INDEX IF NOT EXISTS tango_oauth_sessions_state_tenant_id_index ON "$SCHEMA$".tango_oauth_sessions (state, tenant_id);

--SPLIT--

CREATE INDEX IF NOT EXISTS tango_oauth_sessions_provider_id_index ON "$SCHEMA$".tango_oauth_sessions (provider_id);

--SPLIT--

CREATE INDEX IF NOT EXISTS tango_oauth_sessions_tenant_id_index ON "$SCHEMA$".tango_oauth_sessions (tenant_id);

--SPLIT--

CREATE INDEX IF NOT EXISTS tango_oauth_sessions_tenant_id_provider_id_index ON "$SCHEMA$".tango_oauth_sessions (tenant_id, provider_id);

--SPLIT--

CREATE INDEX IF NOT EXISTS tango_oauth_sessions_expires_at_index ON "$SCHEMA$".tango_oauth_sessions (expires_at);

--SPLIT--

CREATE INDEX IF NOT EXISTS tango_oauth_sessions_expires_at_tenant_id_index ON "$SCHEMA$".tango_oauth_sessions (expires_at, tenant_id);

--SPLIT--

-- Connections table stores active OAuth access tokens and refresh tokens
CREATE TABLE IF NOT EXISTS "$SCHEMA$".tango_connections (
    id BIGSERIAL PRIMARY KEY,
    provider_id BIGINT NOT NULL REFERENCES "$SCHEMA$".tango_providers(id) ON DELETE CASCADE,
    tenant_id VARCHAR NOT NULL,
    access_token BYTEA NOT NULL,
    refresh_token BYTEA,
    token_type VARCHAR DEFAULT 'bearer' NOT NULL,
    expires_at TIMESTAMP,
    granted_scopes TEXT[] DEFAULT '{}',
    raw_payload JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    status VARCHAR DEFAULT 'active' NOT NULL,
    last_used_at TIMESTAMP,
    refresh_attempts INTEGER DEFAULT 0 NOT NULL,
    last_refresh_failure TEXT,
    next_refresh_at TIMESTAMP,
    refresh_exhausted BOOLEAN DEFAULT false NOT NULL,
    auto_refresh_enabled BOOLEAN DEFAULT true NOT NULL,
    connection_config JSONB DEFAULT '{}' NOT NULL,
    inserted_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

--SPLIT--

CREATE INDEX IF NOT EXISTS tango_connections_tenant_id_index ON "$SCHEMA$".tango_connections (tenant_id);

--SPLIT--

CREATE INDEX IF NOT EXISTS tango_connections_tenant_id_provider_id_index ON "$SCHEMA$".tango_connections (tenant_id, provider_id);

--SPLIT--

CREATE INDEX IF NOT EXISTS tango_connections_tenant_id_status_index ON "$SCHEMA$".tango_connections (tenant_id, status);

--SPLIT--

CREATE INDEX IF NOT EXISTS tango_connections_tenant_id_expires_at_index ON "$SCHEMA$".tango_connections (tenant_id, expires_at);

--SPLIT--

CREATE INDEX IF NOT EXISTS tango_connections_tenant_id_last_used_at_index ON "$SCHEMA$".tango_connections (tenant_id, last_used_at);

--SPLIT--

CREATE INDEX IF NOT EXISTS tango_connections_tenant_id_status_expires_at_index ON "$SCHEMA$".tango_connections (tenant_id, status, expires_at);

--SPLIT--

CREATE UNIQUE INDEX IF NOT EXISTS tango_connections_provider_id_tenant_id_index ON "$SCHEMA$".tango_connections (provider_id, tenant_id) 
WHERE status = 'active';

--SPLIT--

-- Audit logs table tracks all OAuth operations for security and compliance
-- Immutable audit records - no updated_at field for security/compliance
CREATE TABLE IF NOT EXISTS "$SCHEMA$".tango_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    provider_id BIGINT REFERENCES "$SCHEMA$".tango_providers(id) ON DELETE CASCADE,
    connection_id BIGINT REFERENCES "$SCHEMA$".tango_connections(id) ON DELETE CASCADE,
    session_id VARCHAR,
    tenant_id VARCHAR NOT NULL,
    event_type VARCHAR NOT NULL,
    success BOOLEAN NOT NULL,
    error_code VARCHAR,
    event_data JSONB DEFAULT '{}',
    sensitive_data_hash VARCHAR,
    user_agent TEXT,
    ip_address VARCHAR,
    occurred_at TIMESTAMP NOT NULL,
    inserted_at TIMESTAMP NOT NULL
);

--SPLIT--

CREATE INDEX IF NOT EXISTS tango_audit_logs_provider_id_index ON "$SCHEMA$".tango_audit_logs (provider_id);

--SPLIT--

CREATE INDEX IF NOT EXISTS tango_audit_logs_connection_id_index ON "$SCHEMA$".tango_audit_logs (connection_id);

--SPLIT--

CREATE INDEX IF NOT EXISTS tango_audit_logs_tenant_id_index ON "$SCHEMA$".tango_audit_logs (tenant_id);

--SPLIT--

CREATE INDEX IF NOT EXISTS tango_audit_logs_event_type_index ON "$SCHEMA$".tango_audit_logs (event_type);

--SPLIT--

CREATE INDEX IF NOT EXISTS tango_audit_logs_occurred_at_index ON "$SCHEMA$".tango_audit_logs (occurred_at);

--SPLIT--

CREATE INDEX IF NOT EXISTS tango_audit_logs_tenant_id_event_type_occurred_at_index ON "$SCHEMA$".tango_audit_logs (tenant_id, event_type, occurred_at);

--SPLIT--

CREATE INDEX IF NOT EXISTS tango_audit_logs_tenant_id_provider_id_occurred_at_index ON "$SCHEMA$".tango_audit_logs (tenant_id, provider_id, occurred_at);