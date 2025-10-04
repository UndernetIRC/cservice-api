-- Add API keys table for service-to-service authentication
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_by INT4 NOT NULL REFERENCES users(id),
    created_at INT4 NOT NULL,
    last_used_at INT4,
    expires_at INT4,
    last_updated INT4 NOT NULL,
    deleted INT2 DEFAULT 0
);

-- Index for fast lookups during authentication
CREATE INDEX api_keys_key_hash_idx ON api_keys(key_hash) WHERE deleted = 0;

-- Index for listing keys by creator
CREATE INDEX api_keys_created_by_idx ON api_keys(created_by) WHERE deleted = 0;

-- Index for expired key cleanup
CREATE INDEX api_keys_expires_at_idx ON api_keys(expires_at) WHERE deleted = 0;

-- Table and column comments for documentation
COMMENT ON TABLE api_keys IS 'Service-to-service authentication keys with scoped permissions';
COMMENT ON COLUMN api_keys.key_hash IS 'SHA-256 hash of the API key (plain key never stored)';
COMMENT ON COLUMN api_keys.scopes IS 'JSON array of permission scopes (e.g., ["channels:read", "users:write"])';
COMMENT ON COLUMN api_keys.deleted IS 'Soft delete flag: 0=active, 1=deleted';
