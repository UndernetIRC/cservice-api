-- Add IP restrictions column to api_keys table
ALTER TABLE api_keys ADD COLUMN ip_restrictions JSONB DEFAULT '[]'::jsonb NOT NULL;

-- Add index for faster queries on ip_restrictions
CREATE INDEX idx_api_keys_ip_restrictions ON api_keys USING GIN (ip_restrictions);

-- Add comment for documentation
COMMENT ON COLUMN api_keys.ip_restrictions IS 'Array of CIDR ranges (IPv4/IPv6) allowed to use this API key. Empty array means no restrictions.';
