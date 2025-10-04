-- Drop API keys table and all associated objects
DROP INDEX IF EXISTS api_keys_expires_at_idx;
DROP INDEX IF EXISTS api_keys_created_by_idx;
DROP INDEX IF EXISTS api_keys_key_hash_idx;
DROP TABLE IF EXISTS api_keys;
