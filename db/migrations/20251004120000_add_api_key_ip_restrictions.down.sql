-- Remove IP restrictions column from api_keys table
DROP INDEX IF EXISTS idx_api_keys_ip_restrictions;
ALTER TABLE api_keys DROP COLUMN IF EXISTS ip_restrictions;
