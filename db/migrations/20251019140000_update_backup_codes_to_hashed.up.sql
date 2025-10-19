-- Update backup codes column comment to reflect bcrypt hashing instead of encryption
-- This migration updates the documentation to match the refactored implementation
-- that uses bcrypt hashing instead of AES encryption for better security
-- Note: Field name is generic 'backup_codes' to allow future implementation changes

COMMENT ON COLUMN users.backup_codes IS 'JSON containing backup codes and metadata: {backup_codes, generated_at, codes_remaining}. Backup codes are bcrypt-hashed for security.';
