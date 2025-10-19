-- Revert backup codes column comment to previous encryption-based description

COMMENT ON COLUMN users.backup_codes IS 'JSON containing encrypted backup codes and metadata: {encrypted_backup_codes, generated_at, codes_remaining}';
