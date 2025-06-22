-- Add backup codes support to users table
-- backup_codes: JSON column to store encrypted backup codes
-- backup_codes_read: BOOLEAN to track if codes have been shown to user

ALTER TABLE users ADD COLUMN backup_codes JSON;
ALTER TABLE users ADD COLUMN backup_codes_read BOOLEAN DEFAULT FALSE;

-- Create index for efficient querying of backup_codes_read status
CREATE INDEX users_backup_codes_read_idx ON users(backup_codes_read);

-- Update column comment to reflect new structure
COMMENT ON COLUMN users.backup_codes IS 'JSON containing encrypted backup codes and metadata: {encrypted_backup_codes, generated_at, codes_remaining}';
