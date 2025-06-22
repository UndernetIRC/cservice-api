-- Rollback backup codes support from users table

DROP INDEX IF EXISTS users_backup_codes_read_idx;
ALTER TABLE users DROP COLUMN IF EXISTS backup_codes_read;
ALTER TABLE users DROP COLUMN IF EXISTS backup_codes;