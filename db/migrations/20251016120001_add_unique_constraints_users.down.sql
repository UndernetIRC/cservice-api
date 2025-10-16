-- Revert unique constraints on users table back to regular indexes

-- Drop the unique indexes
DROP INDEX IF EXISTS users_email_unique_idx;
DROP INDEX IF EXISTS users_username_unique_idx;

-- Recreate the original regular indexes
CREATE INDEX users_username_idx ON users(LOWER(user_name));
CREATE INDEX users_email_idx ON users(LOWER(email));
