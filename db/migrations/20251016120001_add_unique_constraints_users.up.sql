-- Add unique constraints to users table to prevent duplicate user accounts
-- Drop existing non-unique indexes and replace with unique indexes

-- Drop the existing regular indexes
DROP INDEX IF EXISTS users_username_idx;
DROP INDEX IF EXISTS users_email_idx;

-- Create unique indexes on username and email (case-insensitive)
CREATE UNIQUE INDEX users_username_unique_idx ON users(LOWER(user_name));
CREATE UNIQUE INDEX users_email_unique_idx ON users(LOWER(email));
