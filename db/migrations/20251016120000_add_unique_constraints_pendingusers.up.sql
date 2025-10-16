-- Add unique constraints to pendingusers table to prevent duplicate registrations
-- These constraints are case-insensitive using a unique index with LOWER()

-- Create unique index on username (case-insensitive)
CREATE UNIQUE INDEX pendingusers_username_unique_idx ON pendingusers(LOWER(user_name));

-- Create unique index on email (case-insensitive)
CREATE UNIQUE INDEX pendingusers_email_unique_idx ON pendingusers(LOWER(email));
