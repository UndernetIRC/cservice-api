-- Remove unique constraints from pendingusers table

DROP INDEX IF EXISTS pendingusers_email_unique_idx;
DROP INDEX IF EXISTS pendingusers_username_unique_idx;
