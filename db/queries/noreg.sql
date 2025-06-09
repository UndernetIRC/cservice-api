-- NOREG table queries for checking user restrictions

-- name: CheckUserNoregStatus :one
-- Checks if a user has NOREG status
SELECT COUNT(*) > 0 as is_noreg
FROM noreg 
WHERE (lower(user_name) = lower($1) OR $1 = '')
  AND (expire_time IS NULL OR expire_time > EXTRACT(EPOCH FROM NOW())::int);