-- NOREG table queries for checking user restrictions

-- name: CheckUserNoregStatus :one
-- Checks if a user has NOREG status
SELECT COUNT(*) > 0 as is_noreg
FROM noreg
WHERE (lower(user_name) = lower($1) OR $1 = '')
  AND (expire_time IS NULL OR expire_time > EXTRACT(EPOCH FROM NOW())::int);

-- name: CheckSupporterNoregStatus :one
-- Checks if a supporter has NOREG status
SELECT COUNT(*) > 0 as is_noreg
FROM noreg
WHERE lower(user_name) = lower($1)
  AND (never_reg = 1 OR for_review = 1 OR expire_time > EXTRACT(EPOCH FROM NOW())::int);

-- name: CheckMultipleSupportersNoregStatus :many
-- Efficiently checks NOREG status for multiple supporters at once
SELECT
  u.user_name,
  CASE
    WHEN n.user_name IS NOT NULL THEN true
    ELSE false
  END as is_noreg
FROM (SELECT unnest($1::text[]) as user_name) u
LEFT JOIN noreg n ON lower(u.user_name) = lower(n.user_name)
  AND (n.never_reg = 1 OR n.for_review = 1 OR n.expire_time > EXTRACT(EPOCH FROM NOW())::int);

-- name: CheckChannelNoregStatus :one
-- Checks if a channel name is in NOREG
SELECT
  COUNT(*) > 0 as is_noreg,
  COALESCE(MAX(type), 0) as noreg_type,
  COALESCE(MAX(reason), '') as reason,
  COALESCE(MAX(never_reg), 0) as never_reg,
  COALESCE(MAX(expire_time), 0) as expire_time
FROM noreg
WHERE lower(channel_name) = lower($1);

-- name: GetUserNoregDetails :one
-- Gets detailed NOREG information for a user
SELECT
  type,
  reason,
  never_reg,
  expire_time
FROM noreg
WHERE lower(user_name) = lower($1)
  AND (never_reg = 1 OR for_review = 1 OR expire_time > EXTRACT(EPOCH FROM NOW())::int)
LIMIT 1;

-- name: CleanupExpiredNoreg :exec
-- Removes expired NOREG entries (matches PHP cleanup)
DELETE FROM noreg
WHERE never_reg = 0
  AND for_review = 0
  AND expire_time < EXTRACT(EPOCH FROM NOW())::int;
