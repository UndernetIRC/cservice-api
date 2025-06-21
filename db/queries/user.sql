-- name: CreateUser :one
INSERT INTO users (user_name, password, flags, email, last_updated, last_updated_by, language_id, question_id, verificationdata, post_forms, signup_ts, signup_ip, maxlogins)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING *;

-- name: GetUser :one
SELECT u.*, ul.last_seen, l.code as language_code, l.name as language_name
FROM users u
       INNER JOIN users_lastseen ul ON u.id = ul.user_id
       INNER JOIN languages l ON u.language_id = l.id
WHERE CASE WHEN LENGTH(@username::text) != 0 THEN  lower(u.user_name) = lower(@username) ELSE true END
  AND CASE WHEN LENGTH(@email::text) != 0 THEN lower(u.email) = lower(@email) ELSE true END
  AND CASE WHEN @id::int4 > 0 THEN u.id = @id ELSE true END
LIMIT 1;

-- name: GetUserChannels :many
SELECT c.name, l.channel_id, l.user_id, l.access, l.flags, l.last_modif, l.suspend_expires, l.suspend_by
FROM levels l
INNER JOIN channels c
ON l.channel_id = c.id
WHERE l.user_id = $1;

-- name: GetUsersByUsernames :many
SELECT u.*, ul.last_seen, l.code as language_code, l.name as language_name
FROM users u
INNER JOIN users_lastseen ul
ON u.id = ul.user_id
INNER JOIN languages l
ON u.language_id = l.id
WHERE u.user_name ILIKE ANY(@userIDs::VARCHAR[]);

-- name: GetAdminLevel :one
SELECT l.access, l.suspend_expires
FROM channels c
  INNER JOIN levels l
    ON c.id = l.channel_id
WHERE c.name = '*' AND l.user_id=$1;

-- name: UpdateUserPassword :exec
UPDATE users
SET password = $2, last_updated = $3, last_updated_by = $4
WHERE id = $1;

-- name: UpdateUserTotpKey :exec
UPDATE users
SET totp_key = $2, last_updated = $3, last_updated_by = $4
WHERE id = $1;

-- name: UpdateUserFlags :exec
UPDATE users
SET flags = $2, last_updated = $3, last_updated_by = $4
WHERE id = $1;

-- name: GetUserChannelMemberships :many
SELECT l.channel_id, c.name as channel_name, l.access as access_level, l.added as joined_at,
       (SELECT COUNT(*) FROM levels WHERE channel_id = l.channel_id AND deleted = 0) as member_count
FROM levels l
INNER JOIN channels c ON l.channel_id = c.id
WHERE l.user_id = $1 AND l.deleted = 0 AND c.deleted = 0
ORDER BY l.access DESC, c.name ASC;

-- Channel Registration related user queries

-- name: GetUserChannelLimit :one
-- Gets the channel limit for a user based on their flags
SELECT
  CASE
    WHEN u.flags & 1 > 0 THEN $2::int -- Admin limit
    WHEN u.flags & 2 > 0 THEN $3::int -- Supporter limit
    ELSE $4::int                       -- Regular user limit
  END as channel_limit
FROM users u
WHERE u.id = $1;

-- name: GetSupportersByUsernames :many
-- Gets all supporter information in one query for efficient validation
-- This replaces multiple individual supporter validation queries
SELECT
  u.id,
  u.user_name,
  u.flags,
  u.email,
  u.signup_ts,
  ul.last_seen,
  -- Age validation
  CASE
    WHEN u.signup_ts IS NULL THEN false
    WHEN (EXTRACT(EPOCH FROM NOW())::int - u.signup_ts) / 86400 >= $2::int THEN true
    ELSE false
  END as is_old_enough,
  COALESCE((EXTRACT(EPOCH FROM NOW())::int - u.signup_ts) / 86400, 0) as days_old,
  -- Fraud flag check
  (u.flags & 8) > 0 as has_fraud_flag
FROM users u
INNER JOIN users_lastseen ul ON u.id = ul.user_id
WHERE lower(u.user_name) = ANY(SELECT lower(unnest($1::text[])));

-- name: UpdateUserLastSeen :exec
-- Updates user's last seen timestamp (used for instant registration)
UPDATE users_lastseen
SET last_updated = EXTRACT(EPOCH FROM NOW())::int,
    last_seen = EXTRACT(EPOCH FROM NOW())::int
WHERE user_id = $1;
