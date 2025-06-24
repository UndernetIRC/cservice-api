-- Manager Change SQL Queries
-- Based on legacy PHP implementation with optimizations

-- name: CheckUserChannelOwnership :one
-- Check if user has level 500 access on channel (managerchange.php:362)
SELECT c.name, c.id, c.registered_ts
FROM channels c
INNER JOIN levels l ON l.channel_id = c.id
WHERE l.user_id = $1
  AND l.access = 500
  AND c.id = $2
  AND c.id > 1
  AND c.registered_ts > 0
  AND c.deleted = 0
  AND l.deleted = 0;

-- name: GetUserByUsername :one
-- Validate new manager exists (managerchange.php:169)
SELECT id, email, user_name, signup_ts
FROM users
WHERE lower(user_name) = lower($1);

-- name: CheckChannelExistsAndRegistered :one
-- Validate channel exists and is registered (managerchange.php:197)
SELECT id, name, registered_ts
FROM channels
WHERE id = $1
  AND registered_ts > 0
  AND deleted = 0;

-- name: CheckExistingPendingRequests :many
-- Check for existing pending requests (managerchange.php:206,217)
SELECT id, channel_id, confirmed, change_type
FROM pending_mgrchange
WHERE channel_id = $1
  AND (confirmed = '1' OR confirmed = '3');

-- name: CheckNewManagerChannelAccess :one
-- Check new manager has level 499 on channel (managerchange.php:433)
SELECT u.user_name, u.id, u.signup_ts
FROM users u
INNER JOIN levels l ON u.id = l.user_id
LEFT JOIN users_lastseen ul ON u.id = ul.user_id
WHERE l.channel_id = $1
  AND l.access = 499
  AND u.id = $2
  AND l.deleted = 0
  AND ul.last_seen > (EXTRACT(EPOCH FROM NOW())::int - 86400*20);

-- name: CheckUserOwnsOtherChannels :one
-- Check if user already owns other channels (managerchange.php:443)
SELECT EXISTS(
  SELECT 1
  FROM users u
  INNER JOIN levels l ON u.id = l.user_id
  INNER JOIN channels c ON c.id = l.channel_id
  WHERE u.id = $1
    AND l.access = 500
    AND c.registered_ts > 0
    AND c.deleted = 0
    AND l.deleted = 0
) as owns_channels;

-- name: CheckChannelSingleManager :one
-- Ensure channel has only one manager (managerchange.php:295)
SELECT COUNT(*) as manager_count
FROM channels c
INNER JOIN levels l ON c.id = l.channel_id
WHERE c.id = $1
  AND l.access = 500
  AND c.deleted = 0
  AND l.deleted = 0;

-- name: CheckUserCooldownStatus :one
-- Check user form submission cooldown status
SELECT post_forms, verificationdata, email
FROM users
WHERE id = $1;

-- name: InsertManagerChangeRequest :one
-- Create pending manager change request (managerchange.php:327-328)
INSERT INTO pending_mgrchange (
    channel_id, manager_id, new_manager_id, change_type,
    opt_duration, reason, expiration, crc, confirmed, from_host
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, $9)
RETURNING id;

-- name: UpdateUserCooldown :exec
-- Set user form submission cooldown (managerchange.php:352)
UPDATE users
SET post_forms = (EXTRACT(EPOCH FROM NOW())::int + $2)
WHERE id = $1;

-- name: CleanupExpiredManagerChangeRequests :exec
-- Clean up expired unconfirmed requests (confirm_mgrchange.php:16)
DELETE FROM pending_mgrchange
WHERE expiration < EXTRACT(EPOCH FROM NOW())::int
  AND confirmed = '0';

-- name: GetManagerChangeRequestByToken :one
-- Validate confirmation token (confirm_mgrchange.php:17)
SELECT pm.*, c.name as channel_name
FROM pending_mgrchange pm
INNER JOIN channels c ON c.id = pm.channel_id
WHERE pm.crc = $1
  AND pm.expiration >= EXTRACT(EPOCH FROM NOW())::int
  AND pm.confirmed = '0'
  AND c.deleted = 0;

-- name: ConfirmManagerChangeRequest :exec
-- Mark request as confirmed (confirm_mgrchange.php:25)
UPDATE pending_mgrchange
SET confirmed = '1'
WHERE crc = $1
  AND confirmed = '0';

-- name: GetManagerChangeRequestStatus :one
-- Get status of pending manager change requests for a channel
SELECT pm.id, pm.channel_id, pm.change_type, pm.confirmed,
       pm.expiration, pm.reason, pm.opt_duration,
       u.user_name as new_manager_username
FROM pending_mgrchange pm
INNER JOIN users u ON u.id = pm.new_manager_id
WHERE pm.channel_id = $1
  AND pm.confirmed IN ('0', '1')
ORDER BY pm.id DESC
LIMIT 1;
