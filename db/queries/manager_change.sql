-- Manager Change SQL Queries
-- Based on legacy PHP implementation with optimizations

-- name: CheckExistingPendingRequests :many
-- Check for existing pending requests (managerchange.php:206,217)
SELECT id, channel_id, confirmed, change_type
FROM pending_mgrchange
WHERE channel_id = $1
  AND (confirmed = '1' OR confirmed = '3');

-- name: InsertManagerChangeRequest :one
-- Create pending manager change request (managerchange.php:327-328)
INSERT INTO pending_mgrchange (
    channel_id, manager_id, new_manager_id, change_type,
    opt_duration, reason, expiration, crc, confirmed, from_host
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, $9)
RETURNING id;

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
