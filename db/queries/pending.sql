-- Pending table queries for channel registration

-- name: GetUserPendingRegistrations :one
-- Returns the count of pending channel registrations for a user
SELECT COUNT(*) as pending_count
FROM pending
WHERE manager_id = $1;

-- name: CreatePendingChannel :one
-- Creates a new pending channel registration
INSERT INTO pending (
  channel_id,
  manager_id,
  created_ts,
  check_start_ts,
  status,
  managername,
  description,
  last_updated
) VALUES (
  $1, $2, EXTRACT(EPOCH FROM NOW())::int, EXTRACT(EPOCH FROM NOW())::int,
  0, $3, $4, EXTRACT(EPOCH FROM NOW())::int
) RETURNING channel_id, manager_id, created_ts;

-- name: UpdatePendingChannelStatus :one
-- Updates the status of a pending channel registration
UPDATE pending
SET status = $2,
    decision_ts = EXTRACT(EPOCH FROM NOW())::int,
    decision = $3,
    reviewed = 'Y',
    reviewed_by_id = $4,
    last_updated = EXTRACT(EPOCH FROM NOW())::int
WHERE channel_id = $1
RETURNING channel_id, manager_id, status, decision_ts;

-- name: UpdatePendingChannelDescription :exec
-- Updates the description of a pending channel registration
UPDATE pending
SET description = $2,
    last_updated = EXTRACT(EPOCH FROM NOW())::int
WHERE channel_id = $1;

-- name: DeletePendingChannel :exec
-- Removes a pending channel registration
DELETE FROM pending
WHERE channel_id = $1;

-- name: CheckPendingChannelNameConflict :one
-- Checks if there's already a pending registration for this channel name
SELECT
  p.created_ts,
  p.manager_id,
  u.user_name as manager_name
FROM pending p
INNER JOIN channels c ON p.channel_id = c.id
INNER JOIN users u ON p.manager_id = u.id
WHERE lower(c.name) = lower($1)
  AND (p.status < 3 OR p.status = 8)
  AND c.registered_ts = 0
LIMIT 1;

-- name: CreateInstantRegistration :one
-- Creates an instant registration (when no supporters required)
INSERT INTO pending (
  channel_id,
  manager_id,
  created_ts,
  check_start_ts,
  status,
  decision_ts,
  decision,
  managername,
  description,
  reg_acknowledged,
  last_updated
) VALUES (
  $1, $2, EXTRACT(EPOCH FROM NOW())::int, 0, 3,
  EXTRACT(EPOCH FROM NOW())::int, '** INSTANT REGISTRATION **',
  $3, $4, 'Y', EXTRACT(EPOCH FROM NOW())::int
) RETURNING channel_id, manager_id, created_ts;
