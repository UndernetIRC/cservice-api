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