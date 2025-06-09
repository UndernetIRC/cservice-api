-- Supporters table queries for channel registration

-- name: CreateChannelSupporter :exec
-- Adds a supporter to a pending channel registration  
INSERT INTO supporters (
  channel_id,
  user_id,
  support,
  join_count,
  last_updated
) VALUES (
  $1, $2, 'Y', 0, EXTRACT(EPOCH FROM NOW())::int
);

-- name: DeleteChannelSupporters :exec
-- Removes all supporters for a pending channel
DELETE FROM supporters
WHERE channel_id = $1;

-- name: DeleteSpecificChannelSupporter :exec
-- Removes a specific supporter from a pending channel
DELETE FROM supporters
WHERE channel_id = $1 AND user_id = $2;