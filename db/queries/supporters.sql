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

-- name: CheckSupporterConcurrentSupports :one
-- Checks how many channels a supporter is currently supporting
SELECT COUNT(*) as support_count
FROM supporters s
INNER JOIN pending p ON s.channel_id = p.channel_id
INNER JOIN channels c ON s.channel_id = c.id
WHERE s.user_id = $1
  AND (p.status < 3 OR p.status = 8)
  AND c.registered_ts = 0;

-- name: CheckMultipleSupportersConcurrentSupports :many
-- Efficiently checks concurrent supports for multiple supporters at once
SELECT
  u.id,
  u.user_name,
  COUNT(s.channel_id) as support_count,
  CASE
    WHEN COUNT(s.channel_id) >= $2::int THEN true
    ELSE false
  END as exceeds_limit
FROM users u
LEFT JOIN supporters s ON u.id = s.user_id
LEFT JOIN pending p ON s.channel_id = p.channel_id
LEFT JOIN channels c ON s.channel_id = c.id
WHERE lower(u.user_name) = ANY(SELECT lower(unnest($1::text[])))
  AND (s.channel_id IS NULL OR ((p.status < 3 OR p.status = 8) AND c.registered_ts = 0))
GROUP BY u.id, u.user_name;
