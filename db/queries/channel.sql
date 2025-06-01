-- name: SearchChannels :many
SELECT c.id, c.name, c.description, c.url, c.registered_ts as created_at,
       COUNT(l.user_id) as member_count
FROM channels c
LEFT JOIN levels l ON c.id = l.channel_id AND l.deleted = 0
WHERE c.name ILIKE $1
  AND c.deleted = 0
GROUP BY c.id, c.name, c.description, c.url, c.registered_ts
ORDER BY member_count DESC, c.name ASC
LIMIT $2 OFFSET $3;

-- name: SearchChannelsCount :one
SELECT COUNT(DISTINCT c.id) as total
FROM channels c
WHERE c.name ILIKE $1
  AND c.deleted = 0;

-- name: GetChannelByID :one
SELECT c.id, c.name, c.description, c.url, c.registered_ts as created_at,
       COUNT(l.user_id) as member_count
FROM channels c
LEFT JOIN levels l ON c.id = l.channel_id AND l.deleted = 0
WHERE c.id = $1
  AND c.deleted = 0
GROUP BY c.id, c.name, c.description, c.url, c.registered_ts;
