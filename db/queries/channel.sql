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

-- name: UpdateChannelSettings :one
UPDATE channels
SET description = $2, url = $3, last_updated = EXTRACT(EPOCH FROM NOW())::int
WHERE id = $1 AND deleted = 0
RETURNING id, name, description, url, registered_ts as created_at, last_updated;

-- name: GetChannelUserAccess :one
SELECT l.access, l.user_id, l.channel_id
FROM levels l
WHERE l.channel_id = $1 AND l.user_id = $2 AND l.deleted = 0;

-- name: CheckChannelExists :one
SELECT id, name, description, url
FROM channels
WHERE id = $1 AND deleted = 0;

-- name: GetChannelDetails :one
SELECT c.id, c.name, c.description, c.url, c.registered_ts as created_at, c.last_updated,
       COUNT(l.user_id) as member_count
FROM channels c
LEFT JOIN levels l ON c.id = l.channel_id AND l.deleted = 0
WHERE c.id = $1 AND c.deleted = 0
GROUP BY c.id, c.name, c.description, c.url, c.registered_ts, c.last_updated;

-- name: AddChannelMember :one
INSERT INTO levels (channel_id, user_id, access, flags, added, added_by, last_modif, last_modif_by, last_updated)
VALUES ($1, $2, $3, 0, EXTRACT(EPOCH FROM NOW())::int, $4, EXTRACT(EPOCH FROM NOW())::int, $4, EXTRACT(EPOCH FROM NOW())::int)
RETURNING channel_id, user_id, access, added;

-- name: CheckChannelMemberExists :one
SELECT channel_id, user_id, access
FROM levels
WHERE channel_id = $1 AND user_id = $2 AND deleted = 0;

-- name: GetChannelByName :one
SELECT id, name, description, url
FROM channels
WHERE name = $1 AND deleted = 0;

-- name: RemoveChannelMember :one
UPDATE levels
SET deleted = 1, last_modif = EXTRACT(EPOCH FROM NOW())::int, last_modif_by = $3, last_updated = EXTRACT(EPOCH FROM NOW())::int
WHERE channel_id = $1 AND user_id = $2 AND deleted = 0
RETURNING channel_id, user_id, access, last_modif;

-- name: GetChannelMembersByAccessLevel :many
SELECT user_id, access
FROM levels
WHERE channel_id = $1 AND access = $2 AND deleted = 0
ORDER BY user_id;

-- name: CountChannelOwners :one
SELECT COUNT(*) as owner_count
FROM levels
WHERE channel_id = $1 AND access = 500 AND deleted = 0;
