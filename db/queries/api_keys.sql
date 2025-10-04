-- name: CreateAPIKey :one
INSERT INTO api_keys (name, description, key_hash, scopes, created_by, created_at, last_updated)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetAPIKeyByHash :one
SELECT * FROM api_keys
WHERE key_hash = $1 AND deleted = 0
LIMIT 1;

-- name: ListAPIKeys :many
SELECT * FROM api_keys
WHERE deleted = 0
ORDER BY created_at DESC;

-- name: GetAPIKey :one
SELECT * FROM api_keys
WHERE id = $1 AND deleted = 0;

-- name: UpdateAPIKeyScopes :exec
UPDATE api_keys
SET scopes = $2, last_updated = $3
WHERE id = $1 AND deleted = 0;

-- name: UpdateAPIKeyLastUsed :exec
UPDATE api_keys
SET last_used_at = $2
WHERE id = $1 AND deleted = 0;

-- name: DeleteAPIKey :exec
UPDATE api_keys
SET deleted = 1, last_updated = $2
WHERE id = $1;

-- name: GetAPIKeysExpiringSoon :many
SELECT * FROM api_keys
WHERE deleted = 0
  AND expires_at IS NOT NULL
  AND expires_at > 0
  AND expires_at <= $1
ORDER BY expires_at ASC;
