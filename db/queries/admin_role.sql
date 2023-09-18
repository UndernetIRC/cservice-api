-- name: CreateRole :one
INSERT INTO roles (name, description, created_by, created_at)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetRoleByName :one
SELECT *
FROM roles
WHERE lower(name) = lower(sqlc.arg(name)) LIMIT 1;

-- name: GetRoleByID :one
SELECT *
FROM roles
WHERE id = $1 LIMIT 1;

-- name: ListRoles :many
SELECT *
FROM roles
ORDER BY id ASC;

-- name: UpdateRole :exec
UPDATE roles
SET name = $1, description = $2, updated_by = $3, updated_at = $4
WHERE id = $5;

-- name: DeleteRole :exec
DELETE FROM roles
WHERE id = $1;
