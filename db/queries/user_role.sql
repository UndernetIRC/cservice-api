-- name: AddUserRole :exec
INSERT INTO user_roles (user_id, role_id)
VALUES ($1, $2);

-- name: RemoveUserRole :exec
DELETE FROM user_roles
WHERE user_id = $1 AND role_id = $2;

-- name: ListUserRoles :many
SELECT r.*
FROM user_roles ur
INNER JOIN roles r
ON ur.role_id = r.id
WHERE ur.user_id = $1
ORDER BY r.id ASC;

-- name: AddUsersToRole :copyfrom
INSERT INTO user_roles (user_id, role_id, created_by)
VALUES ($1, $2, $3);

-- name: RemoveUsersFromRole :exec
DELETE FROM user_roles
WHERE user_id = ANY(@user_ids::INT4[]) AND role_id = @role_id;
