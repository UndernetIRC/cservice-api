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

-- name: AddMultipleUserRoles :exec
INSERT INTO user_roles (user_id, role_id)
SELECT $1, id
FROM roles
WHERE name = ANY($2);

-- name: RemoveMultipleUserRoles :exec
DELETE FROM user_roles
WHERE user_id = $1 AND role_id IN (
    SELECT id
    FROM roles
    WHERE name = ANY($2)
);
