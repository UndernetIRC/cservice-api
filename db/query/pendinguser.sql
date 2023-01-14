-- name: CreatePendingUser :one
INSERT INTO pendingusers (user_name, cookie, expire, email, language, question_id, verificationdata, poster_ip)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING cookie;

-- name: DeletePendingUserByCookie :exec
DELETE FROM pendingusers
WHERE cookie = $1;

-- name: ListPendingUsers :many
SELECT * FROM pendingusers
ORDER BY expire DESC;
