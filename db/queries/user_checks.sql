-- name: CheckUsernameExists :many
SELECT user_name
FROM users
WHERE lower(user_name) = lower(@username)
UNION ALL
SELECT user_name
FROM pendingusers
WHERE lower(user_name) = lower(@username);

-- name: CheckEmailExists :many
SELECT email
FROM users
WHERE lower(email) = lower(@email)
UNION ALL
SELECT email
FROM pendingusers
WHERE lower(email) = lower(@email);
