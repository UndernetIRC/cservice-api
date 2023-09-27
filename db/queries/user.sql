-- name: CreateUser :one
INSERT INTO users (user_name, password, flags, email, last_updated, last_updated_by, language_id, question_id, verificationdata, post_forms, signup_ts, signup_ip, maxlogins)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING *;

-- name: GetUserByUsername :one
SELECT *
FROM users
WHERE lower(user_name) = lower(@username) LIMIT 1;

-- name: GetUserByEmail :one
SELECT *
FROM users
WHERE lower(email) = lower(@email) LIMIT 1;

-- name: GetUserByID :one
SELECT u.*, ul.last_seen, l.code as language_code, l.name as language_name
FROM users u
INNER JOIN users_lastseen ul ON u.id = ul.user_id
INNER JOIN languages l ON u.language_id = l.id
WHERE u.id = $1 LIMIT 1;

-- name: GetUser :one
SELECT u.*, ul.last_seen, l.code as language_code, l.name as language_name
FROM users u
       INNER JOIN users_lastseen ul ON u.id = ul.user_id
       INNER JOIN languages l ON u.language_id = l.id
WHERE CASE WHEN LENGTH(@username::text) != 0 THEN  lower(u.user_name) = lower(@username) ELSE true END
  AND CASE WHEN LENGTH(@email::text) != 0 THEN lower(u.email) = lower(@email) ELSE true END
  AND CASE WHEN @id::int4 > 0 THEN u.id = @id ELSE true END
LIMIT 1;

-- name: GetUserChannels :many
SELECT c.name, l.channel_id, l.user_id, l.access, l.flags, l.last_modif, l.suspend_expires, l.suspend_by
FROM levels l
INNER JOIN channels c
ON l.channel_id = c.id
WHERE l.user_id = $1;

-- name: GetUsersByUsernames :many
SELECT u.*, ul.last_seen, l.code as language_code, l.name as language_name
FROM users u
INNER JOIN users_lastseen ul
ON u.id = ul.user_id
INNER JOIN languages l
ON u.language_id = l.id
WHERE u.user_name ILIKE ANY(@userIDs::VARCHAR[]);

-- name: GetAdminLevel :one
SELECT l.access, l.suspend_expires
FROM channels c
  INNER JOIN levels l
    ON c.id = l.channel_id
WHERE c.name = '*' AND l.user_id=$1;
