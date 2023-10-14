-- name: GetWhiteListByIP :one
SELECT *
FROM whitelist
WHERE ip = $1 LIMIT 1;
