-- name: GetGlineByIP :one
SELECT *
FROM glines
WHERE host ~ '.*@[abcdef0-9]+[\.:]+' AND split_part(host, '@', 2)::INET >>= $1
LIMIT 1;
