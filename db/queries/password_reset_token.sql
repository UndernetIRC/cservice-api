-- name: CreatePasswordResetToken :one
INSERT INTO password_reset_tokens (user_id, token, created_at, expires_at, last_updated)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetPasswordResetTokenByToken :one
SELECT *
FROM password_reset_tokens
WHERE token = $1 AND deleted = 0 LIMIT 1;

-- name: GetActivePasswordResetTokensByUserID :many
SELECT *
FROM password_reset_tokens
WHERE user_id = $1 AND deleted = 0 AND used_at IS NULL AND expires_at > $2
ORDER BY created_at DESC;

-- name: ValidatePasswordResetToken :one
SELECT *
FROM password_reset_tokens
WHERE token = $1 AND deleted = 0 AND used_at IS NULL AND expires_at > $2 LIMIT 1;

-- name: MarkPasswordResetTokenAsUsed :exec
UPDATE password_reset_tokens
SET used_at = $2, last_updated = $3
WHERE token = $1;

-- name: InvalidateUserPasswordResetTokens :exec
UPDATE password_reset_tokens
SET deleted = 1, last_updated = $2
WHERE user_id = $1 AND deleted = 0 AND used_at IS NULL;

-- name: CleanupExpiredPasswordResetTokens :exec
UPDATE password_reset_tokens
SET deleted = 1, last_updated = $2
WHERE expires_at <= $1 AND deleted = 0;

-- name: DeleteExpiredPasswordResetTokens :exec
DELETE FROM password_reset_tokens
WHERE expires_at <= $1 AND deleted = 1;

-- name: GetPasswordResetTokenStats :one
SELECT
    COUNT(*) as total_tokens,
    COUNT(CASE WHEN used_at IS NOT NULL THEN 1 END) as used_tokens,
    COUNT(CASE WHEN expires_at <= $1 AND used_at IS NULL THEN 1 END) as expired_tokens,
    COUNT(CASE WHEN expires_at > $1 AND used_at IS NULL AND deleted = 0 THEN 1 END) as active_tokens
FROM password_reset_tokens;
