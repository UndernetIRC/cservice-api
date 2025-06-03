// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package reset provides password reset token management functionality
package reset

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

// TokenManager handles password reset token operations
type TokenManager struct {
	queries models.Querier
	config  Config
}

// Config contains configuration for password reset tokens
type Config struct {
	TokenLength      int           // Length of generated tokens (default: 32)
	TokenLifetime    time.Duration // How long tokens are valid (default: 1 hour)
	CleanupInterval  time.Duration // How often to clean up expired tokens (default: 24 hours)
	MaxTokensPerUser int           // Maximum active tokens per user (default: 3)
}

// DefaultConfig returns the default configuration for password reset tokens
func DefaultConfig() Config {
	return Config{
		TokenLength:      32,
		TokenLifetime:    time.Hour,
		CleanupInterval:  24 * time.Hour,
		MaxTokensPerUser: 3,
	}
}

// NewTokenManager creates a new password reset token manager
func NewTokenManager(queries models.Querier, config *Config) *TokenManager {
	if config == nil {
		defaultConfig := DefaultConfig()
		config = &defaultConfig
	}

	return &TokenManager{
		queries: queries,
		config:  *config,
	}
}

// CreateToken creates a new password reset token for the given user
func (tm *TokenManager) CreateToken(ctx context.Context, userID int32) (*models.PasswordResetToken, error) {
	// Generate secure token
	token := helper.GenerateSecureToken(tm.config.TokenLength)
	if token == "" {
		return nil, fmt.Errorf("failed to generate secure token")
	}

	// Calculate expiration time
	now := time.Now().Unix()
	expiresAt := now + int64(tm.config.TokenLifetime.Seconds())

	// Check if user has too many active tokens
	activeTokens, err := tm.queries.GetActivePasswordResetTokensByUserID(ctx,
		pgtype.Int4{Int32: userID, Valid: true},
		int32(now))
	if err != nil {
		return nil, fmt.Errorf("failed to check active tokens: %w", err)
	}

	if len(activeTokens) >= tm.config.MaxTokensPerUser {
		// Invalidate oldest tokens to make room
		err = tm.queries.InvalidateUserPasswordResetTokens(ctx,
			pgtype.Int4{Int32: userID, Valid: true},
			int32(now))
		if err != nil {
			return nil, fmt.Errorf("failed to invalidate old tokens: %w", err)
		}
	}

	// Create new token
	params := models.CreatePasswordResetTokenParams{
		UserID:      pgtype.Int4{Int32: userID, Valid: true},
		Token:       token,
		CreatedAt:   int32(now),
		ExpiresAt:   int32(expiresAt),
		LastUpdated: int32(now),
	}

	resetToken, err := tm.queries.CreatePasswordResetToken(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create reset token: %w", err)
	}

	return &resetToken, nil
}

// ValidateToken validates a password reset token and returns the token if valid
func (tm *TokenManager) ValidateToken(ctx context.Context, token string) (*models.PasswordResetToken, error) {
	now := time.Now().Unix()

	resetToken, err := tm.queries.ValidatePasswordResetToken(ctx, token, int32(now))
	if err != nil {
		return nil, fmt.Errorf("invalid or expired token: %w", err)
	}

	return &resetToken, nil
}

// UseToken marks a password reset token as used
func (tm *TokenManager) UseToken(ctx context.Context, token string) error {
	now := time.Now().Unix()

	// First validate the token is still valid
	_, err := tm.ValidateToken(ctx, token)
	if err != nil {
		return err
	}

	// Mark as used
	params := models.MarkPasswordResetTokenAsUsedParams{
		Token:       token,
		UsedAt:      pgtype.Int4{Int32: int32(now), Valid: true},
		LastUpdated: int32(now),
	}

	err = tm.queries.MarkPasswordResetTokenAsUsed(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to mark token as used: %w", err)
	}

	return nil
}

// InvalidateUserTokens invalidates all active password reset tokens for a user
func (tm *TokenManager) InvalidateUserTokens(ctx context.Context, userID int32) error {
	now := time.Now().Unix()

	err := tm.queries.InvalidateUserPasswordResetTokens(ctx,
		pgtype.Int4{Int32: userID, Valid: true},
		int32(now))
	if err != nil {
		return fmt.Errorf("failed to invalidate user tokens: %w", err)
	}

	return nil
}

// CleanupExpiredTokens removes expired tokens from the database
func (tm *TokenManager) CleanupExpiredTokens(ctx context.Context) error {
	now := time.Now().Unix()

	// First mark expired tokens as deleted
	err := tm.queries.CleanupExpiredPasswordResetTokens(ctx, int32(now), int32(now))
	if err != nil {
		return fmt.Errorf("failed to mark expired tokens as deleted: %w", err)
	}

	// Then permanently delete tokens that have been marked as deleted
	err = tm.queries.DeleteExpiredPasswordResetTokens(ctx, int32(now))
	if err != nil {
		return fmt.Errorf("failed to delete expired tokens: %w", err)
	}

	return nil
}

// GetTokenStats returns statistics about password reset tokens
func (tm *TokenManager) GetTokenStats(ctx context.Context) (*models.GetPasswordResetTokenStatsRow, error) {
	now := time.Now().Unix()

	stats, err := tm.queries.GetPasswordResetTokenStats(ctx, int32(now))
	if err != nil {
		return nil, fmt.Errorf("failed to get token stats: %w", err)
	}

	return &stats, nil
}

// GetTokenTimeRemaining returns the time remaining before a token expires
func (tm *TokenManager) GetTokenTimeRemaining(token *models.PasswordResetToken) time.Duration {
	now := time.Now().Unix()
	remaining := int64(token.ExpiresAt) - now
	if remaining <= 0 {
		return 0
	}
	return time.Duration(remaining) * time.Second
}
