// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package reset

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/models"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.Equal(t, 32, config.TokenLength)
	assert.Equal(t, time.Hour, config.TokenLifetime)
	assert.Equal(t, 24*time.Hour, config.CleanupInterval)
	assert.Equal(t, 3, config.MaxTokensPerUser)
}

func TestNewTokenManager(t *testing.T) {
	// Test with nil config (should use defaults)
	tm := NewTokenManager(nil, nil)
	assert.NotNil(t, tm)
	assert.Equal(t, 32, tm.config.TokenLength)
	assert.Equal(t, time.Hour, tm.config.TokenLifetime)
	assert.Equal(t, 24*time.Hour, tm.config.CleanupInterval)
	assert.Equal(t, 3, tm.config.MaxTokensPerUser)

	// Test with custom config
	customConfig := &Config{
		TokenLength:      64,
		TokenLifetime:    2 * time.Hour,
		CleanupInterval:  12 * time.Hour,
		MaxTokensPerUser: 5,
	}
	tm2 := NewTokenManager(nil, customConfig)
	assert.NotNil(t, tm2)
	assert.Equal(t, 64, tm2.config.TokenLength)
	assert.Equal(t, 2*time.Hour, tm2.config.TokenLifetime)
	assert.Equal(t, 12*time.Hour, tm2.config.CleanupInterval)
	assert.Equal(t, 5, tm2.config.MaxTokensPerUser)
}

func TestGetTokenTimeRemaining(t *testing.T) {
	tm := NewTokenManager(nil, nil)

	now := time.Now().Unix()

	// Token with 1 hour remaining
	token := &models.PasswordResetToken{
		ExpiresAt: int32(now + 3600), // 1 hour from now
	}

	remaining := tm.GetTokenTimeRemaining(token)

	// Should be approximately 1 hour (allowing for small timing differences)
	assert.True(t, remaining > 59*time.Minute)
	assert.True(t, remaining <= time.Hour)

	// Expired token
	expiredToken := &models.PasswordResetToken{
		ExpiresAt: int32(now - 3600), // 1 hour ago
	}

	remainingExpired := tm.GetTokenTimeRemaining(expiredToken)
	assert.Equal(t, time.Duration(0), remainingExpired)

	// Token expiring exactly now
	nowToken := &models.PasswordResetToken{
		ExpiresAt: int32(now),
	}

	remainingNow := tm.GetTokenTimeRemaining(nowToken)
	assert.Equal(t, time.Duration(0), remainingNow)
}

func TestConfigValidation(t *testing.T) {
	// Test that config values are properly set
	config := Config{
		TokenLength:      16,
		TokenLifetime:    30 * time.Minute,
		CleanupInterval:  6 * time.Hour,
		MaxTokensPerUser: 1,
	}

	tm := NewTokenManager(nil, &config)
	assert.Equal(t, 16, tm.config.TokenLength)
	assert.Equal(t, 30*time.Minute, tm.config.TokenLifetime)
	assert.Equal(t, 6*time.Hour, tm.config.CleanupInterval)
	assert.Equal(t, 1, tm.config.MaxTokensPerUser)
}

func TestTokenManagerIntegration(t *testing.T) {
	// This test verifies that the token manager can be created with different configurations
	// and that the configuration is properly applied

	config := &Config{
		TokenLength:      16,
		TokenLifetime:    30 * time.Minute,
		CleanupInterval:  6 * time.Hour,
		MaxTokensPerUser: 2,
	}

	tm := NewTokenManager(nil, config)

	// Create a test token to verify time calculations work
	now := time.Now().Unix()
	token := &models.PasswordResetToken{
		CreatedAt: int32(now - 600),  // 10 minutes ago
		ExpiresAt: int32(now + 1200), // 20 minutes from now
	}

	// Test that time remaining calculation works
	assert.False(t, tm.GetTokenTimeRemaining(token) == 0)

	// Verify the token is not considered expired (indirectly through time remaining)
	remaining := tm.GetTokenTimeRemaining(token)
	assert.True(t, remaining > 0)
}

func TestCreateToken(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		db.On("GetActivePasswordResetTokensByUserID", mock.Anything, mock.Anything, mock.Anything).
			Return([]models.PasswordResetToken{}, nil).Once()
		db.On("CreatePasswordResetToken", mock.Anything, mock.Anything).
			Return(models.PasswordResetToken{
				ID:    1,
				Token: "generated-token",
				UserID: pgtype.Int4{Int32: 100, Valid: true},
			}, nil).Once()

		result, err := tm.CreateToken(ctx, 100)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, int32(1), result.ID)
	})

	t.Run("success_invalidates_old_when_max_reached", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		existingTokens := []models.PasswordResetToken{
			{ID: 1}, {ID: 2}, {ID: 3},
		}
		db.On("GetActivePasswordResetTokensByUserID", mock.Anything, mock.Anything, mock.Anything).
			Return(existingTokens, nil).Once()
		db.On("InvalidateUserPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()
		db.On("CreatePasswordResetToken", mock.Anything, mock.Anything).
			Return(models.PasswordResetToken{ID: 4, Token: "new-token"}, nil).Once()

		result, err := tm.CreateToken(ctx, 100)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, int32(4), result.ID)
	})

	t.Run("db_error_on_get_active", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		db.On("GetActivePasswordResetTokensByUserID", mock.Anything, mock.Anything, mock.Anything).
			Return(nil, errors.New("connection refused")).Once()

		result, err := tm.CreateToken(ctx, 100)
		assert.Nil(t, result)
		assert.ErrorContains(t, err, "failed to check active tokens")
	})
}

func TestCreateToken_DBError(t *testing.T) {
	ctx := context.Background()

	t.Run("db_error_on_create", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		db.On("GetActivePasswordResetTokensByUserID", mock.Anything, mock.Anything, mock.Anything).
			Return([]models.PasswordResetToken{}, nil).Once()
		db.On("CreatePasswordResetToken", mock.Anything, mock.Anything).
			Return(models.PasswordResetToken{}, errors.New("insert failed")).Once()

		result, err := tm.CreateToken(ctx, 100)
		assert.Nil(t, result)
		assert.ErrorContains(t, err, "failed to create reset token")
	})

	t.Run("db_error_on_invalidate", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		existingTokens := []models.PasswordResetToken{
			{ID: 1}, {ID: 2}, {ID: 3},
		}
		db.On("GetActivePasswordResetTokensByUserID", mock.Anything, mock.Anything, mock.Anything).
			Return(existingTokens, nil).Once()
		db.On("InvalidateUserPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything).
			Return(errors.New("update failed")).Once()

		result, err := tm.CreateToken(ctx, 100)
		assert.Nil(t, result)
		assert.ErrorContains(t, err, "failed to invalidate old tokens")
	})
}

func TestValidateToken(t *testing.T) {
	ctx := context.Background()

	t.Run("valid_token", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		expected := models.PasswordResetToken{
			ID:    1,
			Token: "valid-token",
			UserID: pgtype.Int4{Int32: 100, Valid: true},
		}
		db.On("ValidatePasswordResetToken", mock.Anything, "valid-token", mock.Anything).
			Return(expected, nil).Once()

		result, err := tm.ValidateToken(ctx, "valid-token")
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, int32(1), result.ID)
		assert.Equal(t, "valid-token", result.Token)
	})
}

func TestValidateToken_Expired(t *testing.T) {
	ctx := context.Background()
	db := mocks.NewQuerier(t)
	tm := NewTokenManager(db, nil)

	db.On("ValidatePasswordResetToken", mock.Anything, "expired-token", mock.Anything).
		Return(models.PasswordResetToken{}, errors.New("no rows")).Once()

	result, err := tm.ValidateToken(ctx, "expired-token")
	assert.Nil(t, result)
	assert.ErrorContains(t, err, "invalid or expired token")
}

func TestValidateToken_Invalid(t *testing.T) {
	ctx := context.Background()
	db := mocks.NewQuerier(t)
	tm := NewTokenManager(db, nil)

	db.On("ValidatePasswordResetToken", mock.Anything, "nonexistent-token", mock.Anything).
		Return(models.PasswordResetToken{}, errors.New("no rows in result set")).Once()

	result, err := tm.ValidateToken(ctx, "nonexistent-token")
	assert.Nil(t, result)
	assert.ErrorContains(t, err, "invalid or expired token")
}

func TestUseToken(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		db.On("ValidatePasswordResetToken", mock.Anything, "use-me", mock.Anything).
			Return(models.PasswordResetToken{ID: 1, Token: "use-me"}, nil).Once()
		db.On("MarkPasswordResetTokenAsUsed", mock.Anything, mock.Anything).
			Return(nil).Once()

		err := tm.UseToken(ctx, "use-me")
		assert.NoError(t, err)
	})

	t.Run("db_error_on_mark", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		db.On("ValidatePasswordResetToken", mock.Anything, "mark-fail", mock.Anything).
			Return(models.PasswordResetToken{ID: 1, Token: "mark-fail"}, nil).Once()
		db.On("MarkPasswordResetTokenAsUsed", mock.Anything, mock.Anything).
			Return(errors.New("update failed")).Once()

		err := tm.UseToken(ctx, "mark-fail")
		assert.ErrorContains(t, err, "failed to mark token as used")
	})
}

func TestUseToken_AlreadyUsed(t *testing.T) {
	ctx := context.Background()
	db := mocks.NewQuerier(t)
	tm := NewTokenManager(db, nil)

	db.On("ValidatePasswordResetToken", mock.Anything, "already-used", mock.Anything).
		Return(models.PasswordResetToken{}, errors.New("no rows")).Once()

	err := tm.UseToken(ctx, "already-used")
	assert.ErrorContains(t, err, "invalid or expired token")
}

func TestInvalidateUserTokens(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		db.On("InvalidateUserPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()

		err := tm.InvalidateUserTokens(ctx, 100)
		assert.NoError(t, err)
	})

	t.Run("db_error", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		db.On("InvalidateUserPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything).
			Return(errors.New("connection lost")).Once()

		err := tm.InvalidateUserTokens(ctx, 100)
		assert.ErrorContains(t, err, "failed to invalidate user tokens")
	})
}

func TestCleanupExpiredTokens(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		db.On("CleanupExpiredPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()
		db.On("DeleteExpiredPasswordResetTokens", mock.Anything, mock.Anything).
			Return(nil).Once()

		err := tm.CleanupExpiredTokens(ctx)
		assert.NoError(t, err)
	})

	t.Run("nothing_to_clean", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		db.On("CleanupExpiredPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()
		db.On("DeleteExpiredPasswordResetTokens", mock.Anything, mock.Anything).
			Return(nil).Once()

		err := tm.CleanupExpiredTokens(ctx)
		assert.NoError(t, err)
	})

	t.Run("db_error_on_cleanup", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		db.On("CleanupExpiredPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything).
			Return(errors.New("update failed")).Once()

		err := tm.CleanupExpiredTokens(ctx)
		assert.ErrorContains(t, err, "failed to mark expired tokens as deleted")
	})

	t.Run("db_error_on_delete", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		db.On("CleanupExpiredPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()
		db.On("DeleteExpiredPasswordResetTokens", mock.Anything, mock.Anything).
			Return(errors.New("delete failed")).Once()

		err := tm.CleanupExpiredTokens(ctx)
		assert.ErrorContains(t, err, "failed to delete expired tokens")
	})
}

func TestGetTokenStats(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		expected := models.GetPasswordResetTokenStatsRow{
			TotalTokens:   50,
			UsedTokens:    20,
			ExpiredTokens: 10,
			ActiveTokens:  20,
		}
		db.On("GetPasswordResetTokenStats", mock.Anything, mock.Anything).
			Return(expected, nil).Once()

		stats, err := tm.GetTokenStats(ctx)
		require.NoError(t, err)
		assert.NotNil(t, stats)
		assert.Equal(t, int64(50), stats.TotalTokens)
		assert.Equal(t, int64(20), stats.UsedTokens)
		assert.Equal(t, int64(10), stats.ExpiredTokens)
		assert.Equal(t, int64(20), stats.ActiveTokens)
	})

	t.Run("db_error", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		db.On("GetPasswordResetTokenStats", mock.Anything, mock.Anything).
			Return(models.GetPasswordResetTokenStatsRow{}, errors.New("query failed")).Once()

		stats, err := tm.GetTokenStats(ctx)
		assert.Nil(t, stats)
		assert.ErrorContains(t, err, "failed to get token stats")
	})
}
