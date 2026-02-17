// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package reset

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/models"
)

// TestValidateToken_SecurityBoundary tests adversarial inputs to ValidateToken.
// The DB call uses parameterized queries, so SQL injection is not a runtime risk,
// but the token strings should be handled gracefully regardless of content.
func TestValidateToken_SecurityBoundary(t *testing.T) {
	ctx := context.Background()

	adversarialTokens := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"whitespace-only token", "   \t\n  "},
		{"very long token (10000 chars)", strings.Repeat("x", 10000)},
		{"SQL injection attempt", "'; DROP TABLE password_reset_tokens; --"},
		{"unicode characters", "测试-reset-token-值"},
		{"null bytes", "token\x00withNull\x00bytes"},
		{"newline injection", "token\r\nX-Injected: evil"},
		{"path traversal", "../../../../etc/passwd"},
		{"only special chars", "!@#$%^&*()_+{}|:<>?"},
	}

	for _, tc := range adversarialTokens {
		t.Run(tc.name, func(t *testing.T) {
			db := mocks.NewQuerier(t)
			tm := NewTokenManager(db, nil)

			// DB is expected to return an error (no matching token)
			db.On("ValidatePasswordResetToken", mock.Anything, tc.token, mock.Anything).
				Return(models.PasswordResetToken{}, errors.New("no rows in result set")).Once()

			assert.NotPanics(t, func() {
				result, err := tm.ValidateToken(ctx, tc.token)
				assert.Nil(t, result)
				assert.Error(t, err, "adversarial token should be rejected")
				assert.Contains(t, err.Error(), "invalid or expired token")
			})
			db.AssertExpectations(t)
		})
	}
}

// TestGetTokenTimeRemaining_Boundary tests edge cases in the time remaining calculation.
func TestGetTokenTimeRemaining_Boundary(t *testing.T) {
	tm := NewTokenManager(nil, nil)
	now := time.Now().Unix()

	t.Run("token expiring in exactly 1 second has positive remaining time", func(t *testing.T) {
		token := &models.PasswordResetToken{
			ExpiresAt: int32(now + 1),
		}
		remaining := tm.GetTokenTimeRemaining(token)
		assert.Equal(t, time.Second, remaining)
	})

	t.Run("token expiring exactly now returns 0", func(t *testing.T) {
		token := &models.PasswordResetToken{
			ExpiresAt: int32(now),
		}
		remaining := tm.GetTokenTimeRemaining(token)
		assert.Equal(t, time.Duration(0), remaining)
	})

	t.Run("token with ExpiresAt=0 returns 0 (treated as epoch, always expired)", func(t *testing.T) {
		token := &models.PasswordResetToken{
			ExpiresAt: 0,
		}
		remaining := tm.GetTokenTimeRemaining(token)
		// int64(0) - now is very negative → returns 0
		assert.Equal(t, time.Duration(0), remaining,
			"ExpiresAt=0 (epoch) is far in the past, should return 0")
	})

	t.Run("token with int32 max ExpiresAt has very large remaining time", func(t *testing.T) {
		// int32 max = 2147483647 (year 2038)
		token := &models.PasswordResetToken{
			ExpiresAt: math.MaxInt32,
		}
		remaining := tm.GetTokenTimeRemaining(token)
		// Should be many years in the future (positive)
		assert.True(t, remaining > 0, "max int32 ExpiresAt should have large positive remaining time")
		// Should be roughly 12+ years from now (2026 → 2038)
		assert.True(t, remaining > 10*365*24*time.Hour,
			"max int32 expiry should be at least 10 years from now (year 2038)")
	})

	t.Run("token expiring 1 hour from now has correct remaining", func(t *testing.T) {
		token := &models.PasswordResetToken{
			ExpiresAt: int32(now + 3600),
		}
		remaining := tm.GetTokenTimeRemaining(token)
		assert.True(t, remaining > 59*time.Minute)
		assert.True(t, remaining <= time.Hour)
	})

	t.Run("token negative remaining (far past) returns 0", func(t *testing.T) {
		token := &models.PasswordResetToken{
			ExpiresAt: int32(now - 86400), // 1 day ago
		}
		remaining := tm.GetTokenTimeRemaining(token)
		assert.Equal(t, time.Duration(0), remaining)
	})
}

// TestCreateToken_Boundary tests edge cases in CreateToken.
func TestCreateToken_Boundary(t *testing.T) {
	ctx := context.Background()

	t.Run("userID=0 is accepted by CreateToken (boundary at zero)", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		db.On("GetActivePasswordResetTokensByUserID", mock.Anything, mock.Anything, mock.Anything).
			Return([]models.PasswordResetToken{}, nil).Once()
		db.On("CreatePasswordResetToken", mock.Anything, mock.Anything).
			Return(models.PasswordResetToken{
				ID:     1,
				Token:  "generated-token",
				UserID: pgtype.Int4{Int32: 0, Valid: true},
			}, nil).Once()

		result, err := tm.CreateToken(ctx, 0)
		// The function does not validate userID — zero is passed through.
		// This documents the boundary: userID=0 is accepted without validation.
		require.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("exactly MaxTokensPerUser-1 active tokens does NOT trigger invalidation", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		// MaxTokensPerUser defaults to 3; 2 active tokens should NOT trigger invalidation
		existingTokens := []models.PasswordResetToken{
			{ID: 1}, {ID: 2},
		}
		db.On("GetActivePasswordResetTokensByUserID", mock.Anything, mock.Anything, mock.Anything).
			Return(existingTokens, nil).Once()
		db.On("CreatePasswordResetToken", mock.Anything, mock.Anything).
			Return(models.PasswordResetToken{ID: 3, Token: "new-token"}, nil).Once()

		result, err := tm.CreateToken(ctx, 100)
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Verify InvalidateUserPasswordResetTokens was NOT called
		db.AssertNotCalled(t, "InvalidateUserPasswordResetTokens",
			mock.Anything, mock.Anything, mock.Anything)
		db.AssertExpectations(t)
	})

	t.Run("exactly MaxTokensPerUser active tokens triggers invalidation", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		// MaxTokensPerUser defaults to 3; 3 active tokens should trigger invalidation
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
		db.AssertExpectations(t)
	})

	t.Run("MaxTokensPerUser+1 active tokens also triggers invalidation", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		// 4 active tokens (exceeds max of 3) should also trigger invalidation
		existingTokens := []models.PasswordResetToken{
			{ID: 1}, {ID: 2}, {ID: 3}, {ID: 4},
		}
		db.On("GetActivePasswordResetTokensByUserID", mock.Anything, mock.Anything, mock.Anything).
			Return(existingTokens, nil).Once()
		db.On("InvalidateUserPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()
		db.On("CreatePasswordResetToken", mock.Anything, mock.Anything).
			Return(models.PasswordResetToken{ID: 5, Token: "new-token"}, nil).Once()

		result, err := tm.CreateToken(ctx, 100)
		require.NoError(t, err)
		assert.NotNil(t, result)
		db.AssertExpectations(t)
	})

	t.Run("MaxTokensPerUser=1 boundary: single active token triggers invalidation", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		config := &Config{
			TokenLength:      32,
			TokenLifetime:    time.Hour,
			CleanupInterval:  24 * time.Hour,
			MaxTokensPerUser: 1, // Very restrictive: any existing token triggers invalidation
		}
		tm := NewTokenManager(db, config)

		db.On("GetActivePasswordResetTokensByUserID", mock.Anything, mock.Anything, mock.Anything).
			Return([]models.PasswordResetToken{{ID: 1}}, nil).Once()
		db.On("InvalidateUserPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()
		db.On("CreatePasswordResetToken", mock.Anything, mock.Anything).
			Return(models.PasswordResetToken{ID: 2, Token: "new-token"}, nil).Once()

		result, err := tm.CreateToken(ctx, 100)
		require.NoError(t, err)
		assert.NotNil(t, result)
		db.AssertExpectations(t)
	})
}

// TestUseToken_SecurityBoundary tests the UseToken function with security-sensitive scenarios.
func TestUseToken_SecurityBoundary(t *testing.T) {
	ctx := context.Background()

	t.Run("empty token string is rejected", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		db.On("ValidatePasswordResetToken", mock.Anything, "", mock.Anything).
			Return(models.PasswordResetToken{}, errors.New("no rows")).Once()

		err := tm.UseToken(ctx, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid or expired token")
		db.AssertExpectations(t)
	})

	t.Run("very long token string is handled without panic", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		longToken := strings.Repeat("x", 10000)
		db.On("ValidatePasswordResetToken", mock.Anything, longToken, mock.Anything).
			Return(models.PasswordResetToken{}, errors.New("no rows")).Once()

		assert.NotPanics(t, func() {
			err := tm.UseToken(ctx, longToken)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid or expired token")
		})
		db.AssertExpectations(t)
	})

	t.Run("token reuse: UseToken after mark fails validates again and fails", func(t *testing.T) {
		// Simulates a client that calls UseToken twice with the same token.
		// Second call must fail because ValidatePasswordResetToken queries DB for active tokens.
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		// First UseToken call: validate succeeds, mark succeeds
		db.On("ValidatePasswordResetToken", mock.Anything, "one-time-token", mock.Anything).
			Return(models.PasswordResetToken{ID: 1, Token: "one-time-token"}, nil).Once()
		db.On("MarkPasswordResetTokenAsUsed", mock.Anything, mock.Anything).
			Return(nil).Once()

		// Second UseToken call: validate fails because token is now used
		db.On("ValidatePasswordResetToken", mock.Anything, "one-time-token", mock.Anything).
			Return(models.PasswordResetToken{}, errors.New("no rows — token already used")).Once()

		// First use should succeed
		err := tm.UseToken(ctx, "one-time-token")
		assert.NoError(t, err, "first use should succeed")

		// Second use should fail (DB would reject it)
		err = tm.UseToken(ctx, "one-time-token")
		assert.Error(t, err, "second use of same token should fail")
		assert.Contains(t, err.Error(), "invalid or expired token")

		db.AssertExpectations(t)
	})

	t.Run("SQL injection in token is handled safely (parameterized query)", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		injectionToken := "'; UPDATE users SET password='hacked'; --"
		db.On("ValidatePasswordResetToken", mock.Anything, injectionToken, mock.Anything).
			Return(models.PasswordResetToken{}, errors.New("no rows")).Once()

		assert.NotPanics(t, func() {
			err := tm.UseToken(ctx, injectionToken)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid or expired token")
		})
		db.AssertExpectations(t)
	})
}

// TestInvalidateUserTokens_Boundary tests edge cases in InvalidateUserTokens.
func TestInvalidateUserTokens_Boundary(t *testing.T) {
	ctx := context.Background()

	t.Run("userID=0 is accepted (no validation of zero user ID)", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		db.On("InvalidateUserPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()

		err := tm.InvalidateUserTokens(ctx, 0)
		assert.NoError(t, err, "userID=0 should be accepted by InvalidateUserTokens")
		db.AssertExpectations(t)
	})

	t.Run("userID=max int32 is accepted", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		db.On("InvalidateUserPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()

		err := tm.InvalidateUserTokens(ctx, math.MaxInt32)
		assert.NoError(t, err)
		db.AssertExpectations(t)
	})
}

// TestCleanupExpiredTokens_Boundary tests edge cases in CleanupExpiredTokens.
func TestCleanupExpiredTokens_Boundary(t *testing.T) {
	ctx := context.Background()

	t.Run("cleanup with context already cancelled returns error from DB", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		cancelledCtx, cancel := context.WithCancel(ctx)
		cancel() // Cancel immediately

		// The DB call will receive a cancelled context; mock returns an error
		db.On("CleanupExpiredPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything).
			Return(errors.New("context canceled")).Once()

		err := tm.CleanupExpiredTokens(cancelledCtx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to mark expired tokens as deleted")
		db.AssertExpectations(t)
	})
}

// TestTokenManager_ConcurrentAccess tests that TokenManager methods are safe
// to call concurrently (no data races — run with `go test -race`).
func TestTokenManager_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()

	t.Run("concurrent ValidateToken calls are goroutine-safe", func(t *testing.T) {
		const numGoroutines = 20
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)

		// All concurrent calls return "not found"
		db.On("ValidatePasswordResetToken", mock.Anything, mock.Anything, mock.Anything).
			Return(models.PasswordResetToken{}, errors.New("no rows")).Times(numGoroutines)

		var wg sync.WaitGroup
		errs := make([]error, numGoroutines)

		for i := range numGoroutines {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				_, errs[idx] = tm.ValidateToken(ctx, "some-token")
			}(i)
		}
		wg.Wait()

		for i, err := range errs {
			assert.Error(t, err, "goroutine %d: ValidateToken should return error", i)
		}
		db.AssertExpectations(t)
	})

	t.Run("concurrent GetTokenTimeRemaining calls are goroutine-safe", func(t *testing.T) {
		tm := NewTokenManager(nil, nil)
		now := time.Now().Unix()

		token := &models.PasswordResetToken{
			ExpiresAt: int32(now + 3600),
		}

		const numGoroutines = 50
		var wg sync.WaitGroup
		results := make([]time.Duration, numGoroutines)

		for i := range numGoroutines {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				results[idx] = tm.GetTokenTimeRemaining(token)
			}(i)
		}
		wg.Wait()

		for i, d := range results {
			assert.True(t, d > 0, "goroutine %d: time remaining should be positive", i)
		}
	})
}

// TestCreateToken_GeneratesNonEmptyToken verifies that generated tokens are non-empty.
// The builder's test mocked the DB return value but did not verify the generated token length.
func TestCreateToken_GeneratesNonEmptyToken(t *testing.T) {
	ctx := context.Background()
	db := mocks.NewQuerier(t)

	config := &Config{
		TokenLength:      32,
		TokenLifetime:    time.Hour,
		CleanupInterval:  24 * time.Hour,
		MaxTokensPerUser: 3,
	}
	tm := NewTokenManager(db, config)

	var capturedToken string
	db.On("GetActivePasswordResetTokensByUserID", mock.Anything, mock.Anything, mock.Anything).
		Return([]models.PasswordResetToken{}, nil).Once()
	db.On("CreatePasswordResetToken", mock.Anything, mock.MatchedBy(func(p models.CreatePasswordResetTokenParams) bool {
		capturedToken = p.Token
		return p.Token != ""
	})).Return(models.PasswordResetToken{ID: 1, Token: "some-token"}, nil).Once()

	result, err := tm.CreateToken(ctx, 100)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Verify the token was non-empty and has expected length (alphanumeric, 32 chars)
	assert.NotEmpty(t, capturedToken, "generated token must not be empty")
	assert.Len(t, capturedToken, 32, "generated token should be exactly 32 characters long")

	// Token should be alphanumeric only
	for _, ch := range capturedToken {
		assert.True(t,
			(ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9'),
			"token character %c should be alphanumeric", ch)
	}

	db.AssertExpectations(t)
}

// TestCreateToken_CustomTokenLength verifies that the TokenLength config is respected.
func TestCreateToken_CustomTokenLength(t *testing.T) {
	ctx := context.Background()

	tokenLengths := []int{8, 16, 32, 64, 128}

	for _, length := range tokenLengths {
		t.Run("token length "+string(rune('0'+length/10))+string(rune('0'+length%10)), func(t *testing.T) {
			db := mocks.NewQuerier(t)
			config := &Config{
				TokenLength:      length,
				TokenLifetime:    time.Hour,
				CleanupInterval:  24 * time.Hour,
				MaxTokensPerUser: 3,
			}
			tm := NewTokenManager(db, config)

			var capturedLength int
			db.On("GetActivePasswordResetTokensByUserID", mock.Anything, mock.Anything, mock.Anything).
				Return([]models.PasswordResetToken{}, nil).Once()
			db.On("CreatePasswordResetToken", mock.Anything, mock.MatchedBy(func(p models.CreatePasswordResetTokenParams) bool {
				capturedLength = len(p.Token)
				return true
			})).Return(models.PasswordResetToken{ID: 1, Token: "tok"}, nil).Once()

			_, err := tm.CreateToken(ctx, 100)
			require.NoError(t, err)
			assert.Equal(t, length, capturedLength,
				"token length should match configured TokenLength=%d", length)
			db.AssertExpectations(t)
		})
	}
}

// TestValidateToken_ExpirationAtBoundary tests ValidateToken near the expiration boundary.
// ValidateToken passes the current time to the DB query for filtering.
// This test documents that the expiration logic is DB-side.
func TestValidateToken_ExpirationAtBoundary(t *testing.T) {
	ctx := context.Background()
	db := mocks.NewQuerier(t)
	tm := NewTokenManager(db, nil)

	// DB returns an active token (expires in future)
	now := time.Now().Unix()
	activeToken := models.PasswordResetToken{
		ID:        1,
		Token:     "boundary-token",
		UserID:    pgtype.Int4{Int32: 100, Valid: true},
		ExpiresAt: int32(now + 1), // 1 second in future
	}

	db.On("ValidatePasswordResetToken", mock.Anything, "boundary-token", mock.Anything).
		Return(activeToken, nil).Once()

	result, err := tm.ValidateToken(ctx, "boundary-token")
	require.NoError(t, err)
	assert.NotNil(t, result)
	// Verify the token's time remaining is positive
	remaining := tm.GetTokenTimeRemaining(result)
	assert.True(t, remaining > 0, "token expiring in 1 second should have positive remaining time")
	db.AssertExpectations(t)
}
