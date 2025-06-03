// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package reset

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
