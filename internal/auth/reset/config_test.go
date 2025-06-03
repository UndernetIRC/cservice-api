// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package reset

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/undernetirc/cservice-api/internal/config"
)

func TestLoadConfigFromViper(t *testing.T) {
	// Set up test configuration values
	config.ServicePasswordResetTokenLength.Set(32)
	config.ServicePasswordResetTokenLifetimeMinutes.Set(60)
	config.ServicePasswordResetCleanupIntervalHours.Set(24)
	config.ServicePasswordResetMaxTokensPerUser.Set(3)

	cfg, err := LoadConfigFromViper()

	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, 32, cfg.TokenLength)
	assert.Equal(t, time.Hour, cfg.TokenLifetime)
	assert.Equal(t, 24*time.Hour, cfg.CleanupInterval)
	assert.Equal(t, 3, cfg.MaxTokensPerUser)
}

func TestLoadConfigFromViperValidation(t *testing.T) {
	tests := []struct {
		name                 string
		tokenLength          int
		lifetimeMinutes      int
		cleanupIntervalHours int
		maxTokensPerUser     int
		expectError          bool
		errorContains        string
	}{
		{
			name:                 "valid config",
			tokenLength:          32,
			lifetimeMinutes:      60,
			cleanupIntervalHours: 24,
			maxTokensPerUser:     3,
			expectError:          false,
		},
		{
			name:                 "token length too small",
			tokenLength:          8,
			lifetimeMinutes:      60,
			cleanupIntervalHours: 24,
			maxTokensPerUser:     3,
			expectError:          true,
			errorContains:        "token length must be at least 16",
		},
		{
			name:                 "token length too large",
			tokenLength:          256,
			lifetimeMinutes:      60,
			cleanupIntervalHours: 24,
			maxTokensPerUser:     3,
			expectError:          true,
			errorContains:        "token length must be at most 128",
		},
		{
			name:                 "lifetime too short",
			tokenLength:          32,
			lifetimeMinutes:      0,
			cleanupIntervalHours: 24,
			maxTokensPerUser:     3,
			expectError:          true,
			errorContains:        "token lifetime must be at least 1 minute",
		},
		{
			name:                 "lifetime too long",
			tokenLength:          32,
			lifetimeMinutes:      1500, // > 24 hours
			cleanupIntervalHours: 24,
			maxTokensPerUser:     3,
			expectError:          true,
			errorContains:        "token lifetime must be at most 1440 minutes",
		},
		{
			name:                 "cleanup interval too short",
			tokenLength:          32,
			lifetimeMinutes:      60,
			cleanupIntervalHours: 0,
			maxTokensPerUser:     3,
			expectError:          true,
			errorContains:        "cleanup interval must be at least 1 hour",
		},
		{
			name:                 "cleanup interval too long",
			tokenLength:          32,
			lifetimeMinutes:      60,
			cleanupIntervalHours: 200, // > 1 week
			maxTokensPerUser:     3,
			expectError:          true,
			errorContains:        "cleanup interval must be at most 168 hours",
		},
		{
			name:                 "max tokens too small",
			tokenLength:          32,
			lifetimeMinutes:      60,
			cleanupIntervalHours: 24,
			maxTokensPerUser:     0,
			expectError:          true,
			errorContains:        "max tokens per user must be at least 1",
		},
		{
			name:                 "max tokens too large",
			tokenLength:          32,
			lifetimeMinutes:      60,
			cleanupIntervalHours: 24,
			maxTokensPerUser:     15,
			expectError:          true,
			errorContains:        "max tokens per user must be at most 10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set test values
			config.ServicePasswordResetTokenLength.Set(tt.tokenLength)
			config.ServicePasswordResetTokenLifetimeMinutes.Set(tt.lifetimeMinutes)
			config.ServicePasswordResetCleanupIntervalHours.Set(tt.cleanupIntervalHours)
			config.ServicePasswordResetMaxTokensPerUser.Set(tt.maxTokensPerUser)

			cfg, err := LoadConfigFromViper()

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Nil(t, cfg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cfg)
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name          string
		config        *Config
		expectError   bool
		errorContains string
	}{
		{
			name: "valid config",
			config: &Config{
				TokenLength:      32,
				TokenLifetime:    time.Hour,
				CleanupInterval:  24 * time.Hour,
				MaxTokensPerUser: 3,
			},
			expectError: false,
		},
		{
			name:          "nil config",
			config:        nil,
			expectError:   true,
			errorContains: "configuration cannot be nil",
		},
		{
			name: "token length too small",
			config: &Config{
				TokenLength:      8,
				TokenLifetime:    time.Hour,
				CleanupInterval:  24 * time.Hour,
				MaxTokensPerUser: 3,
			},
			expectError:   true,
			errorContains: "token length must be at least 16",
		},
		{
			name: "token length too large",
			config: &Config{
				TokenLength:      256,
				TokenLifetime:    time.Hour,
				CleanupInterval:  24 * time.Hour,
				MaxTokensPerUser: 3,
			},
			expectError:   true,
			errorContains: "token length must be at most 128",
		},
		{
			name: "token lifetime too short",
			config: &Config{
				TokenLength:      32,
				TokenLifetime:    30 * time.Second,
				CleanupInterval:  24 * time.Hour,
				MaxTokensPerUser: 3,
			},
			expectError:   true,
			errorContains: "token lifetime must be at least 1 minute",
		},
		{
			name: "token lifetime too long",
			config: &Config{
				TokenLength:      32,
				TokenLifetime:    25 * time.Hour,
				CleanupInterval:  24 * time.Hour,
				MaxTokensPerUser: 3,
			},
			expectError:   true,
			errorContains: "token lifetime must be at most 24 hours",
		},
		{
			name: "cleanup interval too short",
			config: &Config{
				TokenLength:      32,
				TokenLifetime:    time.Hour,
				CleanupInterval:  30 * time.Minute,
				MaxTokensPerUser: 3,
			},
			expectError:   true,
			errorContains: "cleanup interval must be at least 1 hour",
		},
		{
			name: "cleanup interval too long",
			config: &Config{
				TokenLength:      32,
				TokenLifetime:    time.Hour,
				CleanupInterval:  8 * 24 * time.Hour, // > 1 week
				MaxTokensPerUser: 3,
			},
			expectError:   true,
			errorContains: "cleanup interval must be at most 1 week",
		},
		{
			name: "max tokens too small",
			config: &Config{
				TokenLength:      32,
				TokenLifetime:    time.Hour,
				CleanupInterval:  24 * time.Hour,
				MaxTokensPerUser: 0,
			},
			expectError:   true,
			errorContains: "max tokens per user must be at least 1",
		},
		{
			name: "max tokens too large",
			config: &Config{
				TokenLength:      32,
				TokenLifetime:    time.Hour,
				CleanupInterval:  24 * time.Hour,
				MaxTokensPerUser: 15,
			},
			expectError:   true,
			errorContains: "max tokens per user must be at most 10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigBoundaryValues(t *testing.T) {
	// Test minimum valid values
	minConfig := &Config{
		TokenLength:      16,
		TokenLifetime:    time.Minute,
		CleanupInterval:  time.Hour,
		MaxTokensPerUser: 1,
	}
	assert.NoError(t, ValidateConfig(minConfig))

	// Test maximum valid values
	maxConfig := &Config{
		TokenLength:      128,
		TokenLifetime:    24 * time.Hour,
		CleanupInterval:  7 * 24 * time.Hour,
		MaxTokensPerUser: 10,
	}
	assert.NoError(t, ValidateConfig(maxConfig))
}
