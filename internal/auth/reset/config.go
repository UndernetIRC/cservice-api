// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package reset

import (
	"fmt"
	"time"

	"github.com/undernetirc/cservice-api/internal/config"
)

// LoadConfigFromViper loads password reset token configuration from viper settings
func LoadConfigFromViper() (*Config, error) {
	tokenLength := config.ServicePasswordResetTokenLength.GetInt()
	lifetimeMinutes := config.ServicePasswordResetTokenLifetimeMinutes.GetInt()
	cleanupIntervalHours := config.ServicePasswordResetCleanupIntervalHours.GetInt()
	maxTokensPerUser := config.ServicePasswordResetMaxTokensPerUser.GetInt()

	// Validate configuration values
	if tokenLength < 16 {
		return nil, fmt.Errorf("password reset token length must be at least 16 characters, got %d", tokenLength)
	}
	if tokenLength > 128 {
		return nil, fmt.Errorf("password reset token length must be at most 128 characters, got %d", tokenLength)
	}

	if lifetimeMinutes < 1 {
		return nil, fmt.Errorf("password reset token lifetime must be at least 1 minute, got %d", lifetimeMinutes)
	}
	if lifetimeMinutes > 1440 { // 24 hours
		return nil, fmt.Errorf("password reset token lifetime must be at most 1440 minutes (24 hours), got %d", lifetimeMinutes)
	}

	if cleanupIntervalHours < 1 {
		return nil, fmt.Errorf("password reset cleanup interval must be at least 1 hour, got %d", cleanupIntervalHours)
	}
	if cleanupIntervalHours > 168 { // 1 week
		return nil, fmt.Errorf("password reset cleanup interval must be at most 168 hours (1 week), got %d", cleanupIntervalHours)
	}

	if maxTokensPerUser < 1 {
		return nil, fmt.Errorf("max tokens per user must be at least 1, got %d", maxTokensPerUser)
	}
	if maxTokensPerUser > 10 {
		return nil, fmt.Errorf("max tokens per user must be at most 10, got %d", maxTokensPerUser)
	}

	return &Config{
		TokenLength:      tokenLength,
		TokenLifetime:    time.Duration(lifetimeMinutes) * time.Minute,
		CleanupInterval:  time.Duration(cleanupIntervalHours) * time.Hour,
		MaxTokensPerUser: maxTokensPerUser,
	}, nil
}

// ValidateConfig validates a password reset token configuration
func ValidateConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	if cfg.TokenLength < 16 {
		return fmt.Errorf("token length must be at least 16 characters, got %d", cfg.TokenLength)
	}
	if cfg.TokenLength > 128 {
		return fmt.Errorf("token length must be at most 128 characters, got %d", cfg.TokenLength)
	}

	if cfg.TokenLifetime < time.Minute {
		return fmt.Errorf("token lifetime must be at least 1 minute, got %v", cfg.TokenLifetime)
	}
	if cfg.TokenLifetime > 24*time.Hour {
		return fmt.Errorf("token lifetime must be at most 24 hours, got %v", cfg.TokenLifetime)
	}

	if cfg.CleanupInterval < time.Hour {
		return fmt.Errorf("cleanup interval must be at least 1 hour, got %v", cfg.CleanupInterval)
	}
	if cfg.CleanupInterval > 7*24*time.Hour {
		return fmt.Errorf("cleanup interval must be at most 1 week, got %v", cfg.CleanupInterval)
	}

	if cfg.MaxTokensPerUser < 1 {
		return fmt.Errorf("max tokens per user must be at least 1, got %d", cfg.MaxTokensPerUser)
	}
	if cfg.MaxTokensPerUser > 10 {
		return fmt.Errorf("max tokens per user must be at most 10, got %d", cfg.MaxTokensPerUser)
	}

	return nil
}
