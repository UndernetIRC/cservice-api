// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package cron

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/undernetirc/cservice-api/internal/config"
)

func createServiceTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewService(t *testing.T) {
	t.Run("creates service when enabled", func(t *testing.T) {
		logger := createServiceTestLogger()
		svc, err := NewService(ServiceConfig{
			Enabled:                  true,
			PasswordResetCleanupCron: "*/5 * * * *",
			TimeZone:                 "UTC",
		}, logger)

		require.NoError(t, err)
		require.NotNil(t, svc)
		assert.True(t, svc.IsEnabled())
		assert.NotNil(t, svc.scheduler)
	})

	t.Run("creates disabled service when not enabled", func(t *testing.T) {
		logger := createServiceTestLogger()
		svc, err := NewService(ServiceConfig{
			Enabled: false,
		}, logger)

		require.NoError(t, err)
		require.NotNil(t, svc)
		assert.False(t, svc.IsEnabled())
		assert.Nil(t, svc.scheduler)
	})

	t.Run("uses default logger when nil", func(t *testing.T) {
		svc, err := NewService(ServiceConfig{
			Enabled:                  true,
			PasswordResetCleanupCron: "*/5 * * * *",
			TimeZone:                 "UTC",
		}, nil)

		require.NoError(t, err)
		require.NotNil(t, svc)
		assert.NotNil(t, svc.logger)
	})

	t.Run("returns error for invalid timezone", func(t *testing.T) {
		logger := createServiceTestLogger()
		svc, err := NewService(ServiceConfig{
			Enabled:                  true,
			PasswordResetCleanupCron: "*/5 * * * *",
			TimeZone:                 "Invalid/Timezone",
		}, logger)

		assert.Error(t, err)
		assert.Nil(t, svc)
		assert.Contains(t, err.Error(), "failed to create cron scheduler")
	})

	t.Run("uses default logger when disabled and nil logger", func(t *testing.T) {
		svc, err := NewService(ServiceConfig{
			Enabled: false,
		}, nil)

		require.NoError(t, err)
		require.NotNil(t, svc)
		assert.NotNil(t, svc.logger)
		assert.False(t, svc.IsEnabled())
	})
}

func TestService_Start(t *testing.T) {
	t.Run("starts enabled service", func(t *testing.T) {
		logger := createServiceTestLogger()
		svc, err := NewService(ServiceConfig{
			Enabled:                  true,
			PasswordResetCleanupCron: "*/5 * * * *",
			TimeZone:                 "UTC",
		}, logger)
		require.NoError(t, err)

		err = svc.Start()
		assert.NoError(t, err)

		// Clean up
		svc.Stop()
	})

	t.Run("start on disabled service returns nil", func(t *testing.T) {
		logger := createServiceTestLogger()
		svc, err := NewService(ServiceConfig{
			Enabled: false,
		}, logger)
		require.NoError(t, err)

		err = svc.Start()
		assert.NoError(t, err)
	})
}

func TestService_Stop(t *testing.T) {
	t.Run("stops enabled service", func(t *testing.T) {
		logger := createServiceTestLogger()
		svc, err := NewService(ServiceConfig{
			Enabled:                  true,
			PasswordResetCleanupCron: "*/5 * * * *",
			TimeZone:                 "UTC",
		}, logger)
		require.NoError(t, err)

		err = svc.Start()
		require.NoError(t, err)

		// Should not panic
		svc.Stop()
	})

	t.Run("stop on disabled service does not panic", func(t *testing.T) {
		logger := createServiceTestLogger()
		svc, err := NewService(ServiceConfig{
			Enabled: false,
		}, logger)
		require.NoError(t, err)

		// Should not panic
		svc.Stop()
	})
}

func TestService_SetupPasswordResetCleanup(t *testing.T) {
	t.Run("skips setup when service is disabled", func(t *testing.T) {
		logger := createServiceTestLogger()
		svc, err := NewService(ServiceConfig{
			Enabled: false,
		}, logger)
		require.NoError(t, err)

		cfg := ServiceConfig{
			PasswordResetCleanupCron: "*/5 * * * *",
		}

		err = svc.SetupPasswordResetCleanup(nil, cfg)
		assert.NoError(t, err)
	})

	t.Run("sets up cleanup job when enabled with valid config", func(t *testing.T) {
		logger := createServiceTestLogger()
		svc, err := NewService(ServiceConfig{
			Enabled:                  true,
			PasswordResetCleanupCron: "*/5 * * * *",
			TimeZone:                 "UTC",
		}, logger)
		require.NoError(t, err)

		// Set required password reset config values via viper
		config.ServicePasswordResetTokenLength.Set(32)
		config.ServicePasswordResetTokenLifetimeMinutes.Set(60)
		config.ServicePasswordResetCleanupIntervalHours.Set(24)
		config.ServicePasswordResetMaxTokensPerUser.Set(3)

		cfg := ServiceConfig{
			PasswordResetCleanupCron: "*/5 * * * *",
		}

		err = svc.SetupPasswordResetCleanup(nil, cfg)
		assert.NoError(t, err)

		// Verify job was registered
		entries := svc.GetJobEntries()
		assert.Len(t, entries, 1)
	})

	t.Run("returns error for invalid password reset config", func(t *testing.T) {
		logger := createServiceTestLogger()
		svc, err := NewService(ServiceConfig{
			Enabled:                  true,
			PasswordResetCleanupCron: "*/5 * * * *",
			TimeZone:                 "UTC",
		}, logger)
		require.NoError(t, err)

		// Set invalid token length to trigger config load error
		config.ServicePasswordResetTokenLength.Set(1) // too short, min is 16
		defer config.ServicePasswordResetTokenLength.Set(32)

		cfg := ServiceConfig{
			PasswordResetCleanupCron: "*/5 * * * *",
		}

		err = svc.SetupPasswordResetCleanup(nil, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load password reset config")
	})

	t.Run("returns error for invalid cron expression", func(t *testing.T) {
		logger := createServiceTestLogger()
		svc, err := NewService(ServiceConfig{
			Enabled:                  true,
			PasswordResetCleanupCron: "*/5 * * * *",
			TimeZone:                 "UTC",
		}, logger)
		require.NoError(t, err)

		// Set valid password reset config
		config.ServicePasswordResetTokenLength.Set(32)
		config.ServicePasswordResetTokenLifetimeMinutes.Set(60)
		config.ServicePasswordResetCleanupIntervalHours.Set(24)
		config.ServicePasswordResetMaxTokensPerUser.Set(3)

		cfg := ServiceConfig{
			PasswordResetCleanupCron: "invalid-cron",
		}

		err = svc.SetupPasswordResetCleanup(nil, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to schedule password reset cleanup job")
	})
}

func TestService_AddCustomJob(t *testing.T) {
	t.Run("adds job successfully", func(t *testing.T) {
		logger := createServiceTestLogger()
		svc, err := NewService(ServiceConfig{
			Enabled:                  true,
			PasswordResetCleanupCron: "*/5 * * * *",
			TimeZone:                 "UTC",
		}, logger)
		require.NoError(t, err)

		err = svc.AddCustomJob("*/5 * * * *", "test-job", func() {})
		assert.NoError(t, err)

		entries := svc.GetJobEntries()
		assert.Len(t, entries, 1)
	})

	t.Run("returns error when service is disabled", func(t *testing.T) {
		logger := createServiceTestLogger()
		svc, err := NewService(ServiceConfig{
			Enabled: false,
		}, logger)
		require.NoError(t, err)

		err = svc.AddCustomJob("*/5 * * * *", "test-job", func() {})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cron service is disabled")
	})

	t.Run("adds multiple jobs", func(t *testing.T) {
		logger := createServiceTestLogger()
		svc, err := NewService(ServiceConfig{
			Enabled:                  true,
			PasswordResetCleanupCron: "*/5 * * * *",
			TimeZone:                 "UTC",
		}, logger)
		require.NoError(t, err)

		err = svc.AddCustomJob("*/5 * * * *", "job-1", func() {})
		require.NoError(t, err)

		err = svc.AddCustomJob("0 * * * *", "job-2", func() {})
		require.NoError(t, err)

		entries := svc.GetJobEntries()
		assert.Len(t, entries, 2)
	})
}

func TestService_AddCustomJob_InvalidSchedule(t *testing.T) {
	logger := createServiceTestLogger()
	svc, err := NewService(ServiceConfig{
		Enabled:                  true,
		PasswordResetCleanupCron: "*/5 * * * *",
		TimeZone:                 "UTC",
	}, logger)
	require.NoError(t, err)

	tests := []struct {
		name     string
		cronExpr string
	}{
		{
			name:     "empty expression",
			cronExpr: "",
		},
		{
			name:     "too few fields",
			cronExpr: "0 0 *",
		},
		{
			name:     "invalid field value",
			cronExpr: "60 * * * *",
		},
		{
			name:     "garbage input",
			cronExpr: "not-a-cron",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := svc.AddCustomJob(tt.cronExpr, "bad-job", func() {})
			assert.Error(t, err)
		})
	}
}

func TestService_GetJobEntries(t *testing.T) {
	t.Run("returns nil when service is disabled", func(t *testing.T) {
		logger := createServiceTestLogger()
		svc, err := NewService(ServiceConfig{
			Enabled: false,
		}, logger)
		require.NoError(t, err)

		entries := svc.GetJobEntries()
		assert.Nil(t, entries)
	})

	t.Run("returns empty slice when no jobs", func(t *testing.T) {
		logger := createServiceTestLogger()
		svc, err := NewService(ServiceConfig{
			Enabled:                  true,
			PasswordResetCleanupCron: "*/5 * * * *",
			TimeZone:                 "UTC",
		}, logger)
		require.NoError(t, err)

		entries := svc.GetJobEntries()
		assert.Len(t, entries, 0)
	})

	t.Run("returns job info with valid fields", func(t *testing.T) {
		logger := createServiceTestLogger()
		svc, err := NewService(ServiceConfig{
			Enabled:                  true,
			PasswordResetCleanupCron: "*/5 * * * *",
			TimeZone:                 "UTC",
		}, logger)
		require.NoError(t, err)

		err = svc.AddCustomJob("*/5 * * * *", "test-job", func() {})
		require.NoError(t, err)

		svc.Start()
		defer svc.Stop()

		entries := svc.GetJobEntries()
		require.Len(t, entries, 1)
		assert.NotEmpty(t, entries[0].Schedule)
		assert.False(t, entries[0].Next.IsZero())
	})
}

func TestService_IsEnabled(t *testing.T) {
	t.Run("returns true when enabled", func(t *testing.T) {
		logger := createServiceTestLogger()
		svc, err := NewService(ServiceConfig{
			Enabled:                  true,
			PasswordResetCleanupCron: "*/5 * * * *",
			TimeZone:                 "UTC",
		}, logger)
		require.NoError(t, err)
		assert.True(t, svc.IsEnabled())
	})

	t.Run("returns false when disabled", func(t *testing.T) {
		logger := createServiceTestLogger()
		svc, err := NewService(ServiceConfig{
			Enabled: false,
		}, logger)
		require.NoError(t, err)
		assert.False(t, svc.IsEnabled())
	})
}

func TestLoadServiceConfigFromViper(t *testing.T) {
	// Set config values
	config.ServiceCronEnabled.Set(true)
	config.ServiceCronPasswordResetCleanup.Set("0 */2 * * *")
	config.ServiceCronTimeZone.Set("America/New_York")
	defer func() {
		config.ServiceCronEnabled.Set(false)
		config.ServiceCronPasswordResetCleanup.Set("0 0 * * *")
		config.ServiceCronTimeZone.Set("UTC")
	}()

	cfg := LoadServiceConfigFromViper()

	assert.True(t, cfg.Enabled)
	assert.Equal(t, "0 */2 * * *", cfg.PasswordResetCleanupCron)
	assert.Equal(t, "America/New_York", cfg.TimeZone)
}
