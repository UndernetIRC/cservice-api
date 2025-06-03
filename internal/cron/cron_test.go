// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package cron

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/undernetirc/cservice-api/internal/auth/reset"
	"github.com/undernetirc/cservice-api/models"
)

// mockCleanupService implements a mock cleanup service for testing
type mockCleanupService struct {
	runOnceCalled bool
	shouldError   bool
}

func (m *mockCleanupService) RunOnce(ctx context.Context) error {
	m.runOnceCalled = true
	if m.shouldError {
		return assert.AnError
	}
	return nil
}

// Create a logger that discards output for testing
func createTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.Equal(t, "*/5 * * * *", config.PasswordResetCleanupCron)
	assert.Equal(t, "UTC", config.TimeZone)
}

func TestNewScheduler(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
	}{
		{
			name:        "default config",
			config:      DefaultConfig(),
			expectError: false,
		},
		{
			name: "custom timezone",
			config: Config{
				PasswordResetCleanupCron: "0 */2 * * *",
				TimeZone:                 "America/New_York",
			},
			expectError: false,
		},
		{
			name: "invalid timezone",
			config: Config{
				PasswordResetCleanupCron: "0 */2 * * *",
				TimeZone:                 "Invalid/Timezone",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := createTestLogger()
			scheduler, err := NewScheduler(tt.config, logger)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, scheduler)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, scheduler)

				if scheduler != nil {
					assert.NotNil(t, scheduler.cron)
					assert.NotNil(t, scheduler.logger)
				}
			}
		})
	}
}

func TestScheduler_AddPasswordResetCleanupJob(t *testing.T) {
	tests := []struct {
		name        string
		cronExpr    string
		expectError bool
	}{
		{
			name:        "valid cron expression - every 5 minutes",
			cronExpr:    "*/5 * * * *",
			expectError: false,
		},
		{
			name:        "valid cron expression - every hour",
			cronExpr:    "0 * * * *",
			expectError: false,
		},
		{
			name:        "valid cron expression - daily at midnight",
			cronExpr:    "0 0 * * *",
			expectError: false,
		},
		{
			name:        "invalid cron expression - too few fields",
			cronExpr:    "0 0 *",
			expectError: true,
		},
		{
			name:        "invalid cron expression - invalid field",
			cronExpr:    "60 * * * *",
			expectError: true,
		},
		{
			name:        "invalid cron expression - empty",
			cronExpr:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := createTestLogger()
			scheduler, err := NewScheduler(DefaultConfig(), logger)
			require.NoError(t, err)

			mockCleanup := &mockCleanupService{}
			err = scheduler.AddPasswordResetCleanupJob(tt.cronExpr, mockCleanup)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				// Verify job was added
				entries := scheduler.GetEntries()
				assert.Len(t, entries, 1)
			}
		})
	}
}

func TestScheduler_AddJob(t *testing.T) {
	logger := createTestLogger()
	scheduler, err := NewScheduler(DefaultConfig(), logger)
	require.NoError(t, err)

	jobName := "test-job"
	cronExpr := "*/5 * * * *"

	err = scheduler.AddJob(cronExpr, jobName, func() {
		// Job executed - we don't need to track this for the test
	})

	assert.NoError(t, err)

	// Verify job was added
	entries := scheduler.GetEntries()
	assert.Len(t, entries, 1)

	// Note: We don't test actual execution timing in unit tests
	// as it would make tests slow and flaky
}

func TestScheduler_StartStop(t *testing.T) {
	logger := createTestLogger()
	scheduler, err := NewScheduler(DefaultConfig(), logger)
	require.NoError(t, err)

	// Add a simple job
	err = scheduler.AddJob("*/5 * * * *", "test", func() {})
	require.NoError(t, err)

	// Start scheduler
	scheduler.Start()

	// Verify it's running by checking entries
	entries := scheduler.GetEntries()
	assert.Len(t, entries, 1)
	assert.NotNil(t, entries[0].Next)

	// Stop scheduler
	scheduler.Stop()

	// After stopping, the scheduler should be stopped
	// (We can't easily test this without implementation details)
}

func TestScheduler_Integration(t *testing.T) {
	logger := createTestLogger()
	scheduler, err := NewScheduler(DefaultConfig(), logger)
	require.NoError(t, err)

	// Create mock cleanup service
	mockCleanup := &mockCleanupService{}

	// Add cleanup job - use a very frequent schedule for testing
	// Note: In real usage, you would use "*/5 * * * *" or similar
	err = scheduler.AddPasswordResetCleanupJob("* * * * *", mockCleanup)
	require.NoError(t, err)

	// Start scheduler
	scheduler.Start()
	defer scheduler.Stop()

	// Verify job was scheduled
	entries := scheduler.GetEntries()
	assert.Len(t, entries, 1)
	assert.True(t, entries[0].Next.After(time.Now()))

	// We don't wait for actual execution in unit tests as it would be slow
	// Integration tests should be done separately for timing-dependent behavior
}

func TestCronLogger(t *testing.T) {
	logger := createTestLogger()
	cronLog := &cronLogger{logger: logger}

	// Test Info method - should not panic
	cronLog.Info("test message", "key", "value")

	// Test Error method - should not panic
	cronLog.Error(assert.AnError, "test error message", "key", "value")
}

func TestScheduler_GetEntries(t *testing.T) {
	logger := createTestLogger()
	scheduler, err := NewScheduler(DefaultConfig(), logger)
	require.NoError(t, err)

	// Initially no entries
	entries := scheduler.GetEntries()
	assert.Len(t, entries, 0)

	// Add some jobs
	err = scheduler.AddJob("0 * * * *", "hourly", func() {})
	require.NoError(t, err)

	err = scheduler.AddJob("0 0 * * *", "daily", func() {})
	require.NoError(t, err)

	// Start the scheduler to ensure jobs are scheduled
	scheduler.Start()
	defer scheduler.Stop()

	// Verify entries
	entries = scheduler.GetEntries()
	assert.Len(t, entries, 2)

	// Each entry should have a valid next run time (not zero)
	for _, entry := range entries {
		assert.False(t, entry.Next.IsZero(), "Next run time should not be zero")
	}
}

func TestScheduler_WithNilLogger(t *testing.T) {
	scheduler, err := NewScheduler(DefaultConfig(), nil)
	require.NoError(t, err)
	assert.NotNil(t, scheduler.logger) // Should use default logger
}

func TestPasswordResetCleanupJobExecution(t *testing.T) {
	logger := createTestLogger()
	scheduler, err := NewScheduler(DefaultConfig(), logger)
	require.NoError(t, err)

	// Test successful cleanup
	t.Run("successful cleanup", func(t *testing.T) {
		mockCleanup := &mockCleanupService{shouldError: false}

		err = scheduler.AddPasswordResetCleanupJob("*/5 * * * *", mockCleanup)
		require.NoError(t, err)

		// Manually trigger the job function to test it
		entries := scheduler.GetEntries()
		require.Len(t, entries, 1)

		// The job function is wrapped, we can't easily test it directly
		// This test verifies the job was added successfully
	})

	// Test cleanup with error
	t.Run("cleanup with error", func(t *testing.T) {
		scheduler2, err := NewScheduler(DefaultConfig(), logger)
		require.NoError(t, err)

		mockCleanup := &mockCleanupService{shouldError: true}

		err = scheduler2.AddPasswordResetCleanupJob("*/5 * * * *", mockCleanup)
		require.NoError(t, err)

		// Verify job was added even though it might error during execution
		entries := scheduler2.GetEntries()
		assert.Len(t, entries, 1)
	})
}

// TestRealPasswordResetCleanup tests with actual reset components
// This test is more of an integration test
func TestRealPasswordResetCleanup(t *testing.T) {
	// Skip this test unless we have a real database connection
	t.Skip("Integration test - requires database setup")

	logger := createTestLogger()
	scheduler, err := NewScheduler(DefaultConfig(), logger)
	require.NoError(t, err)

	// This would require actual database setup
	var queries models.Querier = nil
	tokenManager := reset.NewTokenManager(queries, nil)
	cleanupService := reset.NewCleanupService(tokenManager, 1*time.Hour, logger)

	err = scheduler.AddPasswordResetCleanupJob("*/5 * * * *", cleanupService)
	require.NoError(t, err)

	entries := scheduler.GetEntries()
	assert.Len(t, entries, 1)
}
