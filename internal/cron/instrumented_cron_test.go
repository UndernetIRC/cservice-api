// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package cron

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/undernetirc/cservice-api/internal/metrics"
	"go.opentelemetry.io/otel/metric/noop"
)

// instrumentedMockCleanupService implements CleanupServiceInterface for testing
type instrumentedMockCleanupService struct {
	shouldError bool
	callCount   int
}

func (m *instrumentedMockCleanupService) RunOnce(_ context.Context) error {
	m.callCount++
	if m.shouldError {
		return errors.New("mock cleanup error")
	}
	return nil
}

func TestNewInstrumentedScheduler(t *testing.T) {
	// Create mock system metrics
	meter := noop.NewMeterProvider().Meter("test")
	config := metrics.SystemHealthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	}

	systemMetrics, err := metrics.NewSystemHealthMetrics(config)
	require.NoError(t, err)

	// Test creation with valid config
	cronConfig := DefaultConfig()
	logger := slog.Default()

	scheduler, err := NewInstrumentedScheduler(cronConfig, logger, systemMetrics)
	require.NoError(t, err)
	assert.NotNil(t, scheduler)
	assert.NotNil(t, scheduler.scheduler)
	assert.Equal(t, systemMetrics, scheduler.systemMetrics)
	assert.Equal(t, int64(0), scheduler.activeJobs)
	assert.Equal(t, int64(0), scheduler.totalJobs)
}

func TestNewInstrumentedScheduler_InvalidConfig(t *testing.T) {
	// Test with invalid timezone
	cronConfig := Config{
		PasswordResetCleanupCron: "*/5 * * * *",
		TimeZone:                 "Invalid/Timezone",
	}
	logger := slog.Default()

	scheduler, err := NewInstrumentedScheduler(cronConfig, logger, nil)
	assert.Error(t, err)
	assert.Nil(t, scheduler)
}

func TestInstrumentedScheduler_GetActiveJobCount(t *testing.T) {
	scheduler := &InstrumentedScheduler{
		activeJobs: 5,
	}

	count := scheduler.GetActiveJobCount()
	assert.Equal(t, int64(5), count)
}

func TestInstrumentedScheduler_GetTotalJobCount(t *testing.T) {
	scheduler := &InstrumentedScheduler{
		totalJobs: 3,
	}

	count := scheduler.GetTotalJobCount()
	assert.Equal(t, int64(3), count)
}

func TestInstrumentedScheduler_AddPasswordResetCleanupJob(t *testing.T) {
	// Create mock system metrics
	meter := noop.NewMeterProvider().Meter("test")
	config := metrics.SystemHealthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	}

	systemMetrics, err := metrics.NewSystemHealthMetrics(config)
	require.NoError(t, err)

	// Create scheduler
	cronConfig := DefaultConfig()
	logger := slog.Default()

	scheduler, err := NewInstrumentedScheduler(cronConfig, logger, systemMetrics)
	require.NoError(t, err)

	// Create mock cleanup service
	mockService := &instrumentedMockCleanupService{}

	// Add job
	err = scheduler.AddPasswordResetCleanupJob("@every 1m", mockService)
	assert.NoError(t, err)

	// Check that total job count increased
	assert.Equal(t, int64(1), scheduler.GetTotalJobCount())

	// Check that job was added to scheduler
	entries := scheduler.GetEntries()
	assert.Len(t, entries, 1)
}

func TestInstrumentedScheduler_AddJob(t *testing.T) {
	// Create mock system metrics
	meter := noop.NewMeterProvider().Meter("test")
	config := metrics.SystemHealthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	}

	systemMetrics, err := metrics.NewSystemHealthMetrics(config)
	require.NoError(t, err)

	// Create scheduler
	cronConfig := DefaultConfig()
	logger := slog.Default()

	scheduler, err := NewInstrumentedScheduler(cronConfig, logger, systemMetrics)
	require.NoError(t, err)

	// Add job
	err = scheduler.AddJob("@every 1m", "test_job", func() {
		// Job executed - we don't need to track this for the test
	})
	assert.NoError(t, err)

	// Check that total job count increased
	assert.Equal(t, int64(1), scheduler.GetTotalJobCount())

	// Check that job was added to scheduler
	entries := scheduler.GetEntries()
	assert.Len(t, entries, 1)
}

func TestInstrumentedScheduler_AddJobWithError(t *testing.T) {
	// Create mock system metrics
	meter := noop.NewMeterProvider().Meter("test")
	config := metrics.SystemHealthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	}

	systemMetrics, err := metrics.NewSystemHealthMetrics(config)
	require.NoError(t, err)

	// Create scheduler
	cronConfig := DefaultConfig()
	logger := slog.Default()

	scheduler, err := NewInstrumentedScheduler(cronConfig, logger, systemMetrics)
	require.NoError(t, err)

	// Add job that returns error
	err = scheduler.AddJobWithError("@every 1m", "error_job", func() error {
		return errors.New("test error")
	})
	assert.NoError(t, err)

	// Check that total job count increased
	assert.Equal(t, int64(1), scheduler.GetTotalJobCount())

	// Add job that succeeds
	err = scheduler.AddJobWithError("@every 2m", "success_job", func() error {
		return nil
	})
	assert.NoError(t, err)

	// Check that total job count increased
	assert.Equal(t, int64(2), scheduler.GetTotalJobCount())
}

func TestInstrumentedScheduler_StartStop(t *testing.T) {
	// Create scheduler
	cronConfig := DefaultConfig()
	logger := slog.Default()

	scheduler, err := NewInstrumentedScheduler(cronConfig, logger, nil)
	require.NoError(t, err)

	// Test start and stop
	scheduler.Start()

	// Give it a moment to start
	time.Sleep(10 * time.Millisecond)

	scheduler.Stop()

	// Test should complete without hanging
}

func TestInstrumentedScheduler_GetSystemHealthCallbacks(t *testing.T) {
	scheduler := &InstrumentedScheduler{
		activeJobs: 2,
		totalJobs:  5,
	}

	getActiveJobCount, getTotalJobCount := scheduler.GetSystemHealthCallbacks()

	assert.Equal(t, int64(2), getActiveJobCount())
	assert.Equal(t, int64(5), getTotalJobCount())
}

func TestInstrumentedScheduler_GetSystemStatus(t *testing.T) {
	// Create mock system metrics
	meter := noop.NewMeterProvider().Meter("test")
	config := metrics.SystemHealthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	}

	systemMetrics, err := metrics.NewSystemHealthMetrics(config)
	require.NoError(t, err)

	tests := []struct {
		name           string
		setupFunc      func() *InstrumentedScheduler
		expectedStatus int64
		description    string
	}{
		{
			name: "unhealthy - nil scheduler",
			setupFunc: func() *InstrumentedScheduler {
				return &InstrumentedScheduler{
					scheduler: nil,
				}
			},
			expectedStatus: 0,
			description:    "Should be unhealthy when scheduler is nil",
		},
		{
			name: "unhealthy - no jobs scheduled",
			setupFunc: func() *InstrumentedScheduler {
				cronConfig := DefaultConfig()
				logger := slog.Default()
				scheduler, _ := NewInstrumentedScheduler(cronConfig, logger, systemMetrics)
				return scheduler
			},
			expectedStatus: 0,
			description:    "Should be unhealthy when no jobs are scheduled",
		},
		{
			name: "unhealthy - all jobs running (potential deadlock)",
			setupFunc: func() *InstrumentedScheduler {
				cronConfig := DefaultConfig()
				logger := slog.Default()
				scheduler, _ := NewInstrumentedScheduler(cronConfig, logger, systemMetrics)

				// Add a job to make totalJobs > 0
				scheduler.AddJob("@every 1m", "test_job", func() {})

				// Simulate all jobs running
				scheduler.activeJobs = scheduler.totalJobs

				return scheduler
			},
			expectedStatus: 0,
			description:    "Should be unhealthy when all jobs are running simultaneously",
		},
		{
			name: "healthy - normal operation",
			setupFunc: func() *InstrumentedScheduler {
				cronConfig := DefaultConfig()
				logger := slog.Default()
				scheduler, _ := NewInstrumentedScheduler(cronConfig, logger, systemMetrics)

				// Add some jobs
				scheduler.AddJob("@every 1m", "job1", func() {})
				scheduler.AddJob("@every 2m", "job2", func() {})

				// Simulate some jobs running but not all
				scheduler.activeJobs = 1

				return scheduler
			},
			expectedStatus: 1,
			description:    "Should be healthy with jobs scheduled and reasonable activity",
		},
		{
			name: "healthy - jobs scheduled but none running",
			setupFunc: func() *InstrumentedScheduler {
				cronConfig := DefaultConfig()
				logger := slog.Default()
				scheduler, _ := NewInstrumentedScheduler(cronConfig, logger, systemMetrics)

				// Add a job
				scheduler.AddJob("@every 1m", "test_job", func() {})

				// No jobs currently running
				scheduler.activeJobs = 0

				return scheduler
			},
			expectedStatus: 1,
			description:    "Should be healthy with jobs scheduled but none currently running",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheduler := tt.setupFunc()
			status := scheduler.GetSystemStatus()
			assert.Equal(t, tt.expectedStatus, status, tt.description)
		})
	}
}

func TestInstrumentedCleanupService_RunOnce(t *testing.T) {
	// Create mock system metrics
	meter := noop.NewMeterProvider().Meter("test")
	config := metrics.SystemHealthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	}

	systemMetrics, err := metrics.NewSystemHealthMetrics(config)
	require.NoError(t, err)

	// Test successful execution
	t.Run("successful execution", func(t *testing.T) {
		mockService := &instrumentedMockCleanupService{shouldError: false}
		activeJobs := int64(0)

		instrumentedService := &instrumentedCleanupService{
			service:       mockService,
			systemMetrics: systemMetrics,
			activeJobs:    &activeJobs,
			jobName:       "test_cleanup",
		}

		ctx := context.Background()
		err := instrumentedService.RunOnce(ctx)
		assert.NoError(t, err)
		assert.Equal(t, 1, mockService.callCount)
	})

	// Test error execution
	t.Run("error execution", func(t *testing.T) {
		mockService := &instrumentedMockCleanupService{shouldError: true}
		activeJobs := int64(0)

		instrumentedService := &instrumentedCleanupService{
			service:       mockService,
			systemMetrics: systemMetrics,
			activeJobs:    &activeJobs,
			jobName:       "test_cleanup",
		}

		ctx := context.Background()
		err := instrumentedService.RunOnce(ctx)
		assert.Error(t, err)
		assert.Equal(t, 1, mockService.callCount)
	})

	// Test without metrics
	t.Run("without metrics", func(t *testing.T) {
		mockService := &instrumentedMockCleanupService{shouldError: false}
		activeJobs := int64(0)

		instrumentedService := &instrumentedCleanupService{
			service:       mockService,
			systemMetrics: nil,
			activeJobs:    &activeJobs,
			jobName:       "test_cleanup",
		}

		ctx := context.Background()
		err := instrumentedService.RunOnce(ctx)
		assert.NoError(t, err)
		assert.Equal(t, 1, mockService.callCount)
	})
}
