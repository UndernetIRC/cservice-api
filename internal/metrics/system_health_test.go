// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package metrics

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
)

func TestNewSystemHealthMetrics(t *testing.T) {
	tests := []struct {
		name        string
		config      SystemHealthMetricsConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config with all callbacks",
			config: SystemHealthMetricsConfig{
				Meter:             noop.NewMeterProvider().Meter("test"),
				ServiceName:       "test-service",
				GetMailQueueDepth: func() int64 { return 5 },
				GetWorkerCount:    func() int64 { return 3 },
				GetSystemStatus:   func() int64 { return 1 },
			},
			expectError: false,
		},
		{
			name: "valid config with default service name",
			config: SystemHealthMetricsConfig{
				Meter: noop.NewMeterProvider().Meter("test"),
			},
			expectError: false,
		},
		{
			name: "valid config with partial callbacks",
			config: SystemHealthMetricsConfig{
				Meter:             noop.NewMeterProvider().Meter("test"),
				ServiceName:       "partial-service",
				GetMailQueueDepth: func() int64 { return 10 },
			},
			expectError: false,
		},
		{
			name: "missing meter",
			config: SystemHealthMetricsConfig{
				ServiceName: "test-service",
			},
			expectError: true,
			errorMsg:    "meter is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics, err := NewSystemHealthMetrics(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, metrics)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, metrics)

				// Verify service name
				expectedServiceName := tt.config.ServiceName
				if expectedServiceName == "" {
					expectedServiceName = "cservice-api"
				}
				assert.Equal(t, expectedServiceName, metrics.serviceName)

				// Verify start time is recent
				assert.True(t, time.Since(metrics.startTime) < time.Second)

				// Verify callbacks are set
				if tt.config.GetMailQueueDepth != nil {
					assert.NotNil(t, metrics.getMailQueueDepth)
				}
				if tt.config.GetWorkerCount != nil {
					assert.NotNil(t, metrics.getWorkerCount)
				}
				if tt.config.GetSystemStatus != nil {
					assert.NotNil(t, metrics.getSystemStatus)
				}
			}
		})
	}
}

func TestSystemHealthMetrics_RecordMailProcessing(t *testing.T) {
	meter := noop.NewMeterProvider().Meter("test")
	config := SystemHealthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	}

	metrics, err := NewSystemHealthMetrics(config)
	require.NoError(t, err)
	require.NotNil(t, metrics)

	ctx := context.Background()

	tests := []struct {
		name      string
		recipient string
		duration  time.Duration
		err       error
	}{
		{
			name:      "successful mail processing",
			recipient: "user@example.com",
			duration:  100 * time.Millisecond,
			err:       nil,
		},
		{
			name:      "failed mail processing - smtp error",
			recipient: "user@example.com",
			duration:  50 * time.Millisecond,
			err:       errors.New("smtp connection failed"),
		},
		{
			name:      "failed mail processing - timeout error",
			recipient: "user@example.com",
			duration:  5 * time.Second,
			err:       errors.New("operation timeout"),
		},
		{
			name:      "failed mail processing - template error",
			recipient: "user@example.com",
			duration:  10 * time.Millisecond,
			err:       errors.New("template parsing failed"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			// This should not panic or return an error
			metrics.RecordMailProcessing(ctx, tt.recipient, tt.duration, tt.err)
		})
	}
}

func TestSystemHealthMetrics_RecordCronJobExecution(t *testing.T) {
	meter := noop.NewMeterProvider().Meter("test")
	config := SystemHealthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	}

	metrics, err := NewSystemHealthMetrics(config)
	require.NoError(t, err)
	require.NotNil(t, metrics)

	ctx := context.Background()

	tests := []struct {
		name     string
		jobName  string
		duration time.Duration
		err      error
	}{
		{
			name:     "successful cron job",
			jobName:  "password_reset_cleanup",
			duration: 200 * time.Millisecond,
			err:      nil,
		},
		{
			name:     "failed cron job - database error",
			jobName:  "password_reset_cleanup",
			duration: 1 * time.Second,
			err:      errors.New("database connection failed"),
		},
		{
			name:     "failed cron job - context error",
			jobName:  "custom_cleanup",
			duration: 30 * time.Second,
			err:      errors.New("context deadline exceeded"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			// This should not panic or return an error
			metrics.RecordCronJobExecution(ctx, tt.jobName, tt.duration, tt.err)
		})
	}
}

func TestSystemHealthMetrics_MeasureMailProcessing(t *testing.T) {
	meter := noop.NewMeterProvider().Meter("test")
	config := SystemHealthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	}

	metrics, err := NewSystemHealthMetrics(config)
	require.NoError(t, err)
	require.NotNil(t, metrics)

	ctx := context.Background()

	t.Run("successful operation", func(t *testing.T) {
		called := false
		err := metrics.MeasureMailProcessing(ctx, "user@example.com", func() error {
			called = true
			time.Sleep(10 * time.Millisecond) // Simulate work
			return nil
		})

		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("failed operation", func(t *testing.T) {
		expectedErr := errors.New("mail sending failed")
		called := false

		err := metrics.MeasureMailProcessing(ctx, "user@example.com", func() error {
			called = true
			time.Sleep(5 * time.Millisecond) // Simulate work
			return expectedErr
		})

		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		assert.True(t, called)
	})
}

func TestSystemHealthMetrics_MeasureCronJobExecution(t *testing.T) {
	meter := noop.NewMeterProvider().Meter("test")
	config := SystemHealthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	}

	metrics, err := NewSystemHealthMetrics(config)
	require.NoError(t, err)
	require.NotNil(t, metrics)

	ctx := context.Background()

	t.Run("successful operation", func(t *testing.T) {
		called := false
		err := metrics.MeasureCronJobExecution(ctx, "test_job", func() error {
			called = true
			time.Sleep(10 * time.Millisecond) // Simulate work
			return nil
		})

		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("failed operation", func(t *testing.T) {
		expectedErr := errors.New("job execution failed")
		called := false

		err := metrics.MeasureCronJobExecution(ctx, "test_job", func() error {
			called = true
			time.Sleep(5 * time.Millisecond) // Simulate work
			return expectedErr
		})

		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		assert.True(t, called)
	})
}

func TestSystemHealthMetrics_NilSafety(t *testing.T) {
	ctx := context.Background()

	// Test that methods are safe to call on nil metrics
	var metrics *SystemHealthMetrics

	// These should not panic
	metrics.RecordMailProcessing(ctx, "user@example.com", time.Millisecond, nil)
	metrics.RecordCronJobExecution(ctx, "test_job", time.Millisecond, nil)

	// These should return the original error without panicking
	testErr := errors.New("test error")
	err := metrics.MeasureMailProcessing(ctx, "user@example.com", func() error {
		return testErr
	})
	assert.Equal(t, testErr, err)

	err = metrics.MeasureCronJobExecution(ctx, "test_job", func() error {
		return testErr
	})
	assert.Equal(t, testErr, err)
}

func TestGetErrorType(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: "none",
		},
		{
			name:     "timeout error",
			err:      errors.New("operation timeout exceeded"),
			expected: "timeout",
		},
		{
			name:     "connection error",
			err:      errors.New("connection refused"),
			expected: "connection",
		},
		{
			name:     "smtp error",
			err:      errors.New("smtp authentication failed"),
			expected: "smtp",
		},
		{
			name:     "template error",
			err:      errors.New("template parsing error"),
			expected: "template",
		},
		{
			name:     "database error",
			err:      errors.New("database query failed"),
			expected: "database",
		},
		{
			name:     "context error",
			err:      errors.New("context deadline exceeded"),
			expected: "context",
		},
		{
			name:     "unknown error",
			err:      errors.New("some random error"),
			expected: "unknown",
		},
		{
			name:     "case insensitive matching",
			err:      errors.New("SMTP Authentication Failed"),
			expected: "smtp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getErrorType(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		substr   string
		expected bool
	}{
		{
			name:     "exact match",
			s:        "timeout",
			substr:   "timeout",
			expected: true,
		},
		{
			name:     "substring found",
			s:        "operation timeout exceeded",
			substr:   "timeout",
			expected: true,
		},
		{
			name:     "case insensitive match",
			s:        "SMTP Error",
			substr:   "smtp",
			expected: true,
		},
		{
			name:     "substring not found",
			s:        "connection error",
			substr:   "timeout",
			expected: false,
		},
		{
			name:     "empty substring",
			s:        "any string",
			substr:   "",
			expected: true,
		},
		{
			name:     "empty string",
			s:        "",
			substr:   "test",
			expected: false,
		},
		{
			name:     "both empty",
			s:        "",
			substr:   "",
			expected: true,
		},
		{
			name:     "substring longer than string",
			s:        "hi",
			substr:   "hello",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(tt.s, tt.substr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestToLower(t *testing.T) {
	tests := []struct {
		name     string
		input    byte
		expected byte
	}{
		{
			name:     "uppercase A",
			input:    'A',
			expected: 'a',
		},
		{
			name:     "uppercase Z",
			input:    'Z',
			expected: 'z',
		},
		{
			name:     "lowercase a",
			input:    'a',
			expected: 'a',
		},
		{
			name:     "lowercase z",
			input:    'z',
			expected: 'z',
		},
		{
			name:     "number",
			input:    '5',
			expected: '5',
		},
		{
			name:     "special character",
			input:    '@',
			expected: '@',
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toLower(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSystemHealthMetrics_CallbackFunctions(t *testing.T) {
	meter := noop.NewMeterProvider().Meter("test")

	// Test with all callbacks
	queueDepth := int64(15)
	workerCount := int64(5)
	systemStatus := int64(1)

	config := SystemHealthMetricsConfig{
		Meter:             meter,
		ServiceName:       "test-service",
		GetMailQueueDepth: func() int64 { return queueDepth },
		GetWorkerCount:    func() int64 { return workerCount },
		GetSystemStatus:   func() int64 { return systemStatus },
	}

	metrics, err := NewSystemHealthMetrics(config)
	require.NoError(t, err)
	require.NotNil(t, metrics)

	// Verify callbacks are stored
	assert.NotNil(t, metrics.getMailQueueDepth)
	assert.NotNil(t, metrics.getWorkerCount)
	assert.NotNil(t, metrics.getSystemStatus)

	// Test callback execution
	assert.Equal(t, queueDepth, metrics.getMailQueueDepth())
	assert.Equal(t, workerCount, metrics.getWorkerCount())
	assert.Equal(t, systemStatus, metrics.getSystemStatus())
}

func TestSystemHealthMetrics_CallbacksNil(t *testing.T) {
	meter := noop.NewMeterProvider().Meter("test")

	// Test with no callbacks
	config := SystemHealthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	}

	metrics, err := NewSystemHealthMetrics(config)
	require.NoError(t, err)
	require.NotNil(t, metrics)

	// Verify callbacks are nil
	assert.Nil(t, metrics.getMailQueueDepth)
	assert.Nil(t, metrics.getWorkerCount)
	assert.Nil(t, metrics.getSystemStatus)
}
