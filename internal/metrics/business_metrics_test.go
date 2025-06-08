// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
)

func TestNewBusinessMetrics(t *testing.T) {
	tests := []struct {
		name        string
		config      BusinessMetricsConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: BusinessMetricsConfig{
				Meter:       noop.NewMeterProvider().Meter("test"),
				ServiceName: "test-service",
			},
			expectError: false,
		},
		{
			name: "valid config with default service name",
			config: BusinessMetricsConfig{
				Meter: noop.NewMeterProvider().Meter("test"),
			},
			expectError: false,
		},
		{
			name: "nil meter",
			config: BusinessMetricsConfig{
				ServiceName: "test-service",
			},
			expectError: true,
			errorMsg:    "meter cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics, err := NewBusinessMetrics(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, metrics)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, metrics)

				// Verify all metric instruments are created
				assert.NotNil(t, metrics.registrationAttempts)
				assert.NotNil(t, metrics.registrationSuccesses)
				assert.NotNil(t, metrics.registrationFailures)
				assert.NotNil(t, metrics.registrationDuration)
				assert.NotNil(t, metrics.activationAttempts)
				assert.NotNil(t, metrics.activationSuccesses)
				assert.NotNil(t, metrics.activationFailures)
				assert.NotNil(t, metrics.activationDuration)
				assert.NotNil(t, metrics.pendingRegistrations)
				assert.NotNil(t, metrics.registrationConversion)
				assert.NotNil(t, metrics.channelSearches)
				assert.NotNil(t, metrics.channelSearchDuration)
				assert.NotNil(t, metrics.channelSearchResults)
				assert.NotNil(t, metrics.channelSettingsViews)
				assert.NotNil(t, metrics.channelSettingsUpdates)
				assert.NotNil(t, metrics.channelMemberAdded)
				assert.NotNil(t, metrics.channelMemberRemoved)
				assert.NotNil(t, metrics.channelOperationErrors)
				assert.NotNil(t, metrics.activeUsers)
				assert.NotNil(t, metrics.userSessions)
				assert.NotNil(t, metrics.sessionDuration)
				assert.NotNil(t, metrics.apiRequestsTotal)
				assert.NotNil(t, metrics.featureUsage)
				assert.NotNil(t, metrics.errorRate)
				assert.NotNil(t, metrics.responseTime)
				assert.NotNil(t, metrics.throughput)
				assert.NotNil(t, metrics.conversionFunnel)
			}
		})
	}
}

func TestBusinessMetrics_RecordRegistrationAttempt(t *testing.T) {
	// Create a test meter provider
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(resource.Empty()),
		sdkmetric.WithReader(reader),
	)
	meter := provider.Meter("test")

	// Create business metrics
	businessMetrics, err := NewBusinessMetrics(BusinessMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	})
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name     string
		username string
		email    string
		success  bool
		duration time.Duration
		reason   string
	}{
		{
			name:     "successful registration",
			username: "testuser",
			email:    "test@example.com",
			success:  true,
			duration: 150 * time.Millisecond,
			reason:   "success",
		},
		{
			name:     "failed registration",
			username: "baduser",
			email:    "bad@example.com",
			success:  false,
			duration: 100 * time.Millisecond,
			reason:   "username_exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Record the registration attempt
			businessMetrics.RecordRegistrationAttempt(ctx, tt.username, tt.email, tt.success, tt.duration, tt.reason)

			// Collect metrics
			rm := &metricdata.ResourceMetrics{}
			err := reader.Collect(ctx, rm)
			require.NoError(t, err)

			// Verify metrics were recorded
			assert.NotEmpty(t, rm.ScopeMetrics)
		})
	}
}

func TestBusinessMetrics_RecordChannelSearch(t *testing.T) {
	// Create a test meter provider
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(resource.Empty()),
		sdkmetric.WithReader(reader),
	)
	meter := provider.Meter("test")

	// Create business metrics
	businessMetrics, err := NewBusinessMetrics(BusinessMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	})
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name        string
		userID      int32
		query       string
		resultCount int
		duration    time.Duration
		success     bool
	}{
		{
			name:        "successful search",
			userID:      123,
			query:       "#test",
			resultCount: 5,
			duration:    100 * time.Millisecond,
			success:     true,
		},
		{
			name:        "failed search",
			userID:      124,
			query:       "error",
			resultCount: 0,
			duration:    50 * time.Millisecond,
			success:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Record the channel search
			businessMetrics.RecordChannelSearch(ctx, tt.userID, tt.query, tt.resultCount, tt.duration, tt.success)

			// Collect metrics
			rm := &metricdata.ResourceMetrics{}
			err := reader.Collect(ctx, rm)
			require.NoError(t, err)

			// Verify metrics were recorded
			assert.NotEmpty(t, rm.ScopeMetrics)
		})
	}
}

func TestBusinessMetrics_RecordFeatureUsage(t *testing.T) {
	// Create a test meter provider
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(resource.Empty()),
		sdkmetric.WithReader(reader),
	)
	meter := provider.Meter("test")

	// Create business metrics
	businessMetrics, err := NewBusinessMetrics(BusinessMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	})
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name        string
		feature     string
		userID      int32
		contextInfo map[string]string
	}{
		{
			name:    "channel search feature",
			feature: "channel_search",
			userID:  123,
			contextInfo: map[string]string{
				"search_type": "wildcard",
				"results":     "5",
			},
		},
		{
			name:        "simple feature",
			feature:     "simple_feature",
			userID:      124,
			contextInfo: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Record feature usage
			businessMetrics.RecordFeatureUsage(ctx, tt.feature, tt.userID, tt.contextInfo)

			// Collect metrics
			rm := &metricdata.ResourceMetrics{}
			err := reader.Collect(ctx, rm)
			require.NoError(t, err)

			// Verify metrics were recorded
			assert.NotEmpty(t, rm.ScopeMetrics)
		})
	}
}

func TestGetQueryType(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected string
	}{
		{
			name:     "empty query",
			query:    "",
			expected: "empty",
		},
		{
			name:     "channel name query",
			query:    "#test",
			expected: "channel_name",
		},
		{
			name:     "single character query",
			query:    "a",
			expected: "single_char",
		},
		{
			name:     "short query",
			query:    "ab",
			expected: "short",
		},
		{
			name:     "normal query",
			query:    "test",
			expected: "normal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getQueryType(tt.query)
			assert.Equal(t, tt.expected, result)
		})
	}
}
