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

func TestNewAuthMetrics(t *testing.T) {
	tests := []struct {
		name        string
		config      AuthMetricsConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: AuthMetricsConfig{
				Meter:       noop.NewMeterProvider().Meter("test"),
				ServiceName: "test-service",
			},
			expectError: false,
		},
		{
			name: "valid config with default service name",
			config: AuthMetricsConfig{
				Meter: noop.NewMeterProvider().Meter("test"),
			},
			expectError: false,
		},
		{
			name: "nil meter",
			config: AuthMetricsConfig{
				ServiceName: "test-service",
			},
			expectError: true,
			errorMsg:    "meter cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics, err := NewAuthMetrics(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, metrics)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, metrics)

				// Verify all metric instruments are created
				assert.NotNil(t, metrics.loginAttempts)
				assert.NotNil(t, metrics.loginDuration)
				assert.NotNil(t, metrics.loginSuccesses)
				assert.NotNil(t, metrics.loginFailures)
				assert.NotNil(t, metrics.mfaAttempts)
				assert.NotNil(t, metrics.mfaSuccesses)
				assert.NotNil(t, metrics.mfaFailures)
				assert.NotNil(t, metrics.mfaDuration)
				assert.NotNil(t, metrics.tokenGenerated)
				assert.NotNil(t, metrics.tokenRefreshed)
				assert.NotNil(t, metrics.tokenRevoked)
				assert.NotNil(t, metrics.tokenValidated)
				assert.NotNil(t, metrics.tokenExpired)
				assert.NotNil(t, metrics.activeSessions)
				assert.NotNil(t, metrics.sessionDuration)
				assert.NotNil(t, metrics.passwordResetRequests)
				assert.NotNil(t, metrics.passwordResetSuccess)
				assert.NotNil(t, metrics.passwordResetFailures)
			}
		})
	}
}

func TestAuthMetrics_RecordLoginAttempt(t *testing.T) {
	// Create a test meter provider
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(resource.Empty()),
		sdkmetric.WithReader(reader),
	)
	meter := provider.Meter("test")

	// Create auth metrics
	authMetrics, err := NewAuthMetrics(AuthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	})
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name     string
		username string
		success  bool
		duration time.Duration
		reason   string
	}{
		{
			name:     "successful login",
			username: "testuser",
			success:  true,
			duration: 100 * time.Millisecond,
			reason:   "",
		},
		{
			name:     "failed login with reason",
			username: "baduser",
			success:  false,
			duration: 50 * time.Millisecond,
			reason:   "invalid_password",
		},
		{
			name:     "failed login without reason",
			username: "anotheruser",
			success:  false,
			duration: 75 * time.Millisecond,
			reason:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Record the login attempt
			authMetrics.RecordLoginAttempt(ctx, tt.username, tt.success, tt.duration, tt.reason)

			// Collect metrics
			rm := &metricdata.ResourceMetrics{}
			err := reader.Collect(ctx, rm)
			require.NoError(t, err)

			// Verify metrics were recorded
			assert.NotEmpty(t, rm.ScopeMetrics)

			// Find our metrics
			var foundAttempts, foundDuration, foundSuccess, foundFailure bool
			for _, sm := range rm.ScopeMetrics {
				for _, metric := range sm.Metrics {
					switch metric.Name {
					case "auth_login_attempts_total":
						foundAttempts = true
					case "auth_login_duration_ms":
						foundDuration = true
					case "auth_login_successes_total":
						if tt.success {
							foundSuccess = true
						}
					case "auth_login_failures_total":
						if !tt.success {
							foundFailure = true
						}
					}
				}
			}

			assert.True(t, foundAttempts, "login attempts metric should be recorded")
			assert.True(t, foundDuration, "login duration metric should be recorded")

			if tt.success {
				assert.True(t, foundSuccess, "login success metric should be recorded for successful login")
			} else {
				assert.True(t, foundFailure, "login failure metric should be recorded for failed login")
			}
		})
	}
}

func TestAuthMetrics_RecordMFAAttempt(t *testing.T) {
	// Create a test meter provider
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(resource.Empty()),
		sdkmetric.WithReader(reader),
	)
	meter := provider.Meter("test")

	// Create auth metrics
	authMetrics, err := NewAuthMetrics(AuthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	})
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name     string
		userID   int32
		success  bool
		duration time.Duration
		method   string
	}{
		{
			name:     "successful TOTP",
			userID:   123,
			success:  true,
			duration: 200 * time.Millisecond,
			method:   "totp",
		},
		{
			name:     "failed TOTP",
			userID:   456,
			success:  false,
			duration: 150 * time.Millisecond,
			method:   "totp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Record the MFA attempt
			authMetrics.RecordMFAAttempt(ctx, tt.userID, tt.success, tt.duration, tt.method)

			// Collect metrics
			rm := &metricdata.ResourceMetrics{}
			err := reader.Collect(ctx, rm)
			require.NoError(t, err)

			// Verify metrics were recorded
			assert.NotEmpty(t, rm.ScopeMetrics)

			// Find our metrics
			var foundAttempts, foundDuration, foundSuccess, foundFailure bool
			for _, sm := range rm.ScopeMetrics {
				for _, metric := range sm.Metrics {
					switch metric.Name {
					case "auth_mfa_attempts_total":
						foundAttempts = true
					case "auth_mfa_duration_ms":
						foundDuration = true
					case "auth_mfa_successes_total":
						if tt.success {
							foundSuccess = true
						}
					case "auth_mfa_failures_total":
						if !tt.success {
							foundFailure = true
						}
					}
				}
			}

			assert.True(t, foundAttempts, "MFA attempts metric should be recorded")
			assert.True(t, foundDuration, "MFA duration metric should be recorded")

			if tt.success {
				assert.True(t, foundSuccess, "MFA success metric should be recorded for successful attempt")
			} else {
				assert.True(t, foundFailure, "MFA failure metric should be recorded for failed attempt")
			}
		})
	}
}

func TestAuthMetrics_RecordTokenOperations(t *testing.T) {
	// Create a test meter provider
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(resource.Empty()),
		sdkmetric.WithReader(reader),
	)
	meter := provider.Meter("test")

	// Create auth metrics
	authMetrics, err := NewAuthMetrics(AuthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	})
	require.NoError(t, err)

	ctx := context.Background()
	userID := int32(123)

	t.Run("token generated", func(t *testing.T) {
		authMetrics.RecordTokenGenerated(ctx, userID, "access_token")

		rm := &metricdata.ResourceMetrics{}
		err := reader.Collect(ctx, rm)
		require.NoError(t, err)

		// Verify token generated metric
		found := false
		for _, sm := range rm.ScopeMetrics {
			for _, metric := range sm.Metrics {
				if metric.Name == "auth_tokens_generated_total" {
					found = true
					break
				}
			}
		}
		assert.True(t, found, "token generated metric should be recorded")
	})

	t.Run("token refreshed", func(t *testing.T) {
		authMetrics.RecordTokenRefreshed(ctx, userID, true)

		rm := &metricdata.ResourceMetrics{}
		err := reader.Collect(ctx, rm)
		require.NoError(t, err)

		// Verify token refreshed metric
		found := false
		for _, sm := range rm.ScopeMetrics {
			for _, metric := range sm.Metrics {
				if metric.Name == "auth_tokens_refreshed_total" {
					found = true
					break
				}
			}
		}
		assert.True(t, found, "token refreshed metric should be recorded")
	})

	t.Run("token revoked", func(t *testing.T) {
		authMetrics.RecordTokenRevoked(ctx, userID, "logout")

		rm := &metricdata.ResourceMetrics{}
		err := reader.Collect(ctx, rm)
		require.NoError(t, err)

		// Verify token revoked metric
		found := false
		for _, sm := range rm.ScopeMetrics {
			for _, metric := range sm.Metrics {
				if metric.Name == "auth_tokens_revoked_total" {
					found = true
					break
				}
			}
		}
		assert.True(t, found, "token revoked metric should be recorded")
	})
}

func TestAuthMetrics_RecordTokenValidation(t *testing.T) {
	// Create a test meter provider
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(resource.Empty()),
		sdkmetric.WithReader(reader),
	)
	meter := provider.Meter("test")

	// Create auth metrics
	authMetrics, err := NewAuthMetrics(AuthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	})
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name          string
		success       bool
		reason        string
		expectExpired bool
	}{
		{
			name:          "successful validation",
			success:       true,
			reason:        "",
			expectExpired: false,
		},
		{
			name:          "expired token",
			success:       false,
			reason:        "expired",
			expectExpired: true,
		},
		{
			name:          "invalid token",
			success:       false,
			reason:        "invalid_signature",
			expectExpired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authMetrics.RecordTokenValidation(ctx, tt.success, tt.reason)

			rm := &metricdata.ResourceMetrics{}
			err := reader.Collect(ctx, rm)
			require.NoError(t, err)

			// Verify metrics were recorded
			var foundValidated, foundExpired bool
			for _, sm := range rm.ScopeMetrics {
				for _, metric := range sm.Metrics {
					switch metric.Name {
					case "auth_tokens_validated_total":
						foundValidated = true
					case "auth_tokens_expired_total":
						if tt.expectExpired {
							foundExpired = true
						}
					}
				}
			}

			assert.True(t, foundValidated, "token validated metric should be recorded")
			if tt.expectExpired {
				assert.True(t, foundExpired, "token expired metric should be recorded for expired tokens")
			}
		})
	}
}

func TestAuthMetrics_RecordSessionOperations(t *testing.T) {
	// Create a test meter provider
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(resource.Empty()),
		sdkmetric.WithReader(reader),
	)
	meter := provider.Meter("test")

	// Create auth metrics
	authMetrics, err := NewAuthMetrics(AuthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	})
	require.NoError(t, err)

	ctx := context.Background()
	userID := int32(123)

	t.Run("session start", func(t *testing.T) {
		authMetrics.RecordSessionStart(ctx, userID)

		rm := &metricdata.ResourceMetrics{}
		err := reader.Collect(ctx, rm)
		require.NoError(t, err)

		// Verify active sessions metric
		found := false
		for _, sm := range rm.ScopeMetrics {
			for _, metric := range sm.Metrics {
				if metric.Name == "auth_active_sessions" {
					found = true
					break
				}
			}
		}
		assert.True(t, found, "active sessions metric should be recorded")
	})

	t.Run("session end", func(t *testing.T) {
		duration := 30 * time.Minute
		authMetrics.RecordSessionEnd(ctx, userID, duration, "logout")

		rm := &metricdata.ResourceMetrics{}
		err := reader.Collect(ctx, rm)
		require.NoError(t, err)

		// Verify session duration metric
		var foundDuration, foundActiveSessions bool
		for _, sm := range rm.ScopeMetrics {
			for _, metric := range sm.Metrics {
				switch metric.Name {
				case "auth_session_duration_seconds":
					foundDuration = true
				case "auth_active_sessions":
					foundActiveSessions = true
				}
			}
		}
		assert.True(t, foundDuration, "session duration metric should be recorded")
		assert.True(t, foundActiveSessions, "active sessions metric should be updated")
	})
}

func TestAuthMetrics_RecordPasswordResetOperations(t *testing.T) {
	// Create a test meter provider
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(resource.Empty()),
		sdkmetric.WithReader(reader),
	)
	meter := provider.Meter("test")

	// Create auth metrics
	authMetrics, err := NewAuthMetrics(AuthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	})
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("password reset request", func(t *testing.T) {
		authMetrics.RecordPasswordResetRequest(ctx, "user@example.com")

		rm := &metricdata.ResourceMetrics{}
		err := reader.Collect(ctx, rm)
		require.NoError(t, err)

		// Verify password reset request metric
		found := false
		for _, sm := range rm.ScopeMetrics {
			for _, metric := range sm.Metrics {
				if metric.Name == "auth_password_reset_requests_total" {
					found = true
					break
				}
			}
		}
		assert.True(t, found, "password reset request metric should be recorded")
	})

	t.Run("password reset success", func(t *testing.T) {
		authMetrics.RecordPasswordResetResult(ctx, true, "")

		rm := &metricdata.ResourceMetrics{}
		err := reader.Collect(ctx, rm)
		require.NoError(t, err)

		// Verify password reset success metric
		found := false
		for _, sm := range rm.ScopeMetrics {
			for _, metric := range sm.Metrics {
				if metric.Name == "auth_password_reset_success_total" {
					found = true
					break
				}
			}
		}
		assert.True(t, found, "password reset success metric should be recorded")
	})

	t.Run("password reset failure", func(t *testing.T) {
		authMetrics.RecordPasswordResetResult(ctx, false, "invalid_token")

		rm := &metricdata.ResourceMetrics{}
		err := reader.Collect(ctx, rm)
		require.NoError(t, err)

		// Verify password reset failure metric
		found := false
		for _, sm := range rm.ScopeMetrics {
			for _, metric := range sm.Metrics {
				if metric.Name == "auth_password_reset_failures_total" {
					found = true
					break
				}
			}
		}
		assert.True(t, found, "password reset failure metric should be recorded")
	})
}

func TestGetResultString(t *testing.T) {
	tests := []struct {
		name     string
		success  bool
		expected string
	}{
		{
			name:     "success true",
			success:  true,
			expected: "success",
		},
		{
			name:     "success false",
			success:  false,
			expected: "failure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getResultString(tt.success)
			assert.Equal(t, tt.expected, result)
		})
	}
}
