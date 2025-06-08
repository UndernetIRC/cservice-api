// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package middlewares

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/undernetirc/cservice-api/internal/metrics"
)

func TestAuthMetrics(t *testing.T) {
	// Test with nil meter (should return no-op middleware)
	middleware := AuthMetrics(nil)
	assert.NotNil(t, middleware)

	// Test with valid meter
	meter := noop.NewMeterProvider().Meter("test")
	middleware = AuthMetrics(meter)
	assert.NotNil(t, middleware)
}

func TestAuthMetricsWithConfig(t *testing.T) {
	tests := []struct {
		name   string
		config AuthMetricsConfig
	}{
		{
			name: "nil auth metrics",
			config: AuthMetricsConfig{
				AuthMetrics: nil,
			},
		},
		{
			name: "valid config",
			config: AuthMetricsConfig{
				AuthMetrics: createTestAuthMetrics(t),
				ServiceName: "test-service",
			},
		},
		{
			name: "config with defaults",
			config: AuthMetricsConfig{
				AuthMetrics: createTestAuthMetrics(t),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware := AuthMetricsWithConfig(tt.config)
			assert.NotNil(t, middleware)

			// Test the middleware with a simple handler
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			handler := middleware(func(c echo.Context) error {
				return c.String(http.StatusOK, "test")
			})

			err := handler(c)
			assert.NoError(t, err)
		})
	}
}

func TestShouldCaptureRequestBody(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		method   string
		expected bool
	}{
		{
			name:     "login endpoint",
			path:     "/api/v1/login",
			method:   http.MethodPost,
			expected: true,
		},
		{
			name:     "factor verify endpoint",
			path:     "/api/v1/authn/factor_verify",
			method:   http.MethodPost,
			expected: true,
		},
		{
			name:     "refresh endpoint",
			path:     "/api/v1/authn/refresh",
			method:   http.MethodPost,
			expected: true,
		},
		{
			name:     "forgot password endpoint",
			path:     "/api/v1/forgot-password",
			method:   http.MethodPost,
			expected: true,
		},
		{
			name:     "reset password endpoint",
			path:     "/api/v1/reset-password",
			method:   http.MethodPost,
			expected: true,
		},
		{
			name:     "non-auth endpoint",
			path:     "/api/v1/users",
			method:   http.MethodPost,
			expected: false,
		},
		{
			name:     "get request",
			path:     "/api/v1/login",
			method:   http.MethodGet,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldCaptureRequestBody(tt.path, tt.method)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCaptureRequestBody(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		expectError bool
	}{
		{
			name:        "valid JSON body",
			body:        `{"username": "testuser", "password": "testpass"}`,
			expectError: false,
		},
		{
			name:        "empty body",
			body:        "",
			expectError: false,
		},
		{
			name:        "invalid JSON body",
			body:        `{"username": "testuser"`,
			expectError: false, // We don't validate JSON here
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			body, err := captureRequestBody(c)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.body, string(body))

				// Verify the request body is still available for the handler
				bodyBytes := make([]byte, len(tt.body))
				n, _ := c.Request().Body.Read(bodyBytes)
				assert.Equal(t, tt.body, string(bodyBytes[:n]))
			}
		})
	}

	t.Run("nil body", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		body, err := captureRequestBody(c)
		// When body is nil, httptest.NewRequest creates an empty body, not nil
		// So we should get an empty byte slice, not an error
		assert.NoError(t, err)
		assert.Equal(t, []byte{}, body)
	})
}

func TestRecordLoginMetrics(t *testing.T) {
	// Create test meter and auth metrics
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(resource.Empty()),
		sdkmetric.WithReader(reader),
	)
	meter := provider.Meter("test")

	authMetrics, err := metrics.NewAuthMetrics(metrics.AuthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	})
	require.NoError(t, err)

	tests := []struct {
		name        string
		status      int
		requestBody string
		expectUser  string
	}{
		{
			name:        "successful login",
			status:      http.StatusOK,
			requestBody: `{"username": "testuser", "password": "testpass"}`,
			expectUser:  "testuser",
		},
		{
			name:        "failed login",
			status:      http.StatusUnauthorized,
			requestBody: `{"username": "baduser", "password": "badpass"}`,
			expectUser:  "baduser",
		},
		{
			name:        "invalid request body",
			status:      http.StatusBadRequest,
			requestBody: `invalid json`,
			expectUser:  "unknown",
		},
		{
			name:        "empty request body",
			status:      http.StatusBadRequest,
			requestBody: "",
			expectUser:  "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			duration := 100 * time.Millisecond

			recordLoginMetrics(ctx, authMetrics, tt.status, duration, []byte(tt.requestBody))

			// Collect metrics
			rm := &metricdata.ResourceMetrics{}
			err := reader.Collect(ctx, rm)
			require.NoError(t, err)

			// Verify metrics were recorded
			assert.NotEmpty(t, rm.ScopeMetrics)
		})
	}
}

func TestRecordMFAMetrics(t *testing.T) {
	authMetrics := createTestAuthMetrics(t)
	ctx := context.Background()

	tests := []struct {
		name        string
		status      int
		requestBody string
	}{
		{
			name:        "successful MFA",
			status:      http.StatusOK,
			requestBody: `{"state_token": "token123", "otp": "123456"}`,
		},
		{
			name:        "failed MFA",
			status:      http.StatusUnauthorized,
			requestBody: `{"state_token": "token123", "otp": "000000"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			duration := 150 * time.Millisecond
			recordMFAMetrics(ctx, authMetrics, tt.status, duration, []byte(tt.requestBody))
			// Test passes if no panic occurs
		})
	}
}

func TestRecordTokenRefreshMetrics(t *testing.T) {
	authMetrics := createTestAuthMetrics(t)
	ctx := context.Background()

	tests := []struct {
		name   string
		status int
	}{
		{
			name:   "successful refresh",
			status: http.StatusOK,
		},
		{
			name:   "failed refresh",
			status: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			duration := 50 * time.Millisecond
			recordTokenRefreshMetrics(ctx, authMetrics, tt.status, duration)
			// Test passes if no panic occurs
		})
	}
}

func TestRecordLogoutMetrics(t *testing.T) {
	authMetrics := createTestAuthMetrics(t)
	ctx := context.Background()

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	tests := []struct {
		name   string
		status int
	}{
		{
			name:   "successful logout",
			status: http.StatusOK,
		},
		{
			name:   "failed logout",
			status: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recordLogoutMetrics(ctx, authMetrics, tt.status, c)
			// Test passes if no panic occurs
		})
	}
}

func TestRecordPasswordResetRequestMetrics(t *testing.T) {
	authMetrics := createTestAuthMetrics(t)
	ctx := context.Background()

	tests := []struct {
		name        string
		status      int
		requestBody string
	}{
		{
			name:        "successful request",
			status:      http.StatusOK,
			requestBody: `{"email": "user@example.com"}`,
		},
		{
			name:        "failed request",
			status:      http.StatusBadRequest,
			requestBody: `{"email": "invalid-email"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recordPasswordResetRequestMetrics(ctx, authMetrics, tt.status, []byte(tt.requestBody))
			// Test passes if no panic occurs
		})
	}
}

func TestRecordPasswordResetResultMetrics(t *testing.T) {
	authMetrics := createTestAuthMetrics(t)
	ctx := context.Background()

	tests := []struct {
		name   string
		status int
	}{
		{
			name:   "successful reset",
			status: http.StatusOK,
		},
		{
			name:   "failed reset",
			status: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recordPasswordResetResultMetrics(ctx, authMetrics, tt.status)
			// Test passes if no panic occurs
		})
	}
}

func TestExtractUsernameFromRequest(t *testing.T) {
	tests := []struct {
		name        string
		requestBody string
		expected    string
	}{
		{
			name:        "valid username",
			requestBody: `{"username": "testuser", "password": "testpass"}`,
			expected:    "testuser",
		},
		{
			name:        "empty username",
			requestBody: `{"username": "", "password": "testpass"}`,
			expected:    "unknown",
		},
		{
			name:        "missing username",
			requestBody: `{"password": "testpass"}`,
			expected:    "unknown",
		},
		{
			name:        "invalid JSON",
			requestBody: `invalid json`,
			expected:    "unknown",
		},
		{
			name:        "empty body",
			requestBody: "",
			expected:    "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractUsernameFromRequest([]byte(tt.requestBody))
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractEmailFromRequest(t *testing.T) {
	tests := []struct {
		name        string
		requestBody string
		expected    string
	}{
		{
			name:        "valid email",
			requestBody: `{"email": "user@example.com"}`,
			expected:    "user@example.com",
		},
		{
			name:        "empty email",
			requestBody: `{"email": ""}`,
			expected:    "unknown",
		},
		{
			name:        "missing email",
			requestBody: `{"other": "value"}`,
			expected:    "unknown",
		},
		{
			name:        "invalid JSON",
			requestBody: `invalid json`,
			expected:    "unknown",
		},
		{
			name:        "empty body",
			requestBody: "",
			expected:    "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractEmailFromRequest([]byte(tt.requestBody))
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetFailureReason(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		success  bool
		expected string
	}{
		{
			name:     "success",
			status:   http.StatusOK,
			success:  true,
			expected: "",
		},
		{
			name:     "unauthorized",
			status:   http.StatusUnauthorized,
			success:  false,
			expected: "invalid_credentials",
		},
		{
			name:     "bad request",
			status:   http.StatusBadRequest,
			success:  false,
			expected: "invalid_request",
		},
		{
			name:     "too many requests",
			status:   http.StatusTooManyRequests,
			success:  false,
			expected: "rate_limited",
		},
		{
			name:     "internal server error",
			status:   http.StatusInternalServerError,
			success:  false,
			expected: "internal_error",
		},
		{
			name:     "unknown error",
			status:   http.StatusTeapot,
			success:  false,
			expected: "unknown_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getFailureReason(tt.status, tt.success)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAuthMetricsMiddlewareIntegration(t *testing.T) {
	// Create test meter and auth metrics
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(resource.Empty()),
		sdkmetric.WithReader(reader),
	)
	meter := provider.Meter("test")

	authMetrics, err := metrics.NewAuthMetrics(metrics.AuthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	})
	require.NoError(t, err)

	// Create middleware
	middleware := AuthMetricsWithConfig(AuthMetricsConfig{
		AuthMetrics: authMetrics,
		ServiceName: "test-service",
	})

	tests := []struct {
		name       string
		path       string
		method     string
		body       string
		status     int
		expectSkip bool
	}{
		{
			name:   "login endpoint",
			path:   "/api/v1/login",
			method: http.MethodPost,
			body:   `{"username": "testuser", "password": "testpass"}`,
			status: http.StatusOK,
		},
		{
			name:   "factor verify endpoint",
			path:   "/api/v1/authn/factor_verify",
			method: http.MethodPost,
			body:   `{"state_token": "token123", "otp": "123456"}`,
			status: http.StatusOK,
		},
		{
			name:   "refresh endpoint",
			path:   "/api/v1/authn/refresh",
			method: http.MethodPost,
			body:   `{"refresh_token": "token123"}`,
			status: http.StatusOK,
		},
		{
			name:   "logout endpoint",
			path:   "/api/v1/logout",
			method: http.MethodPost,
			body:   "",
			status: http.StatusOK,
		},
		{
			name:   "forgot password endpoint",
			path:   "/api/v1/forgot-password",
			method: http.MethodPost,
			body:   `{"email": "user@example.com"}`,
			status: http.StatusOK,
		},
		{
			name:   "reset password endpoint",
			path:   "/api/v1/reset-password",
			method: http.MethodPost,
			body:   `{"token": "reset123", "password": "newpass"}`,
			status: http.StatusOK,
		},
		{
			name:       "non-auth endpoint",
			path:       "/api/v1/users",
			method:     http.MethodGet,
			body:       "",
			status:     http.StatusOK,
			expectSkip: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()

			var req *http.Request
			if tt.body != "" {
				req = httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(tt.method, tt.path, nil)
			}

			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetPath(tt.path)

			// Create a handler that sets the response status
			handler := middleware(func(c echo.Context) error {
				return c.String(tt.status, "response")
			})

			err := handler(c)
			assert.NoError(t, err)
			assert.Equal(t, tt.status, rec.Code)

			// Collect metrics to verify they were recorded
			ctx := context.Background()
			rm := &metricdata.ResourceMetrics{}
			err = reader.Collect(ctx, rm)
			require.NoError(t, err)

			if !tt.expectSkip {
				// Verify some metrics were recorded for auth endpoints
				assert.NotEmpty(t, rm.ScopeMetrics, "Expected metrics to be recorded for auth endpoint")
			}
		})
	}
}

func TestAuthMetricsMiddlewareWithSkipper(t *testing.T) {
	authMetrics := createTestAuthMetrics(t)

	// Create middleware with skipper that skips all requests
	middleware := AuthMetricsWithConfig(AuthMetricsConfig{
		Skipper: func(c echo.Context) bool {
			return true // Skip all requests
		},
		AuthMetrics: authMetrics,
		ServiceName: "test-service",
	})

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(`{"username": "test"}`))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/api/v1/login")

	handler := middleware(func(c echo.Context) error {
		return c.String(http.StatusOK, "response")
	})

	err := handler(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// Helper function to create test auth metrics
func createTestAuthMetrics(t *testing.T) *metrics.AuthMetrics {
	meter := noop.NewMeterProvider().Meter("test")
	authMetrics, err := metrics.NewAuthMetrics(metrics.AuthMetricsConfig{
		Meter:       meter,
		ServiceName: "test-service",
	})
	require.NoError(t, err)
	return authMetrics
}
