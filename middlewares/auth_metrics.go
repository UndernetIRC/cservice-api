// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package middlewares

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/metric"

	"github.com/undernetirc/cservice-api/internal/metrics"
)

// AuthMetricsConfig holds configuration for authentication metrics middleware
type AuthMetricsConfig struct {
	// Skipper defines a function to skip middleware
	Skipper func(echo.Context) bool
	// AuthMetrics is the authentication metrics collector
	AuthMetrics *metrics.AuthMetrics
	// ServiceName is used for metric labeling
	ServiceName string
}

// DefaultAuthMetricsConfig provides default configuration
var DefaultAuthMetricsConfig = AuthMetricsConfig{
	Skipper:     func(echo.Context) bool { return false },
	ServiceName: "cservice-api",
}

// AuthMetrics returns a middleware that collects authentication metrics
func AuthMetrics(meter metric.Meter) echo.MiddlewareFunc {
	authMetrics, err := metrics.NewAuthMetrics(metrics.AuthMetricsConfig{
		Meter:       meter,
		ServiceName: DefaultAuthMetricsConfig.ServiceName,
	})
	if err != nil {
		// If we can't create metrics, return a no-op middleware
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return next
		}
	}

	return AuthMetricsWithConfig(AuthMetricsConfig{
		Skipper:     DefaultAuthMetricsConfig.Skipper,
		AuthMetrics: authMetrics,
		ServiceName: DefaultAuthMetricsConfig.ServiceName,
	})
}

// AuthMetricsWithConfig returns a middleware with custom configuration
func AuthMetricsWithConfig(config AuthMetricsConfig) echo.MiddlewareFunc {
	// Set defaults
	if config.Skipper == nil {
		config.Skipper = DefaultAuthMetricsConfig.Skipper
	}
	if config.ServiceName == "" {
		config.ServiceName = DefaultAuthMetricsConfig.ServiceName
	}
	if config.AuthMetrics == nil {
		// Return no-op middleware if no metrics collector
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return next
		}
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Skip if configured to do so
			if config.Skipper(c) {
				return next(c)
			}

			ctx := c.Request().Context()
			start := time.Now()
			path := c.Path()
			method := c.Request().Method

			// Capture request body for login endpoints
			var requestBody []byte
			if shouldCaptureRequestBody(path, method) {
				if body, err := captureRequestBody(c); err == nil {
					requestBody = body
				}
			}

			// Execute the handler
			err := next(c)

			// Calculate duration
			duration := time.Since(start)
			status := c.Response().Status

			// Record metrics based on the endpoint
			recordAuthMetrics(ctx, config.AuthMetrics, path, method, status, duration, requestBody, c)

			return err
		}
	}
}

// shouldCaptureRequestBody determines if we should capture the request body for metrics
func shouldCaptureRequestBody(path, method string) bool {
	if method != http.MethodPost {
		return false
	}

	authPaths := []string{
		"/login",
		"/authn/factor_verify",
		"/authn/refresh",
		"/forgot-password",
		"/reset-password",
	}

	for _, authPath := range authPaths {
		if strings.Contains(path, authPath) {
			return true
		}
	}

	return false
}

// captureRequestBody safely captures the request body without consuming it
func captureRequestBody(c echo.Context) ([]byte, error) {
	req := c.Request()
	if req.Body == nil {
		return nil, fmt.Errorf("no request body")
	}

	// Read the body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	// Restore the body for the actual handler
	req.Body = io.NopCloser(strings.NewReader(string(body)))

	return body, nil
}

// recordAuthMetrics records authentication metrics based on the endpoint and response
func recordAuthMetrics(ctx context.Context, authMetrics *metrics.AuthMetrics, path, method string, status int, duration time.Duration, requestBody []byte, c echo.Context) {
	// Login endpoint
	if strings.Contains(path, "/login") && method == http.MethodPost {
		recordLoginMetrics(ctx, authMetrics, status, duration, requestBody)
		return
	}

	// MFA verification endpoint
	if strings.Contains(path, "/authn/factor_verify") && method == http.MethodPost {
		recordMFAMetrics(ctx, authMetrics, status, duration, requestBody)
		return
	}

	// Token refresh endpoint
	if strings.Contains(path, "/authn/refresh") && method == http.MethodPost {
		recordTokenRefreshMetrics(ctx, authMetrics, status, duration)
		return
	}

	// Logout endpoint
	if strings.Contains(path, "/logout") && method == http.MethodPost {
		recordLogoutMetrics(ctx, authMetrics, status, c)
		return
	}

	// Password reset request endpoint
	if strings.Contains(path, "/forgot-password") && method == http.MethodPost {
		recordPasswordResetRequestMetrics(ctx, authMetrics, status, requestBody)
		return
	}

	// Password reset completion endpoint
	if strings.Contains(path, "/reset-password") && method == http.MethodPost {
		recordPasswordResetResultMetrics(ctx, authMetrics, status)
		return
	}
}

// recordLoginMetrics records metrics for login attempts
func recordLoginMetrics(ctx context.Context, authMetrics *metrics.AuthMetrics, status int, duration time.Duration, requestBody []byte) {
	username := extractUsernameFromRequest(requestBody)
	success := status == http.StatusOK
	reason := getFailureReason(status, success)

	authMetrics.RecordLoginAttempt(ctx, username, success, duration, reason)

	// If login was successful, record session start
	if success {
		// Note: In a real implementation, you'd extract the actual user ID from the response or context
		// For now, we'll use a placeholder approach
		authMetrics.RecordSessionStart(ctx, 0) // userID would be extracted from response
		authMetrics.RecordTokenGenerated(ctx, 0, "access_token")
		authMetrics.RecordTokenGenerated(ctx, 0, "refresh_token")
	}
}

// recordMFAMetrics records metrics for MFA verification attempts
func recordMFAMetrics(ctx context.Context, authMetrics *metrics.AuthMetrics, status int, duration time.Duration, requestBody []byte) {
	success := status == http.StatusOK
	method := "totp" // Default to TOTP, could be extracted from request if needed

	// Note: In a real implementation, you'd extract the actual user ID from the state token
	userID := int32(0) // Placeholder

	authMetrics.RecordMFAAttempt(ctx, userID, success, duration, method)

	// If MFA was successful, record token generation and session start
	if success {
		authMetrics.RecordTokenGenerated(ctx, userID, "access_token")
		authMetrics.RecordTokenGenerated(ctx, userID, "refresh_token")
		authMetrics.RecordSessionStart(ctx, userID)
	}
}

// recordTokenRefreshMetrics records metrics for token refresh attempts
func recordTokenRefreshMetrics(ctx context.Context, authMetrics *metrics.AuthMetrics, status int, duration time.Duration) {
	success := status == http.StatusOK
	userID := int32(0) // Would be extracted from the refresh token

	authMetrics.RecordTokenRefreshed(ctx, userID, success)

	if success {
		authMetrics.RecordTokenGenerated(ctx, userID, "access_token")
		authMetrics.RecordTokenGenerated(ctx, userID, "refresh_token")
	}
}

// recordLogoutMetrics records metrics for logout operations
func recordLogoutMetrics(ctx context.Context, authMetrics *metrics.AuthMetrics, status int, c echo.Context) {
	if status == http.StatusOK {
		userID := int32(0) // Would be extracted from JWT claims

		authMetrics.RecordTokenRevoked(ctx, userID, "logout")

		// Record session end - in a real implementation, you'd track session start time
		sessionDuration := 30 * time.Minute // Placeholder duration
		authMetrics.RecordSessionEnd(ctx, userID, sessionDuration, "logout")
	}
}

// recordPasswordResetRequestMetrics records metrics for password reset requests
func recordPasswordResetRequestMetrics(ctx context.Context, authMetrics *metrics.AuthMetrics, status int, requestBody []byte) {
	if status == http.StatusOK {
		email := extractEmailFromRequest(requestBody)
		authMetrics.RecordPasswordResetRequest(ctx, email)
	}
}

// recordPasswordResetResultMetrics records metrics for password reset completion
func recordPasswordResetResultMetrics(ctx context.Context, authMetrics *metrics.AuthMetrics, status int) {
	success := status == http.StatusOK
	reason := getFailureReason(status, success)

	authMetrics.RecordPasswordResetResult(ctx, success, reason)
}

// extractUsernameFromRequest extracts username from login request body
func extractUsernameFromRequest(requestBody []byte) string {
	if len(requestBody) == 0 {
		return "unknown"
	}

	var loginReq struct {
		Username string `json:"username"`
	}

	if err := json.Unmarshal(requestBody, &loginReq); err != nil {
		return "unknown"
	}

	if loginReq.Username == "" {
		return "unknown"
	}

	return loginReq.Username
}

// extractEmailFromRequest extracts email from password reset request body
func extractEmailFromRequest(requestBody []byte) string {
	if len(requestBody) == 0 {
		return "unknown"
	}

	var resetReq struct {
		Email string `json:"email"`
	}

	if err := json.Unmarshal(requestBody, &resetReq); err != nil {
		return "unknown"
	}

	if resetReq.Email == "" {
		return "unknown"
	}

	return resetReq.Email
}

// getFailureReason returns a failure reason based on HTTP status code
func getFailureReason(status int, success bool) string {
	if success {
		return ""
	}

	switch status {
	case http.StatusUnauthorized:
		return "invalid_credentials"
	case http.StatusBadRequest:
		return "invalid_request"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusInternalServerError:
		return "internal_error"
	default:
		return "unknown_error"
	}
}
