// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2025 UnderNET

package middlewares

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/undernetirc/cservice-api/internal/config"
)

// MockRateLimiter implements the RateLimiter interface for testing
type MockRateLimiter struct {
	mock.Mock
}

func (m *MockRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error) {
	args := m.Called(ctx, key, limit, window)
	return args.Bool(0), args.Get(1).(time.Duration), args.Error(2)
}

func setupTestEcho() *echo.Echo {
	e := echo.New()
	return e
}

func createJWTToken(userID float64) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  userID,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte("test-secret"))
	return tokenString
}

func TestRateLimit_Disabled(t *testing.T) {
	// Set rate limiting to disabled
	config.ServiceRateLimitEnabled.Set(false)
	defer config.ServiceRateLimitEnabled.Set(true) // Reset after test

	e := setupTestEcho()
	mockLimiter := &MockRateLimiter{}

	// Middleware should not call the rate limiter when disabled
	middleware := RateLimit(mockLimiter)
	handler := middleware(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/channels", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "success", rec.Body.String())

	// Verify rate limiter was not called
	mockLimiter.AssertNotCalled(t, "Allow")
}

func TestRateLimit_NonChannelEndpoint(t *testing.T) {
	config.ServiceRateLimitEnabled.Set(true)
	defer config.ServiceRateLimitEnabled.Set(false)

	e := setupTestEcho()
	mockLimiter := &MockRateLimiter{}

	middleware := RateLimit(mockLimiter)
	handler := middleware(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	// Test non-channel endpoint
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify rate limiter was not called for non-channel endpoint
	mockLimiter.AssertNotCalled(t, "Allow")
}

func TestRateLimit_ChannelEndpoint_Allowed(t *testing.T) {
	config.ServiceRateLimitEnabled.Set(true)
	config.ServiceRateLimitRequestsPerMinute.Set(10)
	config.ServiceRateLimitWindowMinutes.Set(1)
	defer func() {
		config.ServiceRateLimitEnabled.Set(false)
		config.ServiceRateLimitRequestsPerMinute.Set(10)
		config.ServiceRateLimitWindowMinutes.Set(1)
	}()

	e := setupTestEcho()
	mockLimiter := &MockRateLimiter{}

	// Mock rate limiter to allow request
	mockLimiter.On("Allow", mock.Anything, "ip:192.0.2.1", 10, time.Minute).
		Return(true, time.Duration(0), nil)

	middleware := RateLimit(mockLimiter)
	handler := middleware(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/channels", nil)
	req.Header.Set("X-Real-IP", "192.0.2.1")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "success", rec.Body.String())

	mockLimiter.AssertExpectations(t)
}

func TestRateLimit_ChannelEndpoint_RateLimited(t *testing.T) {
	config.ServiceRateLimitEnabled.Set(true)
	config.ServiceRateLimitRequestsPerMinute.Set(10)
	defer func() {
		config.ServiceRateLimitEnabled.Set(false)
		config.ServiceRateLimitRequestsPerMinute.Set(10)
	}()

	e := setupTestEcho()
	mockLimiter := &MockRateLimiter{}

	// Mock rate limiter to deny request
	retryAfter := 30 * time.Second
	mockLimiter.On("Allow", mock.Anything, "ip:192.0.2.1", 10, time.Minute).
		Return(false, retryAfter, nil)

	middleware := RateLimit(mockLimiter)
	handler := middleware(func(c echo.Context) error {
		return c.String(http.StatusOK, "should not reach here")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/channels", nil)
	req.Header.Set("X-Real-IP", "192.0.2.1")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)

	// Check headers
	assert.Equal(t, "30", rec.Header().Get("Retry-After"))
	assert.Equal(t, "10", rec.Header().Get("X-RateLimit-Limit"))
	assert.Equal(t, "0", rec.Header().Get("X-RateLimit-Remaining"))
	assert.NotEmpty(t, rec.Header().Get("X-RateLimit-Reset"))

	// Check response body
	var response map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.False(t, response["success"].(bool))

	errorObj := response["error"].(map[string]interface{})
	assert.Equal(t, "RATE_LIMIT_EXCEEDED", errorObj["code"])
	assert.Equal(t, "rate_limit", errorObj["category"])
	assert.True(t, errorObj["retryable"].(bool))
	assert.Contains(t, errorObj["message"], "Rate limit exceeded")

	mockLimiter.AssertExpectations(t)
}

func TestRateLimit_WithJWTUser(t *testing.T) {
	config.ServiceRateLimitEnabled.Set(true)
	config.ServiceRateLimitRequestsPerMinute.Set(10)
	defer func() {
		config.ServiceRateLimitEnabled.Set(false)
		config.ServiceRateLimitRequestsPerMinute.Set(10)
	}()

	e := setupTestEcho()
	mockLimiter := &MockRateLimiter{}

	// Mock rate limiter to expect user-based key
	mockLimiter.On("Allow", mock.Anything, "user:123", 10, time.Minute).
		Return(true, time.Duration(0), nil)

	middleware := RateLimit(mockLimiter)
	handler := middleware(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	// Create JWT token and set it in context
	tokenString := createJWTToken(123)
	token, _ := jwt.Parse(tokenString, func(_ *jwt.Token) (interface{}, error) {
		return []byte("test-secret"), nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/channels", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("user", token)

	err := handler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	mockLimiter.AssertExpectations(t)
}

func TestRateLimit_RateLimiterError(t *testing.T) {
	config.ServiceRateLimitEnabled.Set(true)
	defer config.ServiceRateLimitEnabled.Set(false)

	e := setupTestEcho()
	mockLimiter := &MockRateLimiter{}

	// Mock rate limiter to return error
	mockLimiter.On("Allow", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, time.Duration(0), fmt.Errorf("redis connection failed"))

	middleware := RateLimit(mockLimiter)
	handler := middleware(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/channels", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler(c)
	require.NoError(t, err)
	// Should allow request on error
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "success", rec.Body.String())

	mockLimiter.AssertExpectations(t)
}

func TestRateLimit_CustomConfig(t *testing.T) {
	e := setupTestEcho()
	mockLimiter := &MockRateLimiter{}

	customConfig := RateLimitConfig{
		RateLimiter:       mockLimiter,
		RequestsPerMinute: 5,
		WindowMinutes:     2,
		Skipper: func(c echo.Context) bool {
			return strings.Contains(c.Request().URL.Path, "skip")
		},
		KeyGenerator: func(_ echo.Context) string {
			return "custom:key"
		},
	}

	// Test skipper function
	middleware := RateLimitWithConfig(customConfig)
	handler := middleware(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/channels/skip", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify rate limiter was not called due to skipper
	mockLimiter.AssertNotCalled(t, "Allow")
}

func TestRateLimit_KeyGeneration(t *testing.T) {
	tests := []struct {
		name        string
		setupFunc   func(c echo.Context)
		expectedKey string
	}{
		{
			name: "IP-based key when no JWT",
			setupFunc: func(c echo.Context) {
				c.Request().Header.Set("X-Real-IP", "192.0.2.1")
			},
			expectedKey: "ip:192.0.2.1",
		},
		{
			name: "User-based key with JWT",
			setupFunc: func(c echo.Context) {
				tokenString := createJWTToken(456)
				token, _ := jwt.Parse(tokenString, func(_ *jwt.Token) (interface{}, error) {
					return []byte("test-secret"), nil
				})
				c.Set("user", token)
			},
			expectedKey: "user:456",
		},
		{
			name: "IP fallback with invalid JWT",
			setupFunc: func(c echo.Context) {
				c.Set("user", "invalid-token")
				c.Request().Header.Set("X-Real-IP", "192.0.2.2")
			},
			expectedKey: "ip:192.0.2.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := setupTestEcho()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/channels", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			tt.setupFunc(c)

			key := defaultKeyGenerator(c)
			assert.Equal(t, tt.expectedKey, key)
		})
	}
}

func TestRateLimit_EndpointDetection(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		path     string
		expected bool
	}{
		{
			name:     "Channel registration endpoint",
			method:   "POST",
			path:     "/api/v1/channels",
			expected: true,
		},
		{
			name:     "Channel registration with trailing slash",
			method:   "POST",
			path:     "/api/v1/channels/",
			expected: false, // Exact match required
		},
		{
			name:     "GET channels endpoint",
			method:   "GET",
			path:     "/api/v1/channels",
			expected: false,
		},
		{
			name:     "Different endpoint",
			method:   "POST",
			path:     "/api/v1/users",
			expected: false,
		},
		{
			name:     "Channel sub-resource",
			method:   "POST",
			path:     "/api/v1/channels/123/members",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := setupTestEcho()
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			result := isChannelRegistrationEndpoint(c)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRateLimitMiddleware_GlobalMode(t *testing.T) {
	// Enable rate limiting for this test
	config.ServiceRateLimitEnabled.Set(true)
	defer config.ServiceRateLimitEnabled.Set(false)

	mockLimiter := &MockRateLimiter{}
	rateLimitConfig := RateLimitConfig{
		RateLimiter:       mockLimiter,
		RequestsPerMinute: 5,
		WindowMinutes:     1,
		Mode:              RateLimitModeGlobal,
	}

	e := echo.New()

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"GET request", "GET", "/api/v1/users"},
		{"POST request", "POST", "/api/v1/channels"},
		{"PUT request", "PUT", "/api/v1/users/123"},
		{"DELETE request", "DELETE", "/api/v1/admin/users/123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			mockLimiter.On("Allow", mock.Anything, mock.AnythingOfType("string"), 5, time.Minute).Return(true, time.Duration(0), nil).Once()

			middleware := RateLimitWithConfig(rateLimitConfig)
			handler := middleware(func(c echo.Context) error {
				return c.String(http.StatusOK, "success")
			})

			err := handler(c)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, rec.Code)
		})
	}

	mockLimiter.AssertExpectations(t)
}

func TestRateLimitMiddleware_EndpointsMode(t *testing.T) {
	// Enable rate limiting for this test
	config.ServiceRateLimitEnabled.Set(true)
	defer config.ServiceRateLimitEnabled.Set(false)

	mockLimiter := &MockRateLimiter{}
	rateLimitConfig := RateLimitConfig{
		RateLimiter:       mockLimiter,
		RequestsPerMinute: 5,
		WindowMinutes:     1,
		Mode:              RateLimitModeEndpoints,
		EndpointPatterns:  []string{"POST:/api/v1/channels", "GET:/api/v1/users/*", "/admin/**"},
	}

	e := echo.New()

	tests := []struct {
		name        string
		method      string
		path        string
		shouldLimit bool
		description string
	}{
		{"POST channels - should limit", "POST", "/api/v1/channels", true, "matches POST:/api/v1/channels pattern"},
		{"GET user by ID - should limit", "GET", "/api/v1/users/123", true, "matches GET:/api/v1/users/* pattern"},
		{"POST admin - should limit", "POST", "/admin/users", true, "matches /admin/** pattern"},
		{"GET admin - should limit", "GET", "/admin/settings", true, "matches /admin/** pattern"},
		{"GET users list - should not limit", "GET", "/api/v1/users", false, "doesn't match any pattern"},
		{"PUT user - should not limit", "PUT", "/api/v1/users/123", false, "wrong method for user pattern"},
		{"GET other - should not limit", "GET", "/api/v1/other", false, "doesn't match any pattern"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			if tt.shouldLimit {
				mockLimiter.On("Allow", mock.Anything, mock.AnythingOfType("string"), 5, time.Minute).Return(true, time.Duration(0), nil).Once()
			}

			middleware := RateLimitWithConfig(rateLimitConfig)
			handler := middleware(func(c echo.Context) error {
				return c.String(http.StatusOK, "success")
			})

			err := handler(c)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, rec.Code, tt.description)
		})
	}

	mockLimiter.AssertExpectations(t)
}

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		path     string
		pattern  string
		expected bool
	}{
		// Exact matches
		{"exact match with method", "POST", "/api/v1/channels", "POST:/api/v1/channels", true},
		{"exact match without method", "GET", "/api/v1/users", "/api/v1/users", true},
		{"method mismatch", "GET", "/api/v1/channels", "POST:/api/v1/channels", false},

		// Suffix matches
		{"suffix match", "POST", "/api/v1/channels", "/channels", true},
		{"suffix match with method", "POST", "/api/v1/channels", "POST:/api/v1/channels", true},
		{"suffix no match", "POST", "/api/v1/users", "/channels", false},

		// Wildcard matches
		{"single wildcard", "GET", "/api/v1/users/123", "GET:/api/v1/users/*", true},
		{"single wildcard no match", "GET", "/api/v1/users/123/profile", "GET:/api/v1/users/*", false},
		{"double wildcard", "POST", "/admin/users/123/delete", "/admin/**", true},
		{"double wildcard at end", "GET", "/admin/settings", "/admin/**", true},
		{"double wildcard exact", "GET", "/admin", "/admin/**", true},

		// Any method patterns
		{"any method wildcard", "POST", "/api/v1/users/123", "/api/v1/users/*", true},
		{"any method exact", "DELETE", "/admin/clear", "/admin/clear", true},

		// Complex patterns
		{"method with double wildcard", "POST", "/api/v1/admin/users/create", "POST:/api/v1/admin/**", true},
		{"mixed wildcards", "GET", "/api/v1/users/123/settings", "/api/v1/*/123/*", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesPattern(tt.method, tt.path, tt.pattern)
			assert.Equal(t, tt.expected, result, "Pattern: %s, Method: %s, Path: %s", tt.pattern, tt.method, tt.path)
		})
	}
}
