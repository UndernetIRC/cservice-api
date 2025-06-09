//go:build integration

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/undernetirc/cservice-api/controllers"
	"github.com/undernetirc/cservice-api/internal/checks"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/internal/ratelimit"
	"github.com/undernetirc/cservice-api/middlewares"
	"github.com/undernetirc/cservice-api/models"
)

func TestRateLimitIntegration(t *testing.T) {
	// Set up configuration for rate limiting
	config.DefaultConfig()

	// Enable rate limiting for this test
	config.ServiceRateLimitEnabled.Set(true)
	config.ServiceRateLimitRequestsPerMinute.Set(3) // Low limit for testing
	config.ServiceRateLimitWindowMinutes.Set(1)
	config.ServiceRateLimitMode.Set("global") // Test global mode
	defer func() {
		// Clean up after test
		config.ServiceRateLimitEnabled.Set(false)
		config.ServiceRateLimitRequestsPerMinute.Set(10)
		config.ServiceRateLimitWindowMinutes.Set(1)
		config.ServiceRateLimitMode.Set("channels")
	}()

	// Initialize service and controller
	service := models.NewService(db)
	checks.InitUser(context.Background(), db)
	authController := controllers.NewAuthenticationController(service, rdb, nil)

	// Set up Echo with rate limiting middleware
	e := echo.New()
	e.Validator = helper.NewValidator()

	// Add rate limiting middleware
	rateLimiter := ratelimit.NewRedisRateLimiter(rdb)
	e.Use(middlewares.RateLimit(rateLimiter))

	// Register the login endpoint
	e.POST("/api/v1/login", authController.Login)

	t.Run("Rate limit allows requests within limit", func(t *testing.T) {
		// Clear any existing rate limit data for this test
		testKey := "ip:192.0.2.1"
		err := rdb.Del(ctx, fmt.Sprintf("ratelimit:%s", testKey)).Err()
		require.NoError(t, err)

		// Make requests within the limit (3 requests per minute)
		for i := 0; i < 3; i++ {
			w := httptest.NewRecorder()
			body := bytes.NewBufferString(`{"username": "Admin", "password": "temPass2020@"}`)
			r, _ := http.NewRequest("POST", "/api/v1/login", body)
			r.Header.Set("Content-Type", "application/json")
			r.RemoteAddr = "192.0.2.1:12345" // Set a consistent IP for rate limiting

			e.ServeHTTP(w, r)

			// Should succeed (either 200 for valid login or 401 for invalid, but not 429)
			assert.NotEqual(t, http.StatusTooManyRequests, w.Code,
				"Request %d should not be rate limited", i+1)
		}
	})

	t.Run("Rate limit blocks requests exceeding limit", func(t *testing.T) {
		// Clear any existing rate limit data for this test
		testKey := "ip:192.0.2.2"
		err := rdb.Del(ctx, fmt.Sprintf("ratelimit:%s", testKey)).Err()
		require.NoError(t, err)

		// Make requests up to the limit
		for i := 0; i < 3; i++ {
			w := httptest.NewRecorder()
			body := bytes.NewBufferString(`{"username": "Admin", "password": "temPass2020@"}`)
			r, _ := http.NewRequest("POST", "/api/v1/login", body)
			r.Header.Set("Content-Type", "application/json")
			r.RemoteAddr = "192.0.2.2:12345"

			e.ServeHTTP(w, r)
			assert.NotEqual(t, http.StatusTooManyRequests, w.Code)
		}

		// The 4th request should be rate limited
		w := httptest.NewRecorder()
		body := bytes.NewBufferString(`{"username": "Admin", "password": "temPass2020@"}`)
		r, _ := http.NewRequest("POST", "/api/v1/login", body)
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "192.0.2.2:12345"

		e.ServeHTTP(w, r)

		// Should be rate limited
		assert.Equal(t, http.StatusTooManyRequests, w.Code)

		// Check rate limit headers
		assert.NotEmpty(t, w.Header().Get("Retry-After"))
		assert.Equal(t, "3", w.Header().Get("X-RateLimit-Limit"))
		assert.Equal(t, "0", w.Header().Get("X-RateLimit-Remaining"))
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-Reset"))

		// Check error response format
		var errorResponse map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&errorResponse)
		require.NoError(t, err)

		assert.False(t, errorResponse["success"].(bool))
		errorObj := errorResponse["error"].(map[string]interface{})
		assert.Equal(t, "RATE_LIMIT_EXCEEDED", errorObj["code"])
		assert.Equal(t, "rate_limit", errorObj["category"])
		assert.True(t, errorObj["retryable"].(bool))
		assert.Contains(t, errorObj["message"], "Rate limit exceeded")
	})

	t.Run("Rate limit differentiates between IP addresses", func(t *testing.T) {
		// Clear any existing rate limit data
		testKey1 := "ip:192.0.2.3"
		testKey2 := "ip:192.0.2.4"
		err := rdb.Del(ctx, fmt.Sprintf("ratelimit:%s", testKey1)).Err()
		require.NoError(t, err)
		err = rdb.Del(ctx, fmt.Sprintf("ratelimit:%s", testKey2)).Err()
		require.NoError(t, err)

		// Exhaust rate limit for first IP
		for i := 0; i < 3; i++ {
			w := httptest.NewRecorder()
			body := bytes.NewBufferString(`{"username": "Admin", "password": "temPass2020@"}`)
			r, _ := http.NewRequest("POST", "/api/v1/login", body)
			r.Header.Set("Content-Type", "application/json")
			r.RemoteAddr = "192.0.2.3:12345"

			e.ServeHTTP(w, r)
			assert.NotEqual(t, http.StatusTooManyRequests, w.Code)
		}

		// 4th request from first IP should be rate limited
		w1 := httptest.NewRecorder()
		body1 := bytes.NewBufferString(`{"username": "Admin", "password": "temPass2020@"}`)
		r1, _ := http.NewRequest("POST", "/api/v1/login", body1)
		r1.Header.Set("Content-Type", "application/json")
		r1.RemoteAddr = "192.0.2.3:12345"

		e.ServeHTTP(w1, r1)
		assert.Equal(t, http.StatusTooManyRequests, w1.Code)

		// But request from second IP should still work
		w2 := httptest.NewRecorder()
		body2 := bytes.NewBufferString(`{"username": "Admin", "password": "temPass2020@"}`)
		r2, _ := http.NewRequest("POST", "/api/v1/login", body2)
		r2.Header.Set("Content-Type", "application/json")
		r2.RemoteAddr = "192.0.2.4:12345"

		e.ServeHTTP(w2, r2)
		assert.NotEqual(t, http.StatusTooManyRequests, w2.Code)
	})

	t.Run("Rate limit endpoint-specific mode", func(t *testing.T) {
		// Switch to endpoint-specific mode
		config.ServiceRateLimitMode.Set("endpoints")
		config.ServiceRateLimitEndpoints.Set([]string{"POST:/api/v1/login"})
		defer func() {
			config.ServiceRateLimitMode.Set("global")
			config.ServiceRateLimitEndpoints.Set([]string{})
		}()

		// Create a new Echo instance with updated config
		e2 := echo.New()
		e2.Validator = helper.NewValidator()
		rateLimiter2 := ratelimit.NewRedisRateLimiter(rdb)
		e2.Use(middlewares.RateLimit(rateLimiter2))
		e2.POST("/api/v1/login", authController.Login)
		e2.GET("/api/v1/health", func(c echo.Context) error {
			return c.JSON(200, map[string]string{"status": "ok"})
		})

		// Clear rate limit data
		testKey := "ip:192.0.2.5"
		err := rdb.Del(ctx, fmt.Sprintf("ratelimit:%s", testKey)).Err()
		require.NoError(t, err)

		// Exhaust rate limit on login endpoint
		for i := 0; i < 3; i++ {
			w := httptest.NewRecorder()
			body := bytes.NewBufferString(`{"username": "Admin", "password": "temPass2020@"}`)
			r, _ := http.NewRequest("POST", "/api/v1/login", body)
			r.Header.Set("Content-Type", "application/json")
			r.RemoteAddr = "192.0.2.5:12345"

			e2.ServeHTTP(w, r)
			assert.NotEqual(t, http.StatusTooManyRequests, w.Code)
		}

		// 4th login request should be rate limited
		w1 := httptest.NewRecorder()
		body1 := bytes.NewBufferString(`{"username": "Admin", "password": "temPass2020@"}`)
		r1, _ := http.NewRequest("POST", "/api/v1/login", body1)
		r1.Header.Set("Content-Type", "application/json")
		r1.RemoteAddr = "192.0.2.5:12345"

		e2.ServeHTTP(w1, r1)
		assert.Equal(t, http.StatusTooManyRequests, w1.Code)

		// But health endpoint should still work (not in rate limit patterns)
		w2 := httptest.NewRecorder()
		r2, _ := http.NewRequest("GET", "/api/v1/health", nil)
		r2.RemoteAddr = "192.0.2.5:12345"

		e2.ServeHTTP(w2, r2)
		assert.Equal(t, http.StatusOK, w2.Code)
	})

	t.Run("Rate limit disabled mode", func(t *testing.T) {
		// Disable rate limiting
		config.ServiceRateLimitEnabled.Set(false)
		defer config.ServiceRateLimitEnabled.Set(true)

		// Create a new Echo instance
		e3 := echo.New()
		e3.Validator = helper.NewValidator()
		rateLimiter3 := ratelimit.NewRedisRateLimiter(rdb)
		e3.Use(middlewares.RateLimit(rateLimiter3))
		e3.POST("/api/v1/login", authController.Login)

		// Make many requests - should not be rate limited
		for i := 0; i < 10; i++ {
			w := httptest.NewRecorder()
			body := bytes.NewBufferString(`{"username": "Admin", "password": "temPass2020@"}`)
			r, _ := http.NewRequest("POST", "/api/v1/login", body)
			r.Header.Set("Content-Type", "application/json")
			r.RemoteAddr = "192.0.2.6:12345"

			e3.ServeHTTP(w, r)
			assert.NotEqual(t, http.StatusTooManyRequests, w.Code,
				"Request %d should not be rate limited when disabled", i+1)
		}
	})

	t.Run("Rate limit retry after calculation", func(t *testing.T) {
		// Clear rate limit data
		testKey := "ip:192.0.2.7"
		err := rdb.Del(ctx, fmt.Sprintf("ratelimit:%s", testKey)).Err()
		require.NoError(t, err)

		// Exhaust rate limit
		for i := 0; i < 3; i++ {
			w := httptest.NewRecorder()
			body := bytes.NewBufferString(`{"username": "Admin", "password": "temPass2020@"}`)
			r, _ := http.NewRequest("POST", "/api/v1/login", body)
			r.Header.Set("Content-Type", "application/json")
			r.RemoteAddr = "192.0.2.7:12345"

			e.ServeHTTP(w, r)
		}

		// Get rate limited response
		w := httptest.NewRecorder()
		body := bytes.NewBufferString(`{"username": "Admin", "password": "temPass2020@"}`)
		r, _ := http.NewRequest("POST", "/api/v1/login", body)
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "192.0.2.7:12345"

		e.ServeHTTP(w, r)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)

		// Check Retry-After header is reasonable (should be <= 60 seconds for 1-minute window)
		retryAfterStr := w.Header().Get("Retry-After")
		assert.NotEmpty(t, retryAfterStr)

		retryAfter, err := strconv.Atoi(retryAfterStr)
		require.NoError(t, err)
		assert.True(t, retryAfter > 0 && retryAfter <= 60,
			"Retry-After should be between 1 and 60 seconds, got %d", retryAfter)

		// Check X-RateLimit-Reset header is in the future
		resetStr := w.Header().Get("X-RateLimit-Reset")
		assert.NotEmpty(t, resetStr)

		resetTime, err := strconv.ParseInt(resetStr, 10, 64)
		require.NoError(t, err)
		assert.True(t, resetTime > time.Now().Unix(),
			"X-RateLimit-Reset should be in the future")
	})
}
