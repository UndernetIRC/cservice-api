// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2025 UnderNET

// Package middlewares provides middleware functions for the Echo framework
package middlewares

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/internal/ratelimit"
)

// RateLimitMode defines the rate limiting mode
type RateLimitMode string

const (
	// RateLimitModeGlobal applies rate limiting to all endpoints
	RateLimitModeGlobal RateLimitMode = "global"
	// RateLimitModeEndpoints applies rate limiting only to specified endpoints
	RateLimitModeEndpoints RateLimitMode = "endpoints"
	// RateLimitModeChannels applies rate limiting only to channel registration endpoints (legacy)
	RateLimitModeChannels RateLimitMode = "channels"
)

// RateLimitConfig defines the configuration for rate limiting middleware
type RateLimitConfig struct {
	// Skipper defines a function to skip middleware
	Skipper func(c echo.Context) bool

	// RateLimiter is the rate limiter implementation
	RateLimiter ratelimit.RateLimiter

	// RequestsPerMinute is the number of requests allowed per minute
	RequestsPerMinute int

	// WindowMinutes is the time window in minutes
	WindowMinutes int

	// KeyGenerator generates the rate limit key for a request
	KeyGenerator func(c echo.Context) string

	// ErrorHandler handles rate limit exceeded errors
	ErrorHandler func(c echo.Context, retryAfter time.Duration) error

	// Mode determines which endpoints to rate limit
	Mode RateLimitMode

	// EndpointPatterns is a list of endpoint patterns to rate limit (used with RateLimitModeEndpoints)
	EndpointPatterns []string
}

// DefaultRateLimitConfig returns the default rate limit configuration
func DefaultRateLimitConfig() RateLimitConfig {
	mode := RateLimitMode(config.ServiceRateLimitMode.GetString())
	if mode == "" {
		mode = RateLimitModeChannels // Default to legacy behavior
	}

	var endpointPatterns []string
	if mode == RateLimitModeEndpoints {
		patterns := config.ServiceRateLimitEndpoints.GetStringSlice()
		if len(patterns) > 0 {
			endpointPatterns = patterns
		} else {
			// Default to channel registration if no patterns specified
			endpointPatterns = []string{"POST:/api/v1/channels"}
		}
	}

	return RateLimitConfig{
		Skipper:           func(_ echo.Context) bool { return false },
		RequestsPerMinute: config.ServiceRateLimitRequestsPerMinute.GetInt(),
		WindowMinutes:     config.ServiceRateLimitWindowMinutes.GetInt(),
		KeyGenerator:      defaultKeyGenerator,
		ErrorHandler:      defaultErrorHandler,
		Mode:              mode,
		EndpointPatterns:  endpointPatterns,
	}
}

// RateLimit returns a rate limiting middleware with default configuration
func RateLimit(rateLimiter ratelimit.RateLimiter) echo.MiddlewareFunc {
	config := DefaultRateLimitConfig()
	config.RateLimiter = rateLimiter
	return RateLimitWithConfig(config)
}

// RateLimitWithConfig returns a rate limiting middleware with custom configuration
func RateLimitWithConfig(config RateLimitConfig) echo.MiddlewareFunc {
	// Set defaults if not provided
	if config.Skipper == nil {
		config.Skipper = func(_ echo.Context) bool { return false }
	}
	if config.KeyGenerator == nil {
		config.KeyGenerator = defaultKeyGenerator
	}
	if config.ErrorHandler == nil {
		config.ErrorHandler = defaultErrorHandler
	}
	if config.RequestsPerMinute == 0 {
		config.RequestsPerMinute = 10
	}
	if config.WindowMinutes == 0 {
		config.WindowMinutes = 1
	}
	if config.Mode == "" {
		config.Mode = RateLimitModeChannels
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Skip if rate limiting is disabled
			if !config.Skipper(c) && !isRateLimitEnabled() {
				return next(c)
			}

			if config.Skipper(c) {
				return next(c)
			}

			// Check if this endpoint should be rate limited based on mode
			if !shouldRateLimit(c, config.Mode, config.EndpointPatterns) {
				return next(c)
			}

			// Generate rate limit key
			key := config.KeyGenerator(c)
			if key == "" {
				// If we can't generate a key, allow the request but log it
				c.Logger().Warn("Rate limit key generation failed, allowing request")
				return next(c)
			}

			// Check rate limit
			window := time.Duration(config.WindowMinutes) * time.Minute
			allowed, retryAfter, err := config.RateLimiter.Allow(
				c.Request().Context(),
				key,
				config.RequestsPerMinute,
				window,
			)
			if err != nil {
				// On rate limiter error, log and allow the request
				c.Logger().Errorf("Rate limiter error: %v", err)
				return next(c)
			}

			if !allowed {
				return config.ErrorHandler(c, retryAfter)
			}

			return next(c)
		}
	}
}

// defaultKeyGenerator generates a rate limit key based on user ID or IP address
func defaultKeyGenerator(c echo.Context) string {
	user := c.Get("user")

	// Check for API key authentication
	if apiKey, ok := user.(*helper.APIKeyContext); ok {
		return fmt.Sprintf("apikey:%d", apiKey.ID)
	}

	// Check for JWT authentication
	if token, ok := user.(*jwt.Token); ok && token != nil {
		if claims, ok := token.Claims.(*helper.JwtClaims); ok {
			return fmt.Sprintf("user:%d", claims.UserID)
		}
		// Fallback for MapClaims (legacy and tests)
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			// Try user_id first (production)
			if userID, ok := claims["user_id"].(float64); ok {
				return fmt.Sprintf("user:%d", int64(userID))
			}
			// Try id field (tests)
			if userID, ok := claims["id"].(float64); ok {
				return fmt.Sprintf("user:%d", int64(userID))
			}
		}
	}

	// Fall back to IP address
	return fmt.Sprintf("ip:%s", c.RealIP())
}

// defaultErrorHandler handles rate limit exceeded responses
func defaultErrorHandler(c echo.Context, retryAfter time.Duration) error {
	retrySeconds := int(retryAfter.Seconds())
	c.Response().Header().Set("Retry-After", strconv.Itoa(retrySeconds))
	c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(config.ServiceRateLimitRequestsPerMinute.GetInt()))
	c.Response().Header().Set("X-RateLimit-Remaining", "0")
	c.Response().Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(retryAfter).Unix(), 10))

	return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
		"success": false,
		"error": map[string]interface{}{
			"code":      "RATE_LIMIT_EXCEEDED",
			"message":   fmt.Sprintf("Rate limit exceeded. Try again in %d seconds", retrySeconds),
			"category":  "rate_limit",
			"retryable": true,
			"details": map[string]interface{}{
				"retry_after_seconds": retrySeconds,
				"limit_per_minute":    config.ServiceRateLimitRequestsPerMinute.GetInt(),
			},
		},
	})
}

// isRateLimitEnabled checks if rate limiting is enabled in configuration
func isRateLimitEnabled() bool {
	return config.ServiceRateLimitEnabled.GetBool()
}

// shouldRateLimit determines if the current request should be rate limited based on mode and patterns
func shouldRateLimit(c echo.Context, mode RateLimitMode, endpointPatterns []string) bool {
	switch mode {
	case RateLimitModeGlobal:
		return true // Rate limit all endpoints
	case RateLimitModeEndpoints:
		return matchesEndpointPatterns(c, endpointPatterns)
	case RateLimitModeChannels:
		return isChannelRegistrationEndpoint(c)
	default:
		return false
	}
}

// matchesEndpointPatterns checks if the current request matches any of the specified patterns
func matchesEndpointPatterns(c echo.Context, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}

	path := c.Request().URL.Path
	method := c.Request().Method

	for _, pattern := range patterns {
		if matchesPattern(method, path, pattern) {
			return true
		}
	}
	return false
}

// matchesPattern checks if a method and path match a pattern
// Pattern format: "METHOD:/path/pattern" or "/path/pattern" (any method)
// Supports wildcards: * for any segment, ** for any number of segments
func matchesPattern(method, path, pattern string) bool {
	var patternMethod, patternPath string

	// Parse pattern
	if strings.Contains(pattern, ":") {
		parts := strings.SplitN(pattern, ":", 2)
		patternMethod = parts[0]
		patternPath = parts[1]
	} else {
		patternMethod = "*" // Any method
		patternPath = pattern
	}

	// Check method match
	if patternMethod != "*" && patternMethod != method {
		return false
	}

	// Check path match
	return matchesPathPattern(path, patternPath)
}

// matchesPathPattern checks if a path matches a pattern with wildcards
func matchesPathPattern(path, pattern string) bool {
	// Simple exact match
	if pattern == path {
		return true
	}

	// Wildcard matching
	if strings.Contains(pattern, "*") {
		return matchesWildcard(path, pattern)
	}

	// Suffix matching for convenience (e.g., "/channels" matches "/api/v1/channels")
	return strings.HasSuffix(path, pattern)
}

// matchesWildcard performs wildcard matching
func matchesWildcard(path, pattern string) bool {
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	patternParts := strings.Split(strings.Trim(pattern, "/"), "/")

	return matchesWildcardParts(pathParts, patternParts)
}

// matchesWildcardParts performs recursive wildcard matching on path parts
func matchesWildcardParts(pathParts, patternParts []string) bool {
	if len(patternParts) == 0 {
		return len(pathParts) == 0
	}

	if len(pathParts) == 0 {
		// Check if remaining pattern parts are all wildcards that can match zero segments
		for _, part := range patternParts {
			if part != "**" {
				return false // * requires at least one segment, only ** can match zero
			}
		}
		return true
	}

	pattern := patternParts[0]

	if pattern == "**" {
		// ** matches zero or more segments
		if len(patternParts) == 1 {
			return true // ** at end matches everything
		}
		// Try matching with consuming 0, 1, 2, ... path parts
		for i := 0; i <= len(pathParts); i++ {
			if matchesWildcardParts(pathParts[i:], patternParts[1:]) {
				return true
			}
		}
		return false
	}

	if pattern == "*" {
		// * matches exactly one segment (cannot match zero segments)
		if len(pathParts) == 0 {
			return false
		}
		return matchesWildcardParts(pathParts[1:], patternParts[1:])
	}

	if pattern == pathParts[0] {
		// Exact match
		return matchesWildcardParts(pathParts[1:], patternParts[1:])
	}

	return false
}

// isChannelRegistrationEndpoint checks if the current request is for channel registration
func isChannelRegistrationEndpoint(c echo.Context) bool {
	path := c.Request().URL.Path
	method := c.Request().Method

	// Check for POST /api/v1/channels (channel registration endpoint)
	return method == "POST" && strings.HasSuffix(path, "/channels")
}
