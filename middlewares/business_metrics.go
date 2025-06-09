// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

// Package middlewares provides HTTP middleware for business metrics collection
package middlewares

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/undernetirc/cservice-api/internal/metrics"
)

// BusinessMetricsConfig holds configuration for business metrics middleware
type BusinessMetricsConfig struct {
	BusinessMetrics *metrics.BusinessMetrics
	Skipper         func(echo.Context) bool
}

// BusinessMetricsMiddleware creates middleware for collecting business metrics
func BusinessMetricsMiddleware(config BusinessMetricsConfig) echo.MiddlewareFunc {
	// Default skipper
	if config.Skipper == nil {
		config.Skipper = func(_ echo.Context) bool {
			return false
		}
	}

	// If no business metrics provided, return no-op middleware
	if config.BusinessMetrics == nil {
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(c echo.Context) error {
				return next(c)
			}
		}
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Skip if configured to skip
			if config.Skipper(c) {
				return next(c)
			}

			start := time.Now()
			ctx := c.Request().Context()

			// Capture request body for analysis
			var requestBody []byte
			if c.Request().Body != nil {
				requestBody, _ = io.ReadAll(c.Request().Body)
				c.Request().Body = io.NopCloser(bytes.NewBuffer(requestBody))
			}

			// Execute the handler
			err := next(c)

			// Calculate duration
			duration := time.Since(start)
			status := c.Response().Status

			// Record business metrics based on endpoint
			recordBusinessMetrics(ctx, config.BusinessMetrics, c, requestBody, status, duration)

			return err
		}
	}
}

// recordBusinessMetrics records metrics based on the endpoint and operation
func recordBusinessMetrics(ctx context.Context, businessMetrics *metrics.BusinessMetrics, c echo.Context, requestBody []byte, status int, duration time.Duration) {
	path := c.Request().URL.Path
	method := c.Request().Method
	success := status >= 200 && status < 400

	// Extract user ID from context if available
	userID := extractUserID(c)

	// Record API request metrics for all endpoints
	businessMetrics.RecordAPIRequest(ctx, path, method, userID, success)

	// Record business metrics based on specific endpoints
	switch {
	case strings.Contains(path, "/register") && method == "POST":
		recordRegistrationMetrics(ctx, businessMetrics, status, duration, requestBody)

	case strings.Contains(path, "/activate") && method == "POST":
		recordActivationMetrics(ctx, businessMetrics, status, duration, requestBody)

	case strings.Contains(path, "/channels/search") && method == "GET":
		recordChannelSearchMetrics(ctx, businessMetrics, c, status, duration, success)

	case strings.Contains(path, "/channels/") && strings.Contains(path, "/settings") && method == "GET":
		recordChannelSettingsViewMetrics(ctx, businessMetrics, c, userID)

	case strings.Contains(path, "/channels/") && strings.Contains(path, "/settings") && method == "PUT":
		recordChannelSettingsUpdateMetrics(ctx, businessMetrics, c, status, userID, requestBody)

	case strings.Contains(path, "/channels/") && strings.Contains(path, "/members") && method == "POST":
		recordChannelMemberAddMetrics(ctx, businessMetrics, c, status, userID, requestBody)

	case strings.Contains(path, "/channels/") && strings.Contains(path, "/members") && method == "DELETE":
		recordChannelMemberRemoveMetrics(ctx, businessMetrics, c, status, userID)

	case strings.Contains(path, "/login") && method == "POST":
		recordUserSessionMetrics(ctx, businessMetrics, userID, "web", 0) // New session

	case strings.Contains(path, "/logout") && method == "POST":
		recordUserLogoutMetrics(ctx, businessMetrics, userID)
	}

	// Record feature usage based on successful operations
	if success {
		recordFeatureUsageMetrics(ctx, businessMetrics, path, method, userID)
	}

	// Record general business health metrics
	errorRate := calculateErrorRate(status)
	businessMetrics.RecordBusinessMetric(ctx, getOperationType(path, method), duration, success, errorRate)
}

// recordRegistrationMetrics records user registration metrics
func recordRegistrationMetrics(ctx context.Context, businessMetrics *metrics.BusinessMetrics, status int, duration time.Duration, requestBody []byte) {
	success := status >= 200 && status < 400
	username, email := extractRegistrationInfo(requestBody)
	reason := getRegistrationReason(status, success)

	businessMetrics.RecordRegistrationAttempt(ctx, username, email, success, duration, reason)
}

// recordActivationMetrics records account activation metrics
func recordActivationMetrics(ctx context.Context, businessMetrics *metrics.BusinessMetrics, status int, duration time.Duration, requestBody []byte) {
	success := status >= 200 && status < 400
	username := extractUsernameFromActivation(requestBody)
	reason := getActivationReason(status, success)

	businessMetrics.RecordActivationAttempt(ctx, username, success, duration, reason)
}

// recordChannelSearchMetrics records channel search metrics
func recordChannelSearchMetrics(ctx context.Context, businessMetrics *metrics.BusinessMetrics, c echo.Context, _ int, duration time.Duration, success bool) {
	userID := extractUserID(c)
	query := c.QueryParam("q")
	if query == "" {
		query = c.QueryParam("query")
	}

	// Extract result count from response if available
	resultCount := extractResultCount(c)

	businessMetrics.RecordChannelSearch(ctx, userID, query, resultCount, duration, success)
}

// recordChannelSettingsViewMetrics records channel settings view metrics
func recordChannelSettingsViewMetrics(ctx context.Context, businessMetrics *metrics.BusinessMetrics, c echo.Context, userID int32) {
	channelID := extractChannelID(c)
	accessLevel := extractAccessLevel(c)

	businessMetrics.RecordChannelSettingsView(ctx, userID, channelID, accessLevel)
}

// recordChannelSettingsUpdateMetrics records channel settings update metrics
func recordChannelSettingsUpdateMetrics(ctx context.Context, businessMetrics *metrics.BusinessMetrics, c echo.Context, status int, userID int32, requestBody []byte) {
	channelID := extractChannelID(c)
	success := status >= 200 && status < 400
	fieldsUpdated := extractUpdatedFields(requestBody)

	businessMetrics.RecordChannelSettingsUpdate(ctx, userID, channelID, success, fieldsUpdated)
}

// recordChannelMemberAddMetrics records channel member addition metrics
func recordChannelMemberAddMetrics(ctx context.Context, businessMetrics *metrics.BusinessMetrics, c echo.Context, status int, userID int32, requestBody []byte) {
	channelID := extractChannelID(c)
	targetUserID := extractTargetUserID(requestBody)
	success := status >= 200 && status < 400
	accessLevel := extractMemberAccessLevel(requestBody)

	businessMetrics.RecordChannelMemberOperation(ctx, userID, channelID, targetUserID, "add", success, accessLevel)
}

// recordChannelMemberRemoveMetrics records channel member removal metrics
func recordChannelMemberRemoveMetrics(ctx context.Context, businessMetrics *metrics.BusinessMetrics, c echo.Context, status int, userID int32) {
	channelID := extractChannelID(c)
	targetUserID := extractTargetUserIDFromPath(c)
	success := status >= 200 && status < 400

	businessMetrics.RecordChannelMemberOperation(ctx, userID, channelID, targetUserID, "remove", success, 0)
}

// recordUserSessionMetrics records user session metrics
func recordUserSessionMetrics(ctx context.Context, businessMetrics *metrics.BusinessMetrics, userID int32, sessionType string, duration time.Duration) {
	if userID > 0 {
		businessMetrics.RecordUserSession(ctx, userID, sessionType, duration)
		businessMetrics.RecordActiveUser(ctx, userID, "login")
	}
}

// recordUserLogoutMetrics records user logout metrics
func recordUserLogoutMetrics(ctx context.Context, businessMetrics *metrics.BusinessMetrics, userID int32) {
	if userID > 0 {
		businessMetrics.RecordActiveUser(ctx, userID, "logout")
	}
}

// recordFeatureUsageMetrics records feature usage based on successful operations
func recordFeatureUsageMetrics(ctx context.Context, businessMetrics *metrics.BusinessMetrics, path, method string, userID int32) {
	feature := getFeatureName(path, method)
	if feature != "" && userID > 0 {
		contextInfo := map[string]string{
			"endpoint": path,
			"method":   method,
		}
		businessMetrics.RecordFeatureUsage(ctx, feature, userID, contextInfo)
	}
}

// Helper functions for extracting information

// extractUserID extracts user ID from the request context
func extractUserID(c echo.Context) int32 {
	// Try to get user ID from context (set by auth middleware)
	if userID := c.Get("user_id"); userID != nil {
		if id, ok := userID.(int32); ok {
			return id
		}
		if id, ok := userID.(int); ok {
			// Check for overflow before conversion
			if id >= -2147483648 && id <= 2147483647 {
				return int32(id)
			}
		}
		if id, ok := userID.(string); ok {
			if parsed, err := strconv.ParseInt(id, 10, 32); err == nil {
				return int32(parsed)
			}
		}
	}
	return 0
}

// extractChannelID extracts channel ID from the URL path
func extractChannelID(c echo.Context) int32 {
	channelIDStr := c.Param("id")
	if channelIDStr == "" {
		channelIDStr = c.Param("channel_id")
	}
	if channelID, err := strconv.ParseInt(channelIDStr, 10, 32); err == nil {
		return int32(channelID)
	}
	return 0
}

// extractAccessLevel extracts access level from context or headers
func extractAccessLevel(c echo.Context) int {
	// Try to get access level from context (set by auth middleware)
	if level := c.Get("access_level"); level != nil {
		if accessLevel, ok := level.(int); ok {
			return accessLevel
		}
	}
	return 100 // Default user level
}

// extractRegistrationInfo extracts username and email from registration request
func extractRegistrationInfo(requestBody []byte) (string, string) {
	var data map[string]interface{}
	if err := json.Unmarshal(requestBody, &data); err != nil {
		return "", ""
	}

	username, _ := data["username"].(string)
	email, _ := data["email"].(string)
	return username, email
}

// extractUsernameFromActivation extracts username from activation request
func extractUsernameFromActivation(requestBody []byte) string {
	var data map[string]interface{}
	if err := json.Unmarshal(requestBody, &data); err != nil {
		return ""
	}

	username, _ := data["username"].(string)
	return username
}

// extractResultCount extracts result count from response context
func extractResultCount(c echo.Context) int {
	// Try to get result count from context (set by handler)
	if count := c.Get("result_count"); count != nil {
		if resultCount, ok := count.(int); ok {
			return resultCount
		}
	}
	return 0
}

// extractUpdatedFields extracts updated fields from request body
func extractUpdatedFields(requestBody []byte) []string {
	var data map[string]interface{}
	if err := json.Unmarshal(requestBody, &data); err != nil {
		return []string{}
	}

	var fields []string
	for key := range data {
		fields = append(fields, key)
	}
	return fields
}

// extractTargetUserID extracts target user ID from request body
func extractTargetUserID(requestBody []byte) int32 {
	var data map[string]interface{}
	if err := json.Unmarshal(requestBody, &data); err != nil {
		return 0
	}

	if userID, ok := data["user_id"].(float64); ok {
		return int32(userID)
	}
	if userIDStr, ok := data["user_id"].(string); ok {
		if parsed, err := strconv.ParseInt(userIDStr, 10, 32); err == nil {
			return int32(parsed)
		}
	}
	return 0
}

// extractTargetUserIDFromPath extracts target user ID from URL path
func extractTargetUserIDFromPath(c echo.Context) int32 {
	userIDStr := c.Param("user_id")
	if userID, err := strconv.ParseInt(userIDStr, 10, 32); err == nil {
		return int32(userID)
	}
	return 0
}

// extractMemberAccessLevel extracts access level for new member
func extractMemberAccessLevel(requestBody []byte) int {
	var data map[string]interface{}
	if err := json.Unmarshal(requestBody, &data); err != nil {
		return 100 // Default user level
	}

	if level, ok := data["access_level"].(float64); ok {
		return int(level)
	}
	return 100 // Default user level
}

// getRegistrationReason determines the reason for registration success/failure
func getRegistrationReason(status int, success bool) string {
	if success {
		return "success"
	}

	switch status {
	case 400:
		return "invalid_data"
	case 409:
		return "username_or_email_exists"
	case 422:
		return "validation_failed"
	default:
		return "server_error"
	}
}

// getActivationReason determines the reason for activation success/failure
func getActivationReason(status int, success bool) string {
	if success {
		return "success"
	}

	switch status {
	case 400:
		return "invalid_token"
	case 404:
		return "token_not_found"
	case 410:
		return "token_expired"
	default:
		return "server_error"
	}
}

// getOperationType determines the operation type from path and method
func getOperationType(path, method string) string {
	switch {
	case strings.Contains(path, "/register"):
		return "user_registration"
	case strings.Contains(path, "/activate"):
		return "user_activation"
	case strings.Contains(path, "/login"):
		return "user_login"
	case strings.Contains(path, "/logout"):
		return "user_logout"
	case strings.Contains(path, "/channels/search"):
		return "channel_search"
	case strings.Contains(path, "/channels/") && strings.Contains(path, "/settings"):
		if method == "GET" {
			return "channel_settings_view"
		}
		return "channel_settings_update"
	case strings.Contains(path, "/channels/") && strings.Contains(path, "/members"):
		if method == "POST" {
			return "channel_member_add"
		}
		return "channel_member_remove"
	default:
		return "general_api"
	}
}

// getFeatureName determines the feature name from path and method
func getFeatureName(path, _ string) string {
	switch {
	case strings.Contains(path, "/register"):
		return "user_registration"
	case strings.Contains(path, "/activate"):
		return "user_activation"
	case strings.Contains(path, "/channels/search"):
		return "channel_search"
	case strings.Contains(path, "/channels/") && strings.Contains(path, "/settings"):
		return "channel_settings"
	case strings.Contains(path, "/channels/") && strings.Contains(path, "/members"):
		return "channel_members"
	default:
		return ""
	}
}

// calculateErrorRate calculates error rate based on status code
func calculateErrorRate(status int) float64 {
	if status >= 400 {
		return 100.0 // 100% error rate for this request
	}
	return 0.0 // 0% error rate for successful requests
}
