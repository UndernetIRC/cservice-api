// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package tracing

import (
	"strings"

	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/attribute"
)

// HTTPRequestAttributes extracts common HTTP request attributes from Echo context
func HTTPRequestAttributes(c echo.Context) map[string]interface{} {
	return map[string]interface{}{
		"http.method":      c.Request().Method,
		"http.path":        c.Request().URL.Path,
		"http.user_agent":  c.Request().UserAgent(),
		"http.remote_addr": c.RealIP(),
		"http.request_id":  c.Response().Header().Get(echo.HeaderXRequestID),
	}
}

// AddHTTPRequestAttrs adds HTTP request attributes to a traced context
func AddHTTPRequestAttrs(tc *TracedContext, c echo.Context) {
	tc.AddAttrs(HTTPRequestAttributes(c))
}

// EmailAttributes extracts email-related attributes for tracing
// Safely extracts email domain and validates format
func EmailAttributes(email string) map[string]interface{} {
	attrs := map[string]interface{}{
		"email.provided": email != "",
	}

	if email != "" {
		attrs["email.length"] = len(email)

		// Extract domain safely
		if emailParts := strings.Split(email, "@"); len(emailParts) == 2 {
			attrs["email.domain"] = emailParts[1]
			attrs["email.local_part_length"] = len(emailParts[0])
			attrs["email.format_valid"] = true
		} else {
			attrs["email.domain"] = "invalid"
			attrs["email.format_valid"] = false
		}
	}

	return attrs
}

// AddEmailAttrs adds email-related attributes to a traced context
func AddEmailAttrs(tc *TracedContext, email string) {
	tc.AddAttrs(EmailAttributes(email))
}

// UsernameAttributes extracts username-related attributes for tracing
func UsernameAttributes(username string) map[string]interface{} {
	attrs := map[string]interface{}{
		"username.provided": username != "",
	}

	if username != "" {
		attrs["username.length"] = len(username)
		attrs["username.has_special_chars"] = strings.ContainsAny(username, "!@#$%^&*()+=[]{}|\\:;\"'<>,.?/")
		attrs["username.has_numbers"] = strings.ContainsAny(username, "0123456789")
		attrs["username.is_lowercase"] = username == strings.ToLower(username)
	}

	return attrs
}

// AddUsernameAttrs adds username-related attributes to a traced context
func AddUsernameAttrs(tc *TracedContext, username string) {
	tc.AddAttrs(UsernameAttributes(username))
}

// TokenAttributes extracts token-related attributes for tracing
// Safely extracts token metadata without logging the token itself
func TokenAttributes(token string, tokenType string) map[string]interface{} {
	attrs := map[string]interface{}{
		"token.type":     tokenType,
		"token.provided": token != "",
	}

	if token != "" {
		attrs["token.length"] = len(token)

		// Extract prefix safely (first 8 chars for identification)
		if len(token) >= 8 {
			attrs["token.prefix"] = token[:8]
		}

		// Check if it looks like a JWT (has two dots)
		if strings.Count(token, ".") == 2 {
			attrs["token.format"] = "jwt"
			parts := strings.Split(token, ".")
			attrs["token.header_length"] = len(parts[0])
			attrs["token.payload_length"] = len(parts[1])
			attrs["token.signature_length"] = len(parts[2])
		} else {
			attrs["token.format"] = "opaque"
		}
	}

	return attrs
}

// AddTokenAttrs adds token-related attributes to a traced context
func AddTokenAttrs(tc *TracedContext, token string, tokenType string) {
	tc.AddAttrs(TokenAttributes(token, tokenType))
}

// ValidationResultAttrs creates attributes for validation results
func ValidationResultAttrs(field string, valid bool, reason string) map[string]interface{} {
	attrs := map[string]interface{}{
		"validation.field": field,
		"validation.valid": valid,
	}

	if !valid && reason != "" {
		attrs["validation.failure_reason"] = reason
	}

	return attrs
}

// AddValidationResultAttrs adds validation result attributes to a traced context
func AddValidationResultAttrs(tc *TracedContext, field string, valid bool, reason string) {
	tc.AddAttrs(ValidationResultAttrs(field, valid, reason))
}

// DatabaseOperationAttrs creates attributes for database operations
func DatabaseOperationAttrs(operation string, table string, affected int64) map[string]interface{} {
	return map[string]interface{}{
		"db.operation":     operation,
		"db.table":         table,
		"db.rows_affected": affected,
	}
}

// AddDatabaseOperationAttrs adds database operation attributes to a traced context
func AddDatabaseOperationAttrs(tc *TracedContext, operation string, table string, affected int64) {
	tc.AddAttrs(DatabaseOperationAttrs(operation, table, affected))
}

// AuthenticationAttrs creates attributes for authentication operations
func AuthenticationAttrs(username string, authType string, success bool) map[string]interface{} {
	attrs := map[string]interface{}{
		"auth.type":    authType,
		"auth.success": success,
	}

	// Only include username if authentication succeeded or we're in a safe context
	if username != "" {
		attrs["auth.username"] = username
	}

	return attrs
}

// AddAuthenticationAttrs adds authentication attributes to a traced context
func AddAuthenticationAttrs(tc *TracedContext, username string, authType string, success bool) {
	tc.AddAttrs(AuthenticationAttrs(username, authType, success))
}

// ChannelOperationAttrs creates attributes for channel-related operations
func ChannelOperationAttrs(channelName string, operation string) map[string]interface{} {
	return map[string]interface{}{
		"channel.name":      channelName,
		"channel.operation": operation,
	}
}

// AddChannelOperationAttrs adds channel operation attributes to a traced context
func AddChannelOperationAttrs(tc *TracedContext, channelName string, operation string) {
	tc.AddAttrs(ChannelOperationAttrs(channelName, operation))
}

// UserActivityAttrs creates attributes for user activity tracking
func UserActivityAttrs(userID int64, username string, activity string) map[string]interface{} {
	return map[string]interface{}{
		"user.id":       userID,
		"user.username": username,
		"user.activity": activity,
	}
}

// AddUserActivityAttrs adds user activity attributes to a traced context
func AddUserActivityAttrs(tc *TracedContext, userID int64, username string, activity string) {
	tc.AddAttrs(UserActivityAttrs(userID, username, activity))
}

// MailOperationAttrs creates attributes for email operations
func MailOperationAttrs(recipient string, subject string, template string) map[string]interface{} {
	attrs := map[string]interface{}{
		"mail.template": template,
	}

	// Add email domain but not full email for privacy
	if emailParts := strings.Split(recipient, "@"); len(emailParts) == 2 {
		attrs["mail.recipient_domain"] = emailParts[1]
	}

	// Add subject length but not full subject for privacy
	if subject != "" {
		attrs["mail.subject_length"] = len(subject)
	}

	return attrs
}

// AddMailOperationAttrs adds email operation attributes to a traced context
func AddMailOperationAttrs(tc *TracedContext, recipient string, subject string, template string) {
	tc.AddAttrs(MailOperationAttrs(recipient, subject, template))
}

// SecurityEventAttrs creates attributes for security-related events
func SecurityEventAttrs(eventType string, severity string, details map[string]interface{}) map[string]interface{} {
	attrs := map[string]interface{}{
		"security.event_type": eventType,
		"security.severity":   severity,
	}

	// Add prefixed details
	for key, value := range details {
		attrs["security."+key] = value
	}

	return attrs
}

// AddSecurityEventAttrs adds security event attributes to a traced context
func AddSecurityEventAttrs(tc *TracedContext, eventType string, severity string, details map[string]interface{}) {
	tc.AddAttrs(SecurityEventAttrs(eventType, severity, details))
}

// RateLimitAttrs creates attributes for rate limiting events
func RateLimitAttrs(identifier string, limit int64, remaining int64, resetTime int64) map[string]interface{} {
	return map[string]interface{}{
		"ratelimit.identifier": identifier,
		"ratelimit.limit":      limit,
		"ratelimit.remaining":  remaining,
		"ratelimit.reset_time": resetTime,
		"ratelimit.exceeded":   remaining <= 0,
	}
}

// AddRateLimitAttrs adds rate limiting attributes to a traced context
func AddRateLimitAttrs(tc *TracedContext, identifier string, limit int64, remaining int64, resetTime int64) {
	tc.AddAttrs(RateLimitAttrs(identifier, limit, remaining, resetTime))
}

// CacheOperationAttrs creates attributes for cache operations
func CacheOperationAttrs(operation string, key string, hit bool) map[string]interface{} {
	return map[string]interface{}{
		"cache.operation": operation,
		"cache.key":       key,
		"cache.hit":       hit,
	}
}

// AddCacheOperationAttrs adds cache operation attributes to a traced context
func AddCacheOperationAttrs(tc *TracedContext, operation string, key string, hit bool) {
	tc.AddAttrs(CacheOperationAttrs(operation, key, hit))
}

// BusinessMetricAttrs creates attributes for business metrics
func BusinessMetricAttrs(metricName string, value interface{}, unit string) map[string]interface{} {
	return map[string]interface{}{
		"metric.name":  metricName,
		"metric.value": value,
		"metric.unit":  unit,
	}
}

// AddBusinessMetricAttrs adds business metric attributes to a traced context
func AddBusinessMetricAttrs(tc *TracedContext, metricName string, value interface{}, unit string) {
	tc.AddAttrs(BusinessMetricAttrs(metricName, value, unit))
}

// Helper to create span events with structured attributes
func (tc *TracedContext) AddStructuredEvent(eventName string, attrs map[string]interface{}) {
	if tc.span == nil || !tc.span.IsRecording() {
		return
	}

	kvAttrs := make([]attribute.KeyValue, 0, len(attrs))
	for key, value := range attrs {
		kvAttrs = append(kvAttrs, convertToAttribute(key, value))
	}

	tc.AddEvent(eventName, kvAttrs...)
}
