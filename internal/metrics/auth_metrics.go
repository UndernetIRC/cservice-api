// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

// Package metrics provides authentication-specific metrics collection
package metrics

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// AuthMetrics holds all authentication-related metric instruments
type AuthMetrics struct {
	// Login metrics
	loginAttempts  metric.Int64Counter
	loginDuration  metric.Float64Histogram
	loginSuccesses metric.Int64Counter
	loginFailures  metric.Int64Counter

	// MFA metrics
	mfaAttempts  metric.Int64Counter
	mfaSuccesses metric.Int64Counter
	mfaFailures  metric.Int64Counter
	mfaDuration  metric.Float64Histogram

	// Token metrics
	tokenGenerated metric.Int64Counter
	tokenRefreshed metric.Int64Counter
	tokenRevoked   metric.Int64Counter
	tokenValidated metric.Int64Counter
	tokenExpired   metric.Int64Counter

	// Session metrics
	activeSessions  metric.Int64UpDownCounter
	sessionDuration metric.Float64Histogram

	// Password reset metrics
	passwordResetRequests metric.Int64Counter
	passwordResetSuccess  metric.Int64Counter
	passwordResetFailures metric.Int64Counter
}

// AuthMetricsConfig holds configuration for authentication metrics
type AuthMetricsConfig struct {
	Meter       metric.Meter
	ServiceName string
}

// NewAuthMetrics creates a new authentication metrics collector
func NewAuthMetrics(config AuthMetricsConfig) (*AuthMetrics, error) {
	if config.Meter == nil {
		return nil, fmt.Errorf("meter cannot be nil")
	}

	if config.ServiceName == "" {
		config.ServiceName = "cservice-api"
	}

	metrics := &AuthMetrics{}

	// Create login metrics
	var err error
	metrics.loginAttempts, err = config.Meter.Int64Counter(
		"auth_login_attempts_total",
		metric.WithDescription("Total number of login attempts"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create login attempts counter: %w", err)
	}

	metrics.loginDuration, err = config.Meter.Float64Histogram(
		"auth_login_duration_ms",
		metric.WithDescription("Login request duration in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create login duration histogram: %w", err)
	}

	metrics.loginSuccesses, err = config.Meter.Int64Counter(
		"auth_login_successes_total",
		metric.WithDescription("Total number of successful logins"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create login successes counter: %w", err)
	}

	metrics.loginFailures, err = config.Meter.Int64Counter(
		"auth_login_failures_total",
		metric.WithDescription("Total number of failed logins"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create login failures counter: %w", err)
	}

	// Create MFA metrics
	metrics.mfaAttempts, err = config.Meter.Int64Counter(
		"auth_mfa_attempts_total",
		metric.WithDescription("Total number of MFA attempts"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create MFA attempts counter: %w", err)
	}

	metrics.mfaSuccesses, err = config.Meter.Int64Counter(
		"auth_mfa_successes_total",
		metric.WithDescription("Total number of successful MFA verifications"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create MFA successes counter: %w", err)
	}

	metrics.mfaFailures, err = config.Meter.Int64Counter(
		"auth_mfa_failures_total",
		metric.WithDescription("Total number of failed MFA verifications"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create MFA failures counter: %w", err)
	}

	metrics.mfaDuration, err = config.Meter.Float64Histogram(
		"auth_mfa_duration_ms",
		metric.WithDescription("MFA verification duration in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create MFA duration histogram: %w", err)
	}

	// Create token metrics
	metrics.tokenGenerated, err = config.Meter.Int64Counter(
		"auth_tokens_generated_total",
		metric.WithDescription("Total number of tokens generated"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create token generated counter: %w", err)
	}

	metrics.tokenRefreshed, err = config.Meter.Int64Counter(
		"auth_tokens_refreshed_total",
		metric.WithDescription("Total number of tokens refreshed"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create token refreshed counter: %w", err)
	}

	metrics.tokenRevoked, err = config.Meter.Int64Counter(
		"auth_tokens_revoked_total",
		metric.WithDescription("Total number of tokens revoked"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create token revoked counter: %w", err)
	}

	metrics.tokenValidated, err = config.Meter.Int64Counter(
		"auth_tokens_validated_total",
		metric.WithDescription("Total number of token validations"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create token validated counter: %w", err)
	}

	metrics.tokenExpired, err = config.Meter.Int64Counter(
		"auth_tokens_expired_total",
		metric.WithDescription("Total number of expired tokens encountered"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create token expired counter: %w", err)
	}

	// Create session metrics
	metrics.activeSessions, err = config.Meter.Int64UpDownCounter(
		"auth_active_sessions",
		metric.WithDescription("Number of active user sessions"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create active sessions gauge: %w", err)
	}

	metrics.sessionDuration, err = config.Meter.Float64Histogram(
		"auth_session_duration_seconds",
		metric.WithDescription("User session duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create session duration histogram: %w", err)
	}

	// Create password reset metrics
	metrics.passwordResetRequests, err = config.Meter.Int64Counter(
		"auth_password_reset_requests_total",
		metric.WithDescription("Total number of password reset requests"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create password reset requests counter: %w", err)
	}

	metrics.passwordResetSuccess, err = config.Meter.Int64Counter(
		"auth_password_reset_success_total",
		metric.WithDescription("Total number of successful password resets"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create password reset success counter: %w", err)
	}

	metrics.passwordResetFailures, err = config.Meter.Int64Counter(
		"auth_password_reset_failures_total",
		metric.WithDescription("Total number of failed password resets"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create password reset failures counter: %w", err)
	}

	return metrics, nil
}

// RecordLoginAttempt records a login attempt with the given result
func (m *AuthMetrics) RecordLoginAttempt(ctx context.Context, username string, success bool, duration time.Duration, reason string) {
	attrs := []attribute.KeyValue{
		attribute.String("username", username),
		attribute.String("result", getResultString(success)),
	}

	if !success && reason != "" {
		attrs = append(attrs, attribute.String("failure_reason", reason))
	}

	// Record attempt
	m.loginAttempts.Add(ctx, 1, metric.WithAttributes(attrs...))

	// Record duration
	durationMs := float64(duration.Nanoseconds()) / 1e6
	m.loginDuration.Record(ctx, durationMs, metric.WithAttributes(attrs...))

	// Record success/failure
	if success {
		m.loginSuccesses.Add(ctx, 1, metric.WithAttributes(attrs...))
	} else {
		m.loginFailures.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// RecordMFAAttempt records an MFA verification attempt
func (m *AuthMetrics) RecordMFAAttempt(ctx context.Context, userID int32, success bool, duration time.Duration, method string) {
	attrs := []attribute.KeyValue{
		attribute.Int64("user_id", int64(userID)),
		attribute.String("result", getResultString(success)),
		attribute.String("method", method),
	}

	// Record attempt
	m.mfaAttempts.Add(ctx, 1, metric.WithAttributes(attrs...))

	// Record duration
	durationMs := float64(duration.Nanoseconds()) / 1e6
	m.mfaDuration.Record(ctx, durationMs, metric.WithAttributes(attrs...))

	// Record success/failure
	if success {
		m.mfaSuccesses.Add(ctx, 1, metric.WithAttributes(attrs...))
	} else {
		m.mfaFailures.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// RecordTokenGenerated records when a new token is generated
func (m *AuthMetrics) RecordTokenGenerated(ctx context.Context, userID int32, tokenType string) {
	attrs := []attribute.KeyValue{
		attribute.Int64("user_id", int64(userID)),
		attribute.String("token_type", tokenType),
	}

	m.tokenGenerated.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordTokenRefreshed records when a token is refreshed
func (m *AuthMetrics) RecordTokenRefreshed(ctx context.Context, userID int32, success bool) {
	attrs := []attribute.KeyValue{
		attribute.Int64("user_id", int64(userID)),
		attribute.String("result", getResultString(success)),
	}

	m.tokenRefreshed.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordTokenRevoked records when a token is revoked
func (m *AuthMetrics) RecordTokenRevoked(ctx context.Context, userID int32, reason string) {
	attrs := []attribute.KeyValue{
		attribute.Int64("user_id", int64(userID)),
		attribute.String("reason", reason),
	}

	m.tokenRevoked.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordTokenValidation records token validation attempts
func (m *AuthMetrics) RecordTokenValidation(ctx context.Context, success bool, reason string) {
	attrs := []attribute.KeyValue{
		attribute.String("result", getResultString(success)),
	}

	if !success && reason != "" {
		attrs = append(attrs, attribute.String("failure_reason", reason))
	}

	if success {
		m.tokenValidated.Add(ctx, 1, metric.WithAttributes(attrs...))
	} else {
		if reason == "expired" {
			m.tokenExpired.Add(ctx, 1, metric.WithAttributes(attrs...))
		}
		// Still count as validation attempt
		m.tokenValidated.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// RecordSessionStart records when a user session starts
func (m *AuthMetrics) RecordSessionStart(ctx context.Context, userID int32) {
	attrs := []attribute.KeyValue{
		attribute.Int64("user_id", int64(userID)),
	}

	m.activeSessions.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordSessionEnd records when a user session ends
func (m *AuthMetrics) RecordSessionEnd(ctx context.Context, userID int32, duration time.Duration, reason string) {
	attrs := []attribute.KeyValue{
		attribute.Int64("user_id", int64(userID)),
		attribute.String("end_reason", reason),
	}

	// Decrement active sessions
	m.activeSessions.Add(ctx, -1, metric.WithAttributes(
		attribute.Int64("user_id", int64(userID)),
	))

	// Record session duration
	durationSeconds := duration.Seconds()
	m.sessionDuration.Record(ctx, durationSeconds, metric.WithAttributes(attrs...))
}

// RecordPasswordResetRequest records a password reset request
func (m *AuthMetrics) RecordPasswordResetRequest(ctx context.Context, email string) {
	attrs := []attribute.KeyValue{
		attribute.String("email", email),
	}

	m.passwordResetRequests.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordPasswordResetResult records the result of a password reset attempt
func (m *AuthMetrics) RecordPasswordResetResult(ctx context.Context, success bool, reason string) {
	attrs := []attribute.KeyValue{
		attribute.String("result", getResultString(success)),
	}

	if !success && reason != "" {
		attrs = append(attrs, attribute.String("failure_reason", reason))
	}

	if success {
		m.passwordResetSuccess.Add(ctx, 1, metric.WithAttributes(attrs...))
	} else {
		m.passwordResetFailures.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// getResultString converts a boolean result to a string
func getResultString(success bool) string {
	if success {
		return "success"
	}
	return "failure"
}
