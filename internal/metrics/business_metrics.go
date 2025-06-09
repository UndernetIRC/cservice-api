// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

// Package metrics provides business-specific metrics collection
package metrics

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// BusinessMetrics holds all business-related metric instruments
type BusinessMetrics struct {
	// User registration funnel metrics
	registrationAttempts   metric.Int64Counter
	registrationSuccesses  metric.Int64Counter
	registrationFailures   metric.Int64Counter
	registrationDuration   metric.Float64Histogram
	activationAttempts     metric.Int64Counter
	activationSuccesses    metric.Int64Counter
	activationFailures     metric.Int64Counter
	activationDuration     metric.Float64Histogram
	pendingRegistrations   metric.Int64UpDownCounter
	registrationConversion metric.Float64Histogram

	// Channel operation metrics
	channelSearches        metric.Int64Counter
	channelSearchDuration  metric.Float64Histogram
	channelSearchResults   metric.Int64Histogram
	channelSettingsViews   metric.Int64Counter
	channelSettingsUpdates metric.Int64Counter
	channelMemberAdded     metric.Int64Counter
	channelMemberRemoved   metric.Int64Counter
	channelOperationErrors metric.Int64Counter

	// User engagement metrics
	activeUsers      metric.Int64UpDownCounter
	userSessions     metric.Int64Counter
	sessionDuration  metric.Float64Histogram
	apiRequestsTotal metric.Int64Counter
	featureUsage     metric.Int64Counter

	// Business health metrics
	errorRate        metric.Float64Histogram
	responseTime     metric.Float64Histogram
	throughput       metric.Int64Counter
	conversionFunnel metric.Float64Histogram
}

// BusinessMetricsConfig holds configuration for business metrics
type BusinessMetricsConfig struct {
	Meter       metric.Meter
	ServiceName string
}

// NewBusinessMetrics creates a new business metrics collector
func NewBusinessMetrics(config BusinessMetricsConfig) (*BusinessMetrics, error) {
	if config.Meter == nil {
		return nil, fmt.Errorf("meter cannot be nil")
	}

	if config.ServiceName == "" {
		config.ServiceName = "cservice-api"
	}

	metrics := &BusinessMetrics{}

	// Create user registration funnel metrics
	var err error
	metrics.registrationAttempts, err = config.Meter.Int64Counter(
		"business_registration_attempts_total",
		metric.WithDescription("Total number of user registration attempts"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create registration attempts counter: %w", err)
	}

	metrics.registrationSuccesses, err = config.Meter.Int64Counter(
		"business_registration_successes_total",
		metric.WithDescription("Total number of successful user registrations"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create registration successes counter: %w", err)
	}

	metrics.registrationFailures, err = config.Meter.Int64Counter(
		"business_registration_failures_total",
		metric.WithDescription("Total number of failed user registrations"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create registration failures counter: %w", err)
	}

	metrics.registrationDuration, err = config.Meter.Float64Histogram(
		"business_registration_duration_ms",
		metric.WithDescription("User registration request duration in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create registration duration histogram: %w", err)
	}

	metrics.activationAttempts, err = config.Meter.Int64Counter(
		"business_activation_attempts_total",
		metric.WithDescription("Total number of account activation attempts"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create activation attempts counter: %w", err)
	}

	metrics.activationSuccesses, err = config.Meter.Int64Counter(
		"business_activation_successes_total",
		metric.WithDescription("Total number of successful account activations"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create activation successes counter: %w", err)
	}

	metrics.activationFailures, err = config.Meter.Int64Counter(
		"business_activation_failures_total",
		metric.WithDescription("Total number of failed account activations"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create activation failures counter: %w", err)
	}

	metrics.activationDuration, err = config.Meter.Float64Histogram(
		"business_activation_duration_ms",
		metric.WithDescription("Account activation request duration in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create activation duration histogram: %w", err)
	}

	metrics.pendingRegistrations, err = config.Meter.Int64UpDownCounter(
		"business_pending_registrations",
		metric.WithDescription("Number of pending user registrations awaiting activation"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create pending registrations gauge: %w", err)
	}

	metrics.registrationConversion, err = config.Meter.Float64Histogram(
		"business_registration_conversion_rate",
		metric.WithDescription("Registration to activation conversion rate"),
		metric.WithUnit("percent"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create registration conversion histogram: %w", err)
	}

	// Create channel operation metrics
	metrics.channelSearches, err = config.Meter.Int64Counter(
		"business_channel_searches_total",
		metric.WithDescription("Total number of channel searches performed"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create channel searches counter: %w", err)
	}

	metrics.channelSearchDuration, err = config.Meter.Float64Histogram(
		"business_channel_search_duration_ms",
		metric.WithDescription("Channel search request duration in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create channel search duration histogram: %w", err)
	}

	metrics.channelSearchResults, err = config.Meter.Int64Histogram(
		"business_channel_search_results",
		metric.WithDescription("Number of results returned by channel searches"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create channel search results histogram: %w", err)
	}

	metrics.channelSettingsViews, err = config.Meter.Int64Counter(
		"business_channel_settings_views_total",
		metric.WithDescription("Total number of channel settings views"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create channel settings views counter: %w", err)
	}

	metrics.channelSettingsUpdates, err = config.Meter.Int64Counter(
		"business_channel_settings_updates_total",
		metric.WithDescription("Total number of channel settings updates"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create channel settings updates counter: %w", err)
	}

	metrics.channelMemberAdded, err = config.Meter.Int64Counter(
		"business_channel_members_added_total",
		metric.WithDescription("Total number of channel members added"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create channel members added counter: %w", err)
	}

	metrics.channelMemberRemoved, err = config.Meter.Int64Counter(
		"business_channel_members_removed_total",
		metric.WithDescription("Total number of channel members removed"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create channel members removed counter: %w", err)
	}

	metrics.channelOperationErrors, err = config.Meter.Int64Counter(
		"business_channel_operation_errors_total",
		metric.WithDescription("Total number of channel operation errors"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create channel operation errors counter: %w", err)
	}

	// Create user engagement metrics
	metrics.activeUsers, err = config.Meter.Int64UpDownCounter(
		"business_active_users",
		metric.WithDescription("Number of currently active users"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create active users gauge: %w", err)
	}

	metrics.userSessions, err = config.Meter.Int64Counter(
		"business_user_sessions_total",
		metric.WithDescription("Total number of user sessions started"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user sessions counter: %w", err)
	}

	metrics.sessionDuration, err = config.Meter.Float64Histogram(
		"business_session_duration_seconds",
		metric.WithDescription("User session duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create session duration histogram: %w", err)
	}

	metrics.apiRequestsTotal, err = config.Meter.Int64Counter(
		"business_api_requests_total",
		metric.WithDescription("Total number of API requests by endpoint"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create API requests counter: %w", err)
	}

	metrics.featureUsage, err = config.Meter.Int64Counter(
		"business_feature_usage_total",
		metric.WithDescription("Total usage count of specific features"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create feature usage counter: %w", err)
	}

	// Create business health metrics
	metrics.errorRate, err = config.Meter.Float64Histogram(
		"business_error_rate",
		metric.WithDescription("Error rate percentage for business operations"),
		metric.WithUnit("percent"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create error rate histogram: %w", err)
	}

	metrics.responseTime, err = config.Meter.Float64Histogram(
		"business_response_time_ms",
		metric.WithDescription("Business operation response time in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create response time histogram: %w", err)
	}

	metrics.throughput, err = config.Meter.Int64Counter(
		"business_throughput_total",
		metric.WithDescription("Total throughput for business operations"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create throughput counter: %w", err)
	}

	metrics.conversionFunnel, err = config.Meter.Float64Histogram(
		"business_conversion_funnel",
		metric.WithDescription("Conversion rates at different funnel stages"),
		metric.WithUnit("percent"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create conversion funnel histogram: %w", err)
	}

	return metrics, nil
}

// User Registration Funnel Methods

// RecordRegistrationAttempt records a user registration attempt
func (m *BusinessMetrics) RecordRegistrationAttempt(ctx context.Context, username, _ string, success bool, duration time.Duration, reason string) {
	serviceName := "cservice-api"
	result := getResultString(success)

	// Record the attempt
	m.registrationAttempts.Add(ctx, 1, metric.WithAttributes(
		attribute.String("service", serviceName),
		attribute.String("result", result),
		attribute.String("username", username),
		attribute.String("reason", reason),
	))

	// Record duration
	m.registrationDuration.Record(ctx, float64(duration.Milliseconds()), metric.WithAttributes(
		attribute.String("service", serviceName),
		attribute.String("result", result),
	))

	// Record success/failure
	if success {
		m.registrationSuccesses.Add(ctx, 1, metric.WithAttributes(
			attribute.String("service", serviceName),
			attribute.String("username", username),
		))
		// Increment pending registrations
		m.pendingRegistrations.Add(ctx, 1, metric.WithAttributes(
			attribute.String("service", serviceName),
		))
	} else {
		m.registrationFailures.Add(ctx, 1, metric.WithAttributes(
			attribute.String("service", serviceName),
			attribute.String("username", username),
			attribute.String("failure_reason", reason),
		))
	}
}

// RecordActivationAttempt records an account activation attempt
func (m *BusinessMetrics) RecordActivationAttempt(ctx context.Context, username string, success bool, duration time.Duration, reason string) {
	serviceName := "cservice-api"
	result := getResultString(success)

	// Record the attempt
	m.activationAttempts.Add(ctx, 1, metric.WithAttributes(
		attribute.String("service", serviceName),
		attribute.String("result", result),
		attribute.String("username", username),
		attribute.String("reason", reason),
	))

	// Record duration
	m.activationDuration.Record(ctx, float64(duration.Milliseconds()), metric.WithAttributes(
		attribute.String("service", serviceName),
		attribute.String("result", result),
	))

	// Record success/failure
	if success {
		m.activationSuccesses.Add(ctx, 1, metric.WithAttributes(
			attribute.String("service", serviceName),
			attribute.String("username", username),
		))
		// Decrement pending registrations
		m.pendingRegistrations.Add(ctx, -1, metric.WithAttributes(
			attribute.String("service", serviceName),
		))
	} else {
		m.activationFailures.Add(ctx, 1, metric.WithAttributes(
			attribute.String("service", serviceName),
			attribute.String("username", username),
			attribute.String("failure_reason", reason),
		))
	}
}

// RecordRegistrationConversion records registration to activation conversion rate
func (m *BusinessMetrics) RecordRegistrationConversion(ctx context.Context, conversionRate float64) {
	serviceName := "cservice-api"
	m.registrationConversion.Record(ctx, conversionRate, metric.WithAttributes(
		attribute.String("service", serviceName),
	))
}

// Channel Operation Methods

// RecordChannelSearch records a channel search operation
func (m *BusinessMetrics) RecordChannelSearch(ctx context.Context, userID int32, query string, resultCount int, duration time.Duration, success bool) {
	serviceName := "cservice-api"
	result := getResultString(success)

	m.channelSearches.Add(ctx, 1, metric.WithAttributes(
		attribute.String("service", serviceName),
		attribute.String("result", result),
		attribute.Int("user_id", int(userID)),
	))

	m.channelSearchDuration.Record(ctx, float64(duration.Milliseconds()), metric.WithAttributes(
		attribute.String("service", serviceName),
		attribute.String("result", result),
	))

	if success {
		m.channelSearchResults.Record(ctx, int64(resultCount), metric.WithAttributes(
			attribute.String("service", serviceName),
			attribute.String("query_type", getQueryType(query)),
		))
	}
}

// RecordChannelSettingsView records a channel settings view
func (m *BusinessMetrics) RecordChannelSettingsView(ctx context.Context, userID int32, channelID int32, accessLevel int) {
	serviceName := "cservice-api"
	m.channelSettingsViews.Add(ctx, 1, metric.WithAttributes(
		attribute.String("service", serviceName),
		attribute.Int("user_id", int(userID)),
		attribute.Int("channel_id", int(channelID)),
		attribute.Int("access_level", accessLevel),
	))
}

// RecordChannelSettingsUpdate records a channel settings update
func (m *BusinessMetrics) RecordChannelSettingsUpdate(ctx context.Context, userID int32, channelID int32, success bool, fieldsUpdated []string) {
	serviceName := "cservice-api"
	result := getResultString(success)

	m.channelSettingsUpdates.Add(ctx, 1, metric.WithAttributes(
		attribute.String("service", serviceName),
		attribute.String("result", result),
		attribute.Int("user_id", int(userID)),
		attribute.Int("channel_id", int(channelID)),
		attribute.StringSlice("fields_updated", fieldsUpdated),
	))
}

// RecordChannelMemberOperation records channel member add/remove operations
func (m *BusinessMetrics) RecordChannelMemberOperation(ctx context.Context, userID int32, channelID int32, targetUserID int32, operation string, success bool, accessLevel int) {
	serviceName := "cservice-api"
	result := getResultString(success)

	switch operation {
	case "add":
		m.channelMemberAdded.Add(ctx, 1, metric.WithAttributes(
			attribute.String("service", serviceName),
			attribute.String("result", result),
			attribute.Int("user_id", int(userID)),
			attribute.Int("channel_id", int(channelID)),
			attribute.Int("target_user_id", int(targetUserID)),
			attribute.Int("access_level", accessLevel),
		))
	case "remove":
		m.channelMemberRemoved.Add(ctx, 1, metric.WithAttributes(
			attribute.String("service", serviceName),
			attribute.String("result", result),
			attribute.Int("user_id", int(userID)),
			attribute.Int("channel_id", int(channelID)),
			attribute.Int("target_user_id", int(targetUserID)),
		))
	}
}

// RecordChannelOperationError records channel operation errors
func (m *BusinessMetrics) RecordChannelOperationError(ctx context.Context, operation string, errorType string, channelID int32) {
	serviceName := "cservice-api"
	m.channelOperationErrors.Add(ctx, 1, metric.WithAttributes(
		attribute.String("service", serviceName),
		attribute.String("operation", operation),
		attribute.String("error_type", errorType),
		attribute.Int("channel_id", int(channelID)),
	))
}

// User Engagement Methods

// RecordUserSession records user session metrics
func (m *BusinessMetrics) RecordUserSession(ctx context.Context, userID int32, sessionType string, duration time.Duration) {
	serviceName := "cservice-api"

	m.userSessions.Add(ctx, 1, metric.WithAttributes(
		attribute.String("service", serviceName),
		attribute.Int("user_id", int(userID)),
		attribute.String("session_type", sessionType),
	))

	if duration > 0 {
		m.sessionDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(
			attribute.String("service", serviceName),
			attribute.String("session_type", sessionType),
		))
	}
}

// RecordActiveUser records active user metrics
func (m *BusinessMetrics) RecordActiveUser(ctx context.Context, _ int32, action string) {
	serviceName := "cservice-api"
	delta := int64(1)
	if action == "logout" || action == "disconnect" {
		delta = -1
	}

	m.activeUsers.Add(ctx, delta, metric.WithAttributes(
		attribute.String("service", serviceName),
		attribute.String("action", action),
	))
}

// RecordAPIRequest records API request metrics
func (m *BusinessMetrics) RecordAPIRequest(ctx context.Context, endpoint string, method string, userID int32, success bool) {
	serviceName := "cservice-api"
	result := getResultString(success)

	m.apiRequestsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("service", serviceName),
		attribute.String("endpoint", endpoint),
		attribute.String("method", method),
		attribute.String("result", result),
		attribute.Int("user_id", int(userID)),
	))
}

// RecordFeatureUsage records feature usage metrics
func (m *BusinessMetrics) RecordFeatureUsage(ctx context.Context, feature string, userID int32, contextInfo map[string]string) {
	serviceName := "cservice-api"
	attrs := []attribute.KeyValue{
		attribute.String("service", serviceName),
		attribute.String("feature", feature),
		attribute.Int("user_id", int(userID)),
	}

	// Add context information as attributes
	for key, value := range contextInfo {
		attrs = append(attrs, attribute.String(key, value))
	}

	m.featureUsage.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// Business Health Methods

// RecordBusinessMetric records general business health metrics
func (m *BusinessMetrics) RecordBusinessMetric(ctx context.Context, operation string, duration time.Duration, success bool, errorRate float64) {
	serviceName := "cservice-api"
	result := getResultString(success)

	m.responseTime.Record(ctx, float64(duration.Milliseconds()), metric.WithAttributes(
		attribute.String("service", serviceName),
		attribute.String("operation", operation),
		attribute.String("result", result),
	))

	m.throughput.Add(ctx, 1, metric.WithAttributes(
		attribute.String("service", serviceName),
		attribute.String("operation", operation),
	))

	if errorRate >= 0 {
		m.errorRate.Record(ctx, errorRate, metric.WithAttributes(
			attribute.String("service", serviceName),
			attribute.String("operation", operation),
		))
	}
}

// RecordConversionFunnel records conversion funnel metrics
func (m *BusinessMetrics) RecordConversionFunnel(ctx context.Context, stage string, conversionRate float64) {
	serviceName := "cservice-api"
	m.conversionFunnel.Record(ctx, conversionRate, metric.WithAttributes(
		attribute.String("service", serviceName),
		attribute.String("stage", stage),
	))
}

// Helper functions

// getQueryType determines the type of search query
func getQueryType(query string) string {
	if len(query) == 0 {
		return "empty"
	}
	if query[0] == '#' {
		return "channel_name"
	}
	if len(query) == 1 {
		return "single_char"
	}
	if len(query) <= 3 {
		return "short"
	}
	return "normal"
}
