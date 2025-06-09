// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package metrics

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// SystemHealthMetrics provides comprehensive metrics for system health monitoring
type SystemHealthMetrics struct {
	// Mail queue metrics
	mailQueueDepth      metric.Int64ObservableGauge
	mailProcessDuration metric.Float64Histogram
	mailProcessCounter  metric.Int64Counter
	mailProcessErrors   metric.Int64Counter

	// Cron job metrics
	cronJobDuration metric.Float64Histogram
	cronJobCounter  metric.Int64Counter
	cronJobErrors   metric.Int64Counter

	// System health metrics
	systemStatus      metric.Int64ObservableGauge
	serviceUptime     metric.Float64ObservableGauge
	backgroundWorkers metric.Int64ObservableGauge

	// Configuration
	serviceName string
	startTime   time.Time

	// Callback functions for dynamic metrics
	getMailQueueDepth func() int64
	getWorkerCount    func() int64
	getSystemStatus   func() int64 // 1 = healthy, 0 = unhealthy
}

// SystemHealthMetricsConfig holds configuration for system health metrics
type SystemHealthMetricsConfig struct {
	Meter       metric.Meter
	ServiceName string

	// Callback functions for dynamic metrics
	GetMailQueueDepth func() int64 // Function to get current mail queue depth
	GetWorkerCount    func() int64 // Function to get current worker count
	GetSystemStatus   func() int64 // Function to get system health status (1=healthy, 0=unhealthy)
}

// NewSystemHealthMetrics creates a new system health metrics collector
func NewSystemHealthMetrics(config SystemHealthMetricsConfig) (*SystemHealthMetrics, error) {
	if config.Meter == nil {
		return nil, fmt.Errorf("meter is required")
	}

	if config.ServiceName == "" {
		config.ServiceName = "cservice-api"
	}

	metrics := &SystemHealthMetrics{
		serviceName:       config.ServiceName,
		startTime:         time.Now(),
		getMailQueueDepth: config.GetMailQueueDepth,
		getWorkerCount:    config.GetWorkerCount,
		getSystemStatus:   config.GetSystemStatus,
	}

	var err error

	// Mail queue depth gauge
	metrics.mailQueueDepth, err = config.Meter.Int64ObservableGauge(
		"system_mail_queue_depth",
		metric.WithDescription("Current number of emails in the mail queue"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create mail queue depth gauge: %w", err)
	}

	// Mail processing duration histogram
	metrics.mailProcessDuration, err = config.Meter.Float64Histogram(
		"system_mail_process_duration_ms",
		metric.WithDescription("Duration of mail processing operations in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create mail process duration histogram: %w", err)
	}

	// Mail processing counter
	metrics.mailProcessCounter, err = config.Meter.Int64Counter(
		"system_mail_process_total",
		metric.WithDescription("Total number of mail processing operations"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create mail process counter: %w", err)
	}

	// Mail processing errors counter
	metrics.mailProcessErrors, err = config.Meter.Int64Counter(
		"system_mail_process_errors_total",
		metric.WithDescription("Total number of mail processing errors"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create mail process errors counter: %w", err)
	}

	// Cron job duration histogram
	metrics.cronJobDuration, err = config.Meter.Float64Histogram(
		"system_cron_job_duration_ms",
		metric.WithDescription("Duration of cron job execution in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create cron job duration histogram: %w", err)
	}

	// Cron job counter
	metrics.cronJobCounter, err = config.Meter.Int64Counter(
		"system_cron_job_total",
		metric.WithDescription("Total number of cron job executions"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create cron job counter: %w", err)
	}

	// Cron job errors counter
	metrics.cronJobErrors, err = config.Meter.Int64Counter(
		"system_cron_job_errors_total",
		metric.WithDescription("Total number of cron job errors"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create cron job errors counter: %w", err)
	}

	// System status gauge
	metrics.systemStatus, err = config.Meter.Int64ObservableGauge(
		"system_health_status",
		metric.WithDescription("Overall system health status (1=healthy, 0=unhealthy)"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create system status gauge: %w", err)
	}

	// Service uptime gauge
	metrics.serviceUptime, err = config.Meter.Float64ObservableGauge(
		"system_service_uptime_seconds",
		metric.WithDescription("Service uptime in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create service uptime gauge: %w", err)
	}

	// Background workers gauge
	metrics.backgroundWorkers, err = config.Meter.Int64ObservableGauge(
		"system_background_workers",
		metric.WithDescription("Current number of active background workers"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create background workers gauge: %w", err)
	}

	// Register callback for observable gauges
	_, err = config.Meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		serviceName := metrics.serviceName

		// Mail queue depth
		if metrics.getMailQueueDepth != nil {
			queueDepth := metrics.getMailQueueDepth()
			o.ObserveInt64(metrics.mailQueueDepth, queueDepth, metric.WithAttributes(
				attribute.String("service", serviceName),
			))
		}

		// System status
		if metrics.getSystemStatus != nil {
			status := metrics.getSystemStatus()
			o.ObserveInt64(metrics.systemStatus, status, metric.WithAttributes(
				attribute.String("service", serviceName),
			))
		}

		// Service uptime
		uptime := time.Since(metrics.startTime).Seconds()
		o.ObserveFloat64(metrics.serviceUptime, uptime, metric.WithAttributes(
			attribute.String("service", serviceName),
		))

		// Background workers
		if metrics.getWorkerCount != nil {
			workerCount := metrics.getWorkerCount()
			o.ObserveInt64(metrics.backgroundWorkers, workerCount, metric.WithAttributes(
				attribute.String("service", serviceName),
				attribute.String("type", "mail_workers"),
			))
		}

		return nil
	}, metrics.mailQueueDepth, metrics.systemStatus, metrics.serviceUptime, metrics.backgroundWorkers)

	if err != nil {
		return nil, fmt.Errorf("failed to register system health metrics callback: %w", err)
	}

	return metrics, nil
}

// RecordMailProcessing records metrics for mail processing operations
func (m *SystemHealthMetrics) RecordMailProcessing(ctx context.Context, _ string, duration time.Duration, err error) {
	if m == nil {
		return
	}

	durationMs := float64(duration.Nanoseconds()) / 1e6
	success := err == nil

	attrs := []attribute.KeyValue{
		attribute.String("service", m.serviceName),
		attribute.Bool("success", success),
	}

	// Record duration
	m.mailProcessDuration.Record(ctx, durationMs, metric.WithAttributes(attrs...))

	// Record counter
	m.mailProcessCounter.Add(ctx, 1, metric.WithAttributes(attrs...))

	// Record error if applicable
	if err != nil {
		errorAttrs := []attribute.KeyValue{
			attribute.String("service", m.serviceName),
			attribute.String("error_type", getErrorType(err)),
		}
		m.mailProcessErrors.Add(ctx, 1, metric.WithAttributes(errorAttrs...))
	}
}

// RecordCronJobExecution records metrics for cron job execution
func (m *SystemHealthMetrics) RecordCronJobExecution(ctx context.Context, jobName string, duration time.Duration, err error) {
	if m == nil {
		return
	}

	durationMs := float64(duration.Nanoseconds()) / 1e6
	success := err == nil

	attrs := []attribute.KeyValue{
		attribute.String("service", m.serviceName),
		attribute.String("job_name", jobName),
		attribute.Bool("success", success),
	}

	// Record duration
	m.cronJobDuration.Record(ctx, durationMs, metric.WithAttributes(attrs...))

	// Record counter
	m.cronJobCounter.Add(ctx, 1, metric.WithAttributes(attrs...))

	// Record error if applicable
	if err != nil {
		errorAttrs := []attribute.KeyValue{
			attribute.String("service", m.serviceName),
			attribute.String("job_name", jobName),
			attribute.String("error_type", getErrorType(err)),
		}
		m.cronJobErrors.Add(ctx, 1, metric.WithAttributes(errorAttrs...))
	}
}

// MeasureMailProcessing wraps a mail processing function with metrics collection
func (m *SystemHealthMetrics) MeasureMailProcessing(ctx context.Context, recipient string, f func() error) error {
	start := time.Now()
	err := f()
	duration := time.Since(start)

	m.RecordMailProcessing(ctx, recipient, duration, err)
	return err
}

// MeasureCronJobExecution wraps a cron job function with metrics collection
func (m *SystemHealthMetrics) MeasureCronJobExecution(ctx context.Context, jobName string, f func() error) error {
	start := time.Now()
	err := f()
	duration := time.Since(start)

	m.RecordCronJobExecution(ctx, jobName, duration, err)
	return err
}

// Helper function to categorize error types
func getErrorType(err error) string {
	if err == nil {
		return "none"
	}

	errStr := err.Error()
	switch {
	case contains(errStr, "timeout"):
		return "timeout"
	case contains(errStr, "connection"):
		return "connection"
	case contains(errStr, "smtp"):
		return "smtp"
	case contains(errStr, "template"):
		return "template"
	case contains(errStr, "database"):
		return "database"
	case contains(errStr, "context"):
		return "context"
	default:
		return "unknown"
	}
}

// Helper function to check if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) &&
				containsSubstring(s, substr)))
}

// Helper function for substring checking
func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if toLower(s[i+j]) != toLower(substr[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// Helper function to convert character to lowercase
func toLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
