// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// MetricsHandler manages Prometheus metrics endpoint
type MetricsHandler struct {
	gatherer prometheus.Gatherer
	provider *Provider
	config   *Config
	meter    metric.Meter
}

// NewMetricsHandler creates a new metrics handler
func NewMetricsHandler(provider *Provider, config *Config) (*MetricsHandler, error) {
	if !config.Enabled || !config.PrometheusEnabled {
		return nil, fmt.Errorf("prometheus metrics not enabled")
	}

	// Use the existing meter provider from the telemetry provider
	if provider.metricProvider == nil {
		return nil, fmt.Errorf("metric provider not initialized in telemetry provider")
	}

	// Use the default Prometheus registry instead of creating a custom one
	// This ensures we use the same registry as the telemetry provider's Prometheus exporter
	// Note: We don't register Go runtime and process metrics here because they're
	// already registered by the telemetry provider's Prometheus exporter

	// Get a meter from the provider for creating custom metrics
	meter := provider.GetMeter("cservice-api-metrics")

	handler := &MetricsHandler{
		gatherer: prometheus.DefaultGatherer,
		provider: provider,
		config:   config,
		meter:    meter,
	}

	return handler, nil
}

// Handler returns the HTTP handler for Prometheus metrics
func (h *MetricsHandler) Handler() http.Handler {
	return promhttp.HandlerFor(h.gatherer, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
		Timeout:           5 * time.Second,
	})
}

// EchoHandler returns an Echo handler for Prometheus metrics
func (h *MetricsHandler) EchoHandler() echo.HandlerFunc {
	handler := h.Handler()
	return echo.WrapHandler(handler)
}

// RegisterMetricsEndpoint registers the metrics endpoint with Echo router
func RegisterMetricsEndpoint(e *echo.Echo, provider *Provider, config *Config) error {
	if !config.Enabled || !config.PrometheusEnabled {
		return nil // Silently skip if not enabled
	}

	// Create metrics handler
	metricsHandler, err := NewMetricsHandler(provider, config)
	if err != nil {
		return fmt.Errorf("failed to create metrics handler: %w", err)
	}

	// Register the endpoint
	e.GET(config.PrometheusEndpoint, metricsHandler.EchoHandler())

	return nil
}

// HealthMetrics provides health-related metrics
type HealthMetrics struct {
	meter         metric.Meter
	healthCounter metric.Int64Counter
	uptimeGauge   metric.Float64ObservableGauge
	versionInfo   metric.Int64ObservableGauge
	startTime     time.Time
}

// NewHealthMetrics creates health-related metrics
func NewHealthMetrics(meter metric.Meter, serviceName, serviceVersion string) (*HealthMetrics, error) {
	healthCounter, err := meter.Int64Counter(
		"health_checks_total",
		metric.WithDescription("Total number of health checks"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create health counter: %w", err)
	}

	uptimeGauge, err := meter.Float64ObservableGauge(
		"uptime_seconds",
		metric.WithDescription("Service uptime in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create uptime gauge: %w", err)
	}

	versionInfo, err := meter.Int64ObservableGauge(
		"version_info",
		metric.WithDescription("Service version information"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create version info gauge: %w", err)
	}

	hm := &HealthMetrics{
		meter:         meter,
		healthCounter: healthCounter,
		uptimeGauge:   uptimeGauge,
		versionInfo:   versionInfo,
		startTime:     time.Now(),
	}

	// Register callbacks
	_, err = meter.RegisterCallback(
		func(_ context.Context, o metric.Observer) error {
			uptime := time.Since(hm.startTime).Seconds()
			o.ObserveFloat64(uptimeGauge, uptime)
			o.ObserveInt64(versionInfo, 1,
				metric.WithAttributes(
					attribute.String("service", serviceName),
					attribute.String("version", serviceVersion),
				),
			)
			return nil
		},
		uptimeGauge,
		versionInfo,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register health callbacks: %w", err)
	}

	return hm, nil
}

// RecordHealthCheck records a health check metric
func (hm *HealthMetrics) RecordHealthCheck(ctx context.Context, status string) {
	hm.healthCounter.Add(ctx, 1,
		metric.WithAttributes(attribute.String("status", status)),
	)
}
