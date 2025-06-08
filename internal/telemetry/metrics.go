// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	promexporter "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// MetricsHandler manages Prometheus metrics endpoint
type MetricsHandler struct {
	registry *prometheus.Registry
	provider *Provider
	config   *Config
	meter    metric.Meter
}

// NewMetricsHandler creates a new metrics handler
func NewMetricsHandler(provider *Provider, config *Config) (*MetricsHandler, error) {
	if !config.Enabled || !config.PrometheusEnabled {
		return nil, fmt.Errorf("prometheus metrics not enabled")
	}

	// Create custom Prometheus registry
	registry := prometheus.NewRegistry()

	// Create Prometheus exporter
	promExporter, err := promexporter.New(
		promexporter.WithRegisterer(registry),
		promexporter.WithoutUnits(),
		promexporter.WithoutScopeInfo(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create prometheus exporter: %w", err)
	}

	// Create meter provider with Prometheus reader
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(provider.GetResource()),
		sdkmetric.WithReader(promExporter),
	)

	// Get meter for application metrics
	meter := mp.Meter("cservice-api")

	handler := &MetricsHandler{
		registry: registry,
		provider: provider,
		config:   config,
		meter:    meter,
	}

	// Initialize system metrics collectors
	if err := handler.initializeSystemMetrics(); err != nil {
		return nil, fmt.Errorf("failed to initialize system metrics: %w", err)
	}

	return handler, nil
}

// initializeSystemMetrics sets up system-level metrics collectors
func (h *MetricsHandler) initializeSystemMetrics() error {
	// Add Go runtime metrics
	h.registry.MustRegister(collectors.NewGoCollector())

	// Add process metrics
	h.registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	// Create custom application metrics
	if err := h.createApplicationMetrics(); err != nil {
		return fmt.Errorf("failed to create application metrics: %w", err)
	}

	return nil
}

// createApplicationMetrics creates application-specific metrics
func (h *MetricsHandler) createApplicationMetrics() error {
	// Create a gauge for active connections
	_, err := h.meter.Int64UpDownCounter(
		"http_active_connections",
		metric.WithDescription("Number of active HTTP connections"),
	)
	if err != nil {
		return fmt.Errorf("failed to create active connections metric: %w", err)
	}

	// Create histogram for response times
	_, err = h.meter.Float64Histogram(
		"http_request_duration_ms",
		metric.WithDescription("HTTP request duration in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return fmt.Errorf("failed to create request duration metric: %w", err)
	}

	// Create counter for total requests
	_, err = h.meter.Int64Counter(
		"http_requests_total",
		metric.WithDescription("Total number of HTTP requests"),
	)
	if err != nil {
		return fmt.Errorf("failed to create requests counter: %w", err)
	}

	// Create gauge for memory usage
	memoryGauge, err := h.meter.Int64ObservableGauge(
		"process_memory_bytes",
		metric.WithDescription("Process memory usage in bytes"),
		metric.WithUnit("bytes"),
	)
	if err != nil {
		return fmt.Errorf("failed to create memory gauge: %w", err)
	}

	// Register callback for memory usage
	_, err = h.meter.RegisterCallback(
		func(_ context.Context, o metric.Observer) error {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			// #nosec G115 - Memory allocation size is safe to convert
			o.ObserveInt64(memoryGauge, int64(m.Alloc))
			return nil
		},
		memoryGauge,
	)
	if err != nil {
		return fmt.Errorf("failed to register memory callback: %w", err)
	}

	// Create gauge for goroutines
	goroutineGauge, err := h.meter.Int64ObservableGauge(
		"process_goroutines",
		metric.WithDescription("Number of goroutines"),
	)
	if err != nil {
		return fmt.Errorf("failed to create goroutine gauge: %w", err)
	}

	// Register callback for goroutines
	_, err = h.meter.RegisterCallback(
		func(_ context.Context, o metric.Observer) error {
			o.ObserveInt64(goroutineGauge, int64(runtime.NumGoroutine()))
			return nil
		},
		goroutineGauge,
	)
	if err != nil {
		return fmt.Errorf("failed to register goroutine callback: %w", err)
	}

	return nil
}

// Handler returns the HTTP handler for Prometheus metrics
func (h *MetricsHandler) Handler() http.Handler {
	return promhttp.HandlerFor(h.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
		Timeout:           5 * time.Second,
	})
}

// HandlerWithFilter returns the HTTP handler for Prometheus metrics with filtering
func (h *MetricsHandler) HandlerWithFilter(filter MetricsFilter) http.Handler {
	filteredGatherer := filter.FilterRegistry(h.registry)
	return promhttp.HandlerFor(filteredGatherer, promhttp.HandlerOpts{
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
