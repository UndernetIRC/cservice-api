// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

// Package telemetry provides OpenTelemetry initialization and management
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Provider manages OpenTelemetry providers and their lifecycle
type Provider struct {
	traceProvider  *sdktrace.TracerProvider
	metricProvider *sdkmetric.MeterProvider
	resource       *resource.Resource
	config         *Config
}

// Config holds the telemetry configuration
type Config struct {
	Enabled            bool
	ServiceName        string
	ServiceVersion     string
	OTLPEndpoint       string
	OTLPHeaders        map[string]string
	OTLPInsecure       bool
	PrometheusEnabled  bool
	PrometheusEndpoint string
	JaegerEnabled      bool
	JaegerEndpoint     string
	TracingEnabled     bool
	TracingSampleRate  float64
	MetricsEnabled     bool
	MetricsInterval    int
	ResourceAttributes map[string]string
}

// Exporter represents an OpenTelemetry exporter
type Exporter interface {
	Shutdown(context.Context) error
}

// NewProvider creates a new telemetry provider with the given configuration
func NewProvider(ctx context.Context, config *Config) (*Provider, error) {
	if config == nil {
		return nil, errors.New("telemetry config cannot be nil")
	}

	if !config.Enabled {
		return &Provider{
			config: config,
		}, nil
	}

	provider := &Provider{
		config: config,
	}

	// Create resource
	res, err := provider.createResource(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}
	provider.resource = res

	// Initialize trace provider if tracing is enabled
	if config.TracingEnabled {
		tp, err := provider.createTraceProvider(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create trace provider: %w", err)
		}
		provider.traceProvider = tp
		otel.SetTracerProvider(tp)
	}

	// Initialize metric provider if metrics are enabled
	if config.MetricsEnabled {
		mp, err := provider.createMetricProvider(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create metric provider: %w", err)
		}
		provider.metricProvider = mp
		otel.SetMeterProvider(mp)
	}

	return provider, nil
}

// Shutdown gracefully shuts down all telemetry providers
func (p *Provider) Shutdown(ctx context.Context) error {
	if !p.config.Enabled {
		return nil
	}

	var errors []error

	// Shutdown trace provider
	if p.traceProvider != nil {
		if err := p.traceProvider.Shutdown(ctx); err != nil {
			errors = append(errors, fmt.Errorf("failed to shutdown trace provider: %w", err))
		}
	}

	// Shutdown metric provider
	if p.metricProvider != nil {
		if err := p.metricProvider.Shutdown(ctx); err != nil {
			errors = append(errors, fmt.Errorf("failed to shutdown metric provider: %w", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("shutdown errors: %v", errors)
	}

	return nil
}

// GetTracer returns a tracer for the given name
func (p *Provider) GetTracer(name string, opts ...trace.TracerOption) trace.Tracer {
	if p.traceProvider == nil {
		return otel.GetTracerProvider().Tracer(name, opts...)
	}
	return p.traceProvider.Tracer(name, opts...)
}

// GetMeter returns a meter for the given name
func (p *Provider) GetMeter(name string, opts ...metric.MeterOption) metric.Meter {
	return otel.GetMeterProvider().Meter(name, opts...)
}

// IsEnabled returns whether telemetry is enabled
func (p *Provider) IsEnabled() bool {
	return p.config != nil && p.config.Enabled
}

// GetResource returns the telemetry resource
func (p *Provider) GetResource() *resource.Resource {
	return p.resource
}

// WithShutdownTimeout creates a context with a timeout for shutdown operations
func WithShutdownTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

// createTraceProvider creates and configures the trace provider
func (p *Provider) createTraceProvider(ctx context.Context) (*sdktrace.TracerProvider, error) {
	// Create exporter factory
	factory := NewExporterFactory(p.config)

	// Create trace exporters
	exporters, err := factory.CreateTraceExporters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create trace exporters: %w", err)
	}

	// Create span processors for each exporter
	var spanProcessors []sdktrace.SpanProcessor
	for _, exporter := range exporters {
		// Use batch processor for better performance
		processor := sdktrace.NewBatchSpanProcessor(
			exporter,
			sdktrace.WithBatchTimeout(5*time.Second),
			sdktrace.WithMaxExportBatchSize(512),
			sdktrace.WithMaxQueueSize(2048),
		)
		spanProcessors = append(spanProcessors, processor)
	}

	// Create sampler based on configuration
	sampler := sdktrace.TraceIDRatioBased(p.config.TracingSampleRate)

	// Create trace provider options
	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(p.resource),
		sdktrace.WithSampler(sampler),
	}

	// Add span processors
	for _, processor := range spanProcessors {
		opts = append(opts, sdktrace.WithSpanProcessor(processor))
	}

	// Create and return trace provider
	tp := sdktrace.NewTracerProvider(opts...)
	return tp, nil
}

// createMetricProvider creates and configures the metric provider
func (p *Provider) createMetricProvider(ctx context.Context) (*sdkmetric.MeterProvider, error) {
	// Create exporter factory
	factory := NewExporterFactory(p.config)

	// Create metric readers
	readers, err := factory.CreateMetricExporters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create metric readers: %w", err)
	}

	// Create metric provider options
	opts := []sdkmetric.Option{
		sdkmetric.WithResource(p.resource),
	}

	// Add readers
	for _, reader := range readers {
		opts = append(opts, sdkmetric.WithReader(reader))
	}

	// Configure views for common metrics
	views := p.createDefaultViews()
	for _, view := range views {
		opts = append(opts, sdkmetric.WithView(view))
	}

	// Create and return metric provider
	mp := sdkmetric.NewMeterProvider(opts...)
	return mp, nil
}

// createDefaultViews creates default metric views for common instruments
func (p *Provider) createDefaultViews() []sdkmetric.View {
	return []sdkmetric.View{
		// HTTP request duration histogram with custom buckets
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "http_request_duration_ms"},
			sdkmetric.Stream{
				Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
					Boundaries: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000},
				},
			},
		),
		// Database query duration histogram
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "db_query_duration_ms"},
			sdkmetric.Stream{
				Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
					Boundaries: []float64{1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000},
				},
			},
		),
		// Memory usage gauge
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "process_memory_bytes"},
			sdkmetric.Stream{
				Aggregation: sdkmetric.AggregationLastValue{},
			},
		),
	}
}
