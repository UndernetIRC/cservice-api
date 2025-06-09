// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package telemetry

import (
	"context"
	"crypto/tls"
	"fmt"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// ExporterFactory creates exporters based on configuration
type ExporterFactory struct {
	config *Config
}

// NewExporterFactory creates a new exporter factory
func NewExporterFactory(config *Config) *ExporterFactory {
	return &ExporterFactory{config: config}
}

// CreateTraceExporters creates trace exporters based on configuration
func (f *ExporterFactory) CreateTraceExporters(ctx context.Context) ([]sdktrace.SpanExporter, error) {
	var exporters []sdktrace.SpanExporter

	// Create OTLP exporter if endpoint is configured
	if f.config.OTLPEndpoint != "" {
		exporter, err := f.createOTLPTraceExporter(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create OTLP trace exporter: %w", err)
		}
		exporters = append(exporters, exporter)
	}

	// Create Jaeger exporter if enabled (placeholder - requires additional dependency)
	if f.config.JaegerEnabled && f.config.JaegerEndpoint != "" {
		// Note: Jaeger exporter requires go.opentelemetry.io/otel/exporters/jaeger
		// For now, we'll log a warning and skip
		fmt.Printf("Warning: Jaeger exporter is configured but not implemented (requires additional dependency)\n")
	}

	if len(exporters) == 0 {
		return nil, fmt.Errorf("no trace exporters configured")
	}

	return exporters, nil
}

// CreateMetricExporters creates metric exporters based on configuration
func (f *ExporterFactory) CreateMetricExporters(ctx context.Context) ([]metric.Reader, error) {
	var readers []metric.Reader

	// Create Prometheus exporter if enabled
	if f.config.PrometheusEnabled {
		reader, err := f.createPrometheusReader()
		if err != nil {
			return nil, fmt.Errorf("failed to create Prometheus reader: %w", err)
		}
		readers = append(readers, reader)
	}

	// Create OTLP metric exporter if endpoint is configured
	if f.config.OTLPEndpoint != "" {
		reader, err := f.createOTLPMetricReader(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create OTLP metric reader: %w", err)
		}
		readers = append(readers, reader)
	}

	if len(readers) == 0 {
		return nil, fmt.Errorf("no metric readers configured")
	}

	return readers, nil
}

// createOTLPTraceExporter creates an OTLP trace exporter
func (f *ExporterFactory) createOTLPTraceExporter(ctx context.Context) (sdktrace.SpanExporter, error) {
	// For now, only support HTTP OTLP exporter (gRPC requires additional dependency)
	return f.createOTLPHTTPTraceExporter(ctx)
}

// createOTLPHTTPTraceExporter creates an OTLP HTTP trace exporter
func (f *ExporterFactory) createOTLPHTTPTraceExporter(ctx context.Context) (sdktrace.SpanExporter, error) {
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(f.config.OTLPEndpoint),
	}

	// Add headers if configured
	if len(f.config.OTLPHeaders) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(f.config.OTLPHeaders))
	}

	// Configure TLS
	if f.config.OTLPInsecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	} else {
		opts = append(opts, otlptracehttp.WithTLSClientConfig(&tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false,
		}))
	}

	return otlptracehttp.New(ctx, opts...)
}

// createPrometheusReader creates a Prometheus metric reader
func (f *ExporterFactory) createPrometheusReader() (metric.Reader, error) {
	return prometheus.New()
}

// createOTLPMetricReader creates an OTLP metric reader
func (f *ExporterFactory) createOTLPMetricReader(_ context.Context) (metric.Reader, error) {
	// For now, return a manual reader as a placeholder
	// This can be expanded to support OTLP metric export when the exporter is available
	return metric.NewManualReader(), nil
}

// ValidateExporterConfig validates the exporter configuration
func ValidateExporterConfig(config *Config) error {
	if !config.Enabled {
		return nil
	}

	// Check if at least one exporter is configured
	hasExporter := config.OTLPEndpoint != "" ||
		(config.JaegerEnabled && config.JaegerEndpoint != "") ||
		config.PrometheusEnabled

	if !hasExporter {
		return fmt.Errorf("telemetry is enabled but no exporters are configured")
	}

	// Validate OTLP configuration
	if config.OTLPEndpoint != "" {
		if config.OTLPEndpoint == "localhost" || config.OTLPEndpoint == "127.0.0.1" {
			return fmt.Errorf("OTLP endpoint must include protocol and port")
		}
	}

	// Validate Jaeger configuration
	if config.JaegerEnabled && config.JaegerEndpoint == "" {
		return fmt.Errorf("jaeger is enabled but endpoint is not configured")
	}

	// Validate sampling rate
	if config.TracingSampleRate < 0.0 || config.TracingSampleRate > 1.0 {
		return fmt.Errorf("tracing sample rate must be between 0.0 and 1.0, got %f", config.TracingSampleRate)
	}

	// Validate metrics interval
	if config.MetricsInterval <= 0 {
		return fmt.Errorf("metrics interval must be positive, got %d", config.MetricsInterval)
	}

	return nil
}
