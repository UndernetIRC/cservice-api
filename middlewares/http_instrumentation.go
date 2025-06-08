// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package middlewares

import (
	"fmt"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// HTTPInstrumentationConfig holds configuration for HTTP instrumentation middleware
type HTTPInstrumentationConfig struct {
	// Skipper defines a function to skip middleware
	Skipper func(echo.Context) bool
	// Meter is the OpenTelemetry meter for creating instruments
	Meter metric.Meter
	// ServiceName is used for metric labeling
	ServiceName string
}

// HTTPInstruments holds all the metric instruments for HTTP requests
type HTTPInstruments struct {
	requestDuration metric.Float64Histogram
	requestCounter  metric.Int64Counter
	requestSize     metric.Int64Histogram
	responseSize    metric.Int64Histogram
	activeRequests  metric.Int64UpDownCounter
}

// DefaultHTTPInstrumentationConfig provides default configuration
var DefaultHTTPInstrumentationConfig = HTTPInstrumentationConfig{
	Skipper:     func(echo.Context) bool { return false },
	ServiceName: "cservice-api",
}

// HTTPInstrumentation returns a middleware that instruments HTTP requests with OpenTelemetry metrics
func HTTPInstrumentation(meter metric.Meter) echo.MiddlewareFunc {
	return HTTPInstrumentationWithConfig(HTTPInstrumentationConfig{
		Skipper:     DefaultHTTPInstrumentationConfig.Skipper,
		Meter:       meter,
		ServiceName: DefaultHTTPInstrumentationConfig.ServiceName,
	})
}

// HTTPInstrumentationWithConfig returns a middleware with custom configuration
func HTTPInstrumentationWithConfig(config HTTPInstrumentationConfig) echo.MiddlewareFunc {
	// Set defaults
	if config.Skipper == nil {
		config.Skipper = DefaultHTTPInstrumentationConfig.Skipper
	}
	if config.ServiceName == "" {
		config.ServiceName = DefaultHTTPInstrumentationConfig.ServiceName
	}

	// Create metric instruments
	instruments, err := createHTTPInstruments(config.Meter)
	if err != nil {
		// If we can't create instruments, return a no-op middleware
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return next
		}
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Skip if configured to do so
			if config.Skipper(c) {
				return next(c)
			}

			ctx := c.Request().Context()
			start := time.Now()

			// Get request information
			req := c.Request()
			method := req.Method
			route := c.Path()
			if route == "" {
				route = "unknown"
			}

			// Calculate request size
			requestSize := int64(0)
			if req.ContentLength > 0 {
				requestSize = req.ContentLength
			}

			// Increment active requests
			instruments.activeRequests.Add(ctx, 1, metric.WithAttributes(
				attribute.String("method", method),
				attribute.String("route", route),
				attribute.String("service", config.ServiceName),
			))

			// Record request size
			if requestSize > 0 {
				instruments.requestSize.Record(ctx, requestSize, metric.WithAttributes(
					attribute.String("method", method),
					attribute.String("route", route),
					attribute.String("service", config.ServiceName),
				))
			}

			// Execute the handler
			err := next(c)

			// Calculate duration
			duration := time.Since(start)
			durationMs := float64(duration.Nanoseconds()) / 1e6

			// Get response information
			res := c.Response()
			status := res.Status
			statusClass := getStatusClass(status)

			// Common attributes for metrics
			attrs := []attribute.KeyValue{
				attribute.String("method", method),
				attribute.String("route", route),
				attribute.String("status", strconv.Itoa(status)),
				attribute.String("status_class", statusClass),
				attribute.String("service", config.ServiceName),
			}

			// Record metrics
			instruments.requestDuration.Record(ctx, durationMs, metric.WithAttributes(attrs...))
			instruments.requestCounter.Add(ctx, 1, metric.WithAttributes(attrs...))

			// Record response size if available
			if res.Size > 0 {
				instruments.responseSize.Record(ctx, res.Size, metric.WithAttributes(attrs...))
			}

			// Decrement active requests
			instruments.activeRequests.Add(ctx, -1, metric.WithAttributes(
				attribute.String("method", method),
				attribute.String("route", route),
				attribute.String("service", config.ServiceName),
			))

			return err
		}
	}
}

// createHTTPInstruments creates all the metric instruments needed for HTTP instrumentation
func createHTTPInstruments(meter metric.Meter) (*HTTPInstruments, error) {
	if meter == nil {
		return nil, fmt.Errorf("meter cannot be nil")
	}

	// Request duration histogram
	requestDuration, err := meter.Float64Histogram(
		"http_request_duration_ms",
		metric.WithDescription("HTTP request duration in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, err
	}

	// Request counter
	requestCounter, err := meter.Int64Counter(
		"http_requests_total",
		metric.WithDescription("Total number of HTTP requests"),
	)
	if err != nil {
		return nil, err
	}

	// Request size histogram
	requestSize, err := meter.Int64Histogram(
		"http_request_size_bytes",
		metric.WithDescription("HTTP request size in bytes"),
		metric.WithUnit("bytes"),
	)
	if err != nil {
		return nil, err
	}

	// Response size histogram
	responseSize, err := meter.Int64Histogram(
		"http_response_size_bytes",
		metric.WithDescription("HTTP response size in bytes"),
		metric.WithUnit("bytes"),
	)
	if err != nil {
		return nil, err
	}

	// Active requests gauge
	activeRequests, err := meter.Int64UpDownCounter(
		"http_active_requests",
		metric.WithDescription("Number of active HTTP requests"),
	)
	if err != nil {
		return nil, err
	}

	return &HTTPInstruments{
		requestDuration: requestDuration,
		requestCounter:  requestCounter,
		requestSize:     requestSize,
		responseSize:    responseSize,
		activeRequests:  activeRequests,
	}, nil
}

// getStatusClass returns the status class (1xx, 2xx, 3xx, 4xx, 5xx) for a given status code
func getStatusClass(status int) string {
	switch {
	case status >= 100 && status < 200:
		return "1xx"
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500 && status < 600:
		return "5xx"
	default:
		return "unknown"
	}
}
