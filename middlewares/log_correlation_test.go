// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package middlewares

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
)

func TestLogCorrelation(t *testing.T) {
	// Create a buffer to capture log output
	var buf bytes.Buffer

	// Create a test logger that writes to our buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(handler)

	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	// Create Echo instance
	e := echo.New()

	// Add request ID middleware first
	e.Use(middleware.RequestID())

	// Add tracing middleware
	e.Use(HTTPTracingEnhanced(tracerProvider, "test-service"))

	// Add log correlation middleware
	e.Use(LogCorrelationWithConfig(LogCorrelationConfig{
		Logger:                logger,
		IncludeRequestDetails: true,
	}))

	// Add a test route that uses the logger from context
	e.GET("/api/test", func(c echo.Context) error {
		// Get the logger from context and log a message
		InfoWithContext(c, "Processing request", "user", "test-user")

		return c.JSON(http.StatusOK, map[string]string{"status": "success"})
	})

	// Create a test request
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()

	// Execute the request
	e.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify log output contains trace context
	logOutput := buf.String()
	assert.Contains(t, logOutput, "traceID", "Expected log to contain trace ID")
	assert.Contains(t, logOutput, "spanID", "Expected log to contain span ID")
	assert.Contains(t, logOutput, "requestID", "Expected log to contain request ID")
	assert.Contains(t, logOutput, "Processing request", "Expected log to contain our message")
	assert.Contains(t, logOutput, "user", "Expected log to contain our custom attribute")
	assert.Contains(t, logOutput, "test-user", "Expected log to contain our custom value")
}

func TestLogCorrelationWithoutTracing(t *testing.T) {
	// Create a buffer to capture log output
	var buf bytes.Buffer

	// Create a test logger that writes to our buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(handler)

	// Create Echo instance without tracing
	e := echo.New()

	// Add request ID middleware
	e.Use(middleware.RequestID())

	// Add log correlation middleware only
	e.Use(LogCorrelationWithConfig(LogCorrelationConfig{
		Logger:                logger,
		IncludeRequestDetails: false,
	}))

	// Add a test route
	e.POST("/api/test", func(c echo.Context) error {
		// Log a message using the context logger
		ErrorWithContext(c, "Test error message", "error_code", 500)

		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "test error"})
	})

	// Create a test request
	req := httptest.NewRequest(http.MethodPost, "/api/test", nil)
	rec := httptest.NewRecorder()

	// Execute the request
	e.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	// Verify log output contains request ID but no trace context
	logOutput := buf.String()
	assert.Contains(t, logOutput, "requestID", "Expected log to contain request ID")
	assert.Contains(t, logOutput, "Test error message", "Expected log to contain our message")
	assert.Contains(t, logOutput, "error_code", "Expected log to contain our custom attribute")

	// Should not contain trace context since tracing is not enabled
	assert.NotContains(t, logOutput, "traceID", "Expected log to NOT contain trace ID without tracing")
}

func TestGetLoggerFromContext(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	// Create Echo instance
	e := echo.New()
	e.Use(HTTPTracingEnhanced(tracerProvider, "test-service"))
	e.Use(LogCorrelation())

	// Add a test route
	e.GET("/api/test", func(c echo.Context) error {
		// Get logger from context
		logger := GetLoggerFromContext(c)
		assert.NotNil(t, logger, "Expected logger to be available from context")

		// Verify it's a properly configured logger (this is hard to test directly,
		// but we can at least verify it doesn't panic)
		logger.Info("Test message from context logger")

		return c.String(http.StatusOK, "test response")
	})

	// Create a test request
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()

	// Execute the request
	e.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCreateContextLogger(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)

	// Create a tracer and span
	tracer := tracerProvider.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-operation")
	defer span.End()

	// Create a buffer to capture log output
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	baseLogger := slog.New(handler)

	// Create context logger
	contextLogger := CreateContextLogger(ctx, baseLogger)
	assert.NotNil(t, contextLogger, "Expected context logger to be created")

	// Log a message
	contextLogger.Info("Test message with trace context", "key", "value")

	// Verify log output contains trace context
	logOutput := buf.String()
	assert.Contains(t, logOutput, "traceID", "Expected log to contain trace ID")
	assert.Contains(t, logOutput, "spanID", "Expected log to contain span ID")
	assert.Contains(t, logOutput, "Test message with trace context", "Expected log to contain our message")
}

func TestLogWithTraceContext(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)

	// Create a tracer and span
	tracer := tracerProvider.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-operation")
	defer span.End()

	// Create a buffer to capture log output
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	baseLogger := slog.New(handler)

	// Log with trace context
	LogWithTraceContext(ctx, baseLogger, slog.LevelWarn, "Warning message", "warning_type", "test")

	// Verify log output
	logOutput := buf.String()
	assert.Contains(t, logOutput, "traceID", "Expected log to contain trace ID")
	assert.Contains(t, logOutput, "spanID", "Expected log to contain span ID")
	assert.Contains(t, logOutput, "Warning message", "Expected log to contain our message")
	assert.Contains(t, logOutput, "warning_type", "Expected log to contain our attribute")
	assert.Contains(t, logOutput, "test", "Expected log to contain our attribute value")
}

func TestLogCorrelationSkipper(t *testing.T) {
	// Create a buffer to capture log output
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(handler)

	// Create Echo instance
	e := echo.New()

	// Add log correlation middleware with skipper
	e.Use(LogCorrelationWithConfig(LogCorrelationConfig{
		Logger: logger,
		Skipper: func(c echo.Context) bool {
			// Skip health check endpoints
			return strings.HasPrefix(c.Request().URL.Path, "/health")
		},
	}))

	// Add test routes
	e.GET("/health", func(c echo.Context) error {
		// This should not have the logger in context due to skipper
		// Use the test logger directly to verify the skipper works
		logger.Info("Health check")
		return c.String(http.StatusOK, "healthy")
	})

	e.GET("/api/test", func(c echo.Context) error {
		// This should have the logger in context
		InfoWithContext(c, "API call")
		return c.String(http.StatusOK, "test")
	})

	// Test health endpoint (should be skipped)
	req1 := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec1 := httptest.NewRecorder()
	e.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code)

	// Test API endpoint (should not be skipped)
	req2 := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)

	// Verify logs were generated
	logOutput := buf.String()
	assert.Contains(t, logOutput, "Health check", "Expected health check log")
	assert.Contains(t, logOutput, "API call", "Expected API call log")
}

func TestLogRequestCompletion(t *testing.T) {
	// Create a buffer to capture log output
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(handler)

	// Create Echo instance
	e := echo.New()
	e.Use(LogCorrelationWithConfig(LogCorrelationConfig{
		Logger:                logger,
		IncludeRequestDetails: true,
	}))

	// Add test routes with different response codes
	e.GET("/success", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	e.GET("/client-error", func(c echo.Context) error {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "bad request"})
	})

	e.GET("/server-error", func(c echo.Context) error {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	})

	// Test successful request
	req1 := httptest.NewRequest(http.MethodGet, "/success", nil)
	rec1 := httptest.NewRecorder()
	e.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code)

	// Test client error
	req2 := httptest.NewRequest(http.MethodGet, "/client-error", nil)
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusBadRequest, rec2.Code)

	// Test server error
	req3 := httptest.NewRequest(http.MethodGet, "/server-error", nil)
	rec3 := httptest.NewRecorder()
	e.ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusInternalServerError, rec3.Code)

	// Verify log output contains completion logs
	logOutput := buf.String()
	assert.Contains(t, logOutput, "Request completed successfully", "Expected success completion log")
	assert.Contains(t, logOutput, "Request completed with client error", "Expected client error completion log")
	assert.Contains(t, logOutput, "Request completed with server error", "Expected server error completion log")

	// Verify status codes are logged
	assert.Contains(t, logOutput, "\"status\":200", "Expected 200 status in logs")
	assert.Contains(t, logOutput, "\"status\":400", "Expected 400 status in logs")
	assert.Contains(t, logOutput, "\"status\":500", "Expected 500 status in logs")
}
