// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package middlewares

import (
	"context"
	"log/slog"

	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/trace"
)

// LogCorrelationConfig holds configuration for log correlation middleware
type LogCorrelationConfig struct {
	// Skipper defines a function to skip middleware
	Skipper func(echo.Context) bool
	// Logger is the base logger to enhance with trace context
	Logger *slog.Logger
	// IncludeRequestDetails adds request details to log context
	IncludeRequestDetails bool
}

// LogCorrelation returns a middleware that automatically adds trace context to logs
func LogCorrelation() echo.MiddlewareFunc {
	return LogCorrelationWithConfig(LogCorrelationConfig{})
}

// LogCorrelationWithConfig returns a middleware with custom configuration
func LogCorrelationWithConfig(config LogCorrelationConfig) echo.MiddlewareFunc {
	// Set defaults
	if config.Skipper == nil {
		config.Skipper = func(echo.Context) bool { return false }
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if config.Skipper(c) {
				return next(c)
			}

			// Create a logger with trace context for this request
			logger := createTraceAwareLogger(c, config.Logger, config.IncludeRequestDetails)

			// Store the logger in the context for use by handlers
			c.Set("logger", logger)

			// Execute the handler
			err := next(c)

			// Log the request completion with trace context
			logRequestCompletion(c, logger, err)

			return err
		}
	}
}

// createTraceAwareLogger creates a logger with trace context and request details
func createTraceAwareLogger(c echo.Context, baseLogger *slog.Logger, includeRequestDetails bool) *slog.Logger {
	// Start with the base logger
	logger := baseLogger

	// Add request ID
	if requestID := c.Response().Header().Get(echo.HeaderXRequestID); requestID != "" {
		logger = logger.With("requestID", requestID)
	}

	// Add trace context
	span := trace.SpanFromContext(c.Request().Context())
	if span.SpanContext().IsValid() {
		logger = logger.With(
			"traceID", span.SpanContext().TraceID().String(),
			"spanID", span.SpanContext().SpanID().String(),
		)

		// Add trace flags
		if span.SpanContext().TraceFlags().IsSampled() {
			logger = logger.With("traceSampled", true)
		}
	}

	// Add trace information from Echo context (fallback) only if not already added from span
	if !span.SpanContext().IsValid() {
		if traceID, ok := c.Get("trace.id").(string); ok && traceID != "" {
			logger = logger.With("traceID", traceID)
		}
		if spanID, ok := c.Get("span.id").(string); ok && spanID != "" {
			logger = logger.With("spanID", spanID)
		}
	}

	// Add request details if requested
	if includeRequestDetails {
		req := c.Request()
		logger = logger.With(
			"method", req.Method,
			"path", req.URL.Path,
			"userAgent", req.UserAgent(),
			"clientIP", c.RealIP(),
		)

		// Add route if available
		if route := c.Path(); route != "" {
			logger = logger.With("route", route)
		}
	}

	return logger
}

// logRequestCompletion logs the completion of a request with trace context
func logRequestCompletion(c echo.Context, logger *slog.Logger, err error) {
	res := c.Response()
	req := c.Request()

	// Prepare log attributes
	attrs := []any{
		"method", req.Method,
		"path", req.URL.Path,
		"status", res.Status,
		"size", res.Size,
	}

	// Add route if available
	if route := c.Path(); route != "" {
		attrs = append(attrs, "route", route)
	}

	// Log based on status code and error
	if err != nil {
		attrs = append(attrs, "error", err.Error())
		logger.Error("Request completed with error", attrs...)
	} else if res.Status >= 500 {
		logger.Error("Request completed with server error", attrs...)
	} else if res.Status >= 400 {
		logger.Warn("Request completed with client error", attrs...)
	} else {
		logger.Info("Request completed successfully", attrs...)
	}
}

// GetLoggerFromContext retrieves the trace-aware logger from Echo context
func GetLoggerFromContext(c echo.Context) *slog.Logger {
	if logger, ok := c.Get("logger").(*slog.Logger); ok {
		return logger
	}

	// Fallback: create a trace-aware logger on the fly
	return createTraceAwareLogger(c, slog.Default(), false)
}

// LogWithContext logs a message using the trace-aware logger from context
func LogWithContext(c echo.Context, level slog.Level, msg string, args ...any) {
	logger := GetLoggerFromContext(c)
	logger.Log(c.Request().Context(), level, msg, args...)
}

// InfoWithContext logs an info message with trace context from Echo context
func InfoWithContext(c echo.Context, msg string, args ...any) {
	LogWithContext(c, slog.LevelInfo, msg, args...)
}

// WarnWithContext logs a warning message with trace context from Echo context
func WarnWithContext(c echo.Context, msg string, args ...any) {
	LogWithContext(c, slog.LevelWarn, msg, args...)
}

// ErrorWithContext logs an error message with trace context from Echo context
func ErrorWithContext(c echo.Context, msg string, args ...any) {
	LogWithContext(c, slog.LevelError, msg, args...)
}

// DebugWithContext logs a debug message with trace context from Echo context
func DebugWithContext(c echo.Context, msg string, args ...any) {
	LogWithContext(c, slog.LevelDebug, msg, args...)
}

// CreateContextLogger creates a context-aware logger that can be used outside of Echo handlers
func CreateContextLogger(ctx context.Context, baseLogger *slog.Logger) *slog.Logger {
	if baseLogger == nil {
		baseLogger = slog.Default()
	}

	// Add trace context if available
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		return baseLogger.With(
			"traceID", span.SpanContext().TraceID().String(),
			"spanID", span.SpanContext().SpanID().String(),
		)
	}

	return baseLogger
}

// LogWithTraceContext logs a message with trace context from a Go context
func LogWithTraceContext(ctx context.Context, logger *slog.Logger, level slog.Level, msg string, args ...any) {
	traceLogger := CreateContextLogger(ctx, logger)
	traceLogger.Log(ctx, level, msg, args...)
}
