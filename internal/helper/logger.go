// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

package helper

import (
	"log/slog"

	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/trace"
)

// GetRequestLogger returns a slog.Logger that automatically includes the request ID
// from the Echo context in all log entries. If no request ID is found, it uses "unknown".
func GetRequestLogger(c echo.Context) *slog.Logger {
	requestID := c.Response().Header().Get(echo.HeaderXRequestID)
	if requestID == "" {
		requestID = "unknown"
	}

	return slog.With("requestID", requestID)
}

// GetRequestID extracts the request ID from the Echo context.
// Returns "unknown" if no request ID is found.
func GetRequestID(c echo.Context) string {
	requestID := c.Response().Header().Get(echo.HeaderXRequestID)
	if requestID == "" {
		requestID = "unknown"
	}
	return requestID
}

// GetTraceLogger returns a slog.Logger that includes both request ID and trace context
// information (trace ID, span ID) for complete log correlation.
func GetTraceLogger(c echo.Context) *slog.Logger {
	// Start with request ID
	requestID := GetRequestID(c)
	logger := slog.With("requestID", requestID)

	// Add trace context if available
	span := trace.SpanFromContext(c.Request().Context())
	if span.SpanContext().IsValid() {
		logger = logger.With(
			"traceID", span.SpanContext().TraceID().String(),
			"spanID", span.SpanContext().SpanID().String(),
		)

		// Add trace flags if they exist
		if span.SpanContext().TraceFlags().IsSampled() {
			logger = logger.With("traceSampled", true)
		}
	}

	// Add trace information from Echo context if available (fallback)
	if traceID, ok := c.Get("trace.id").(string); ok && traceID != "" {
		logger = logger.With("traceID", traceID)
	}
	if spanID, ok := c.Get("span.id").(string); ok && spanID != "" {
		logger = logger.With("spanID", spanID)
	}

	return logger
}

// GetTraceID extracts the trace ID from the Echo context.
// Returns empty string if no trace ID is found.
func GetTraceID(c echo.Context) string {
	// First try to get from active span
	span := trace.SpanFromContext(c.Request().Context())
	if span.SpanContext().IsValid() {
		return span.SpanContext().TraceID().String()
	}

	// Fallback to stored trace ID in Echo context
	if traceID, ok := c.Get("trace.id").(string); ok {
		return traceID
	}

	return ""
}

// GetSpanID extracts the span ID from the Echo context.
// Returns empty string if no span ID is found.
func GetSpanID(c echo.Context) string {
	// First try to get from active span
	span := trace.SpanFromContext(c.Request().Context())
	if span.SpanContext().IsValid() {
		return span.SpanContext().SpanID().String()
	}

	// Fallback to stored span ID in Echo context
	if spanID, ok := c.Get("span.id").(string); ok {
		return spanID
	}

	return ""
}

// LogWithTrace logs a message with automatic trace context correlation.
// This is a convenience function that creates a trace-aware logger and logs the message.
func LogWithTrace(c echo.Context, level slog.Level, msg string, args ...any) {
	logger := GetTraceLogger(c)
	logger.Log(c.Request().Context(), level, msg, args...)
}

// InfoWithTrace logs an info message with trace context.
func InfoWithTrace(c echo.Context, msg string, args ...any) {
	LogWithTrace(c, slog.LevelInfo, msg, args...)
}

// WarnWithTrace logs a warning message with trace context.
func WarnWithTrace(c echo.Context, msg string, args ...any) {
	LogWithTrace(c, slog.LevelWarn, msg, args...)
}

// ErrorWithTrace logs an error message with trace context.
func ErrorWithTrace(c echo.Context, msg string, args ...any) {
	LogWithTrace(c, slog.LevelError, msg, args...)
}

// DebugWithTrace logs a debug message with trace context.
func DebugWithTrace(c echo.Context, msg string, args ...any) {
	LogWithTrace(c, slog.LevelDebug, msg, args...)
}
