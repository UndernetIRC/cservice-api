// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package tracing

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// TracedContext wraps a context and span to provide convenient tracing methods
// This eliminates the need for repeated trace.SpanFromContext() calls
type TracedContext struct {
	context.Context
	span trace.Span
}

// NewTracedContext creates a new TracedContext from a context
// If the context doesn't have a span, it uses a no-op span
func NewTracedContext(ctx context.Context) *TracedContext {
	span := trace.SpanFromContext(ctx)
	return &TracedContext{
		Context: ctx,
		span:    span,
	}
}

// WithSpan creates a new TracedContext with the given span
func WithSpan(ctx context.Context, span trace.Span) *TracedContext {
	return &TracedContext{
		Context: ctx,
		span:    span,
	}
}

// Span returns the underlying span
func (tc *TracedContext) Span() trace.Span {
	return tc.span
}

// AddAttr adds a single attribute to the span
// Automatically handles type conversion for common Go types
func (tc *TracedContext) AddAttr(key string, value interface{}) {
	if tc.span == nil || !tc.span.IsRecording() {
		return
	}

	attr := convertToAttribute(key, value)
	tc.span.SetAttributes(attr)
}

// AddAttrs adds multiple attributes to the span at once
func (tc *TracedContext) AddAttrs(attrs map[string]interface{}) {
	if tc.span == nil || !tc.span.IsRecording() {
		return
	}

	converted := make([]attribute.KeyValue, 0, len(attrs))
	for key, value := range attrs {
		converted = append(converted, convertToAttribute(key, value))
	}
	tc.span.SetAttributes(converted...)
}

// AddStringAttr adds a string attribute (convenience method)
func (tc *TracedContext) AddStringAttr(key, value string) {
	if tc.span != nil && tc.span.IsRecording() {
		tc.span.SetAttributes(attribute.String(key, value))
	}
}

// AddIntAttr adds an int attribute (convenience method)
func (tc *TracedContext) AddIntAttr(key string, value int) {
	if tc.span != nil && tc.span.IsRecording() {
		tc.span.SetAttributes(attribute.Int(key, value))
	}
}

// AddInt64Attr adds an int64 attribute (convenience method)
func (tc *TracedContext) AddInt64Attr(key string, value int64) {
	if tc.span != nil && tc.span.IsRecording() {
		tc.span.SetAttributes(attribute.Int64(key, value))
	}
}

// AddBoolAttr adds a bool attribute (convenience method)
func (tc *TracedContext) AddBoolAttr(key string, value bool) {
	if tc.span != nil && tc.span.IsRecording() {
		tc.span.SetAttributes(attribute.Bool(key, value))
	}
}

// RecordError records an error in the span with automatic categorization
func (tc *TracedContext) RecordError(err error) {
	if tc.span == nil || !tc.span.IsRecording() || err == nil {
		return
	}

	tc.span.RecordError(err)
	tc.span.SetStatus(codes.Error, err.Error())

	// Auto-categorize the error
	bt := GetGlobalBusinessTracer()
	category := bt.categorizeError(err)
	severity := bt.determineSeverity(err, category)

	tc.span.SetAttributes(
		attribute.String("error.category", category),
		attribute.String("error.severity", severity),
		attribute.String("error.message", err.Error()),
		attribute.String("error.type", fmt.Sprintf("%T", err)),
	)
}

// RecordDetailedError records an error with additional context
func (tc *TracedContext) RecordDetailedError(err error, context map[string]interface{}) {
	if tc.span == nil || !tc.span.IsRecording() || err == nil {
		return
	}

	tc.RecordError(err)

	// Add context information
	for key, value := range context {
		tc.span.SetAttributes(attribute.String(fmt.Sprintf("error.context.%s", key), fmt.Sprintf("%v", value)))
	}
}

// MarkSuccess marks the current operation as successful
func (tc *TracedContext) MarkSuccess() {
	if tc.span != nil && tc.span.IsRecording() {
		tc.span.SetStatus(codes.Ok, "")
		tc.span.SetAttributes(attribute.Bool("operation.success", true))
	}
}

// MarkFailure marks the current operation as failed
func (tc *TracedContext) MarkFailure(reason string) {
	if tc.span != nil && tc.span.IsRecording() {
		tc.span.SetStatus(codes.Error, reason)
		tc.span.SetAttributes(
			attribute.Bool("operation.success", false),
			attribute.String("operation.failure_reason", reason),
		)
	}
}

// AddEvent adds an event to the span
func (tc *TracedContext) AddEvent(name string, attrs ...attribute.KeyValue) {
	if tc.span != nil && tc.span.IsRecording() {
		tc.span.AddEvent(name, trace.WithAttributes(attrs...))
	}
}

// convertToAttribute converts a Go value to an OpenTelemetry attribute
func convertToAttribute(key string, value interface{}) attribute.KeyValue {
	switch v := value.(type) {
	case string:
		return attribute.String(key, v)
	case int:
		return attribute.Int(key, v)
	case int32:
		return attribute.Int64(key, int64(v))
	case int64:
		return attribute.Int64(key, v)
	case float64:
		return attribute.Float64(key, v)
	case bool:
		return attribute.Bool(key, v)
	case []string:
		return attribute.StringSlice(key, v)
	case []int:
		return attribute.IntSlice(key, v)
	case []int64:
		return attribute.Int64Slice(key, v)
	case []bool:
		return attribute.BoolSlice(key, v)
	default:
		// For unknown types, convert to string
		return attribute.String(key, fmt.Sprintf("%v", v))
	}
}
