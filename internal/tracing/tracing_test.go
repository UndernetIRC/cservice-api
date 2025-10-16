// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package tracing

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// setupTestTracer creates a test tracer with in-memory span recorder
func setupTestTracer(_ *testing.T) (*sdktrace.TracerProvider, *tracetest.SpanRecorder) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	otel.SetTracerProvider(tp)

	// Initialize global business tracer
	InitGlobalBusinessTracer(BusinessTracerConfig{
		TracerProvider: tp,
		ServiceName:    "test-service",
	})

	return tp, spanRecorder
}

// TestTracedContext_AddAttr tests adding attributes with automatic type conversion
func TestTracedContext_AddAttr(t *testing.T) {
	tp, spanRecorder := setupTestTracer(t)
	defer tp.Shutdown(context.Background())

	ctx, span := tp.Tracer("test").Start(context.Background(), "test-span")
	defer span.End()

	tc := WithSpan(ctx, span)

	// Test various types
	tc.AddAttr("string_key", "value")
	tc.AddAttr("int_key", 42)
	tc.AddAttr("int64_key", int64(100))
	tc.AddAttr("float_key", 3.14)
	tc.AddAttr("bool_key", true)
	tc.AddAttr("string_slice", []string{"a", "b"})

	span.End()

	spans := spanRecorder.Ended()
	assert.Len(t, spans, 1)

	// Verify attributes were added
	attrs := spans[0].Attributes()
	assert.Contains(t, attrs, attribute.String("string_key", "value"))
	assert.Contains(t, attrs, attribute.Int("int_key", 42))
	assert.Contains(t, attrs, attribute.Int64("int64_key", 100))
	assert.Contains(t, attrs, attribute.Float64("float_key", 3.14))
	assert.Contains(t, attrs, attribute.Bool("bool_key", true))
}

// TestTracedContext_AddAttrs tests adding multiple attributes at once
func TestTracedContext_AddAttrs(t *testing.T) {
	tp, spanRecorder := setupTestTracer(t)
	defer tp.Shutdown(context.Background())

	ctx, span := tp.Tracer("test").Start(context.Background(), "test-span")
	defer span.End()

	tc := WithSpan(ctx, span)

	attrs := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
		"key3": true,
	}

	tc.AddAttrs(attrs)
	span.End()

	spans := spanRecorder.Ended()
	assert.Len(t, spans, 1)

	spanAttrs := spans[0].Attributes()
	assert.Contains(t, spanAttrs, attribute.String("key1", "value1"))
	assert.Contains(t, spanAttrs, attribute.Int("key2", 42))
	assert.Contains(t, spanAttrs, attribute.Bool("key3", true))
}

// TestTracedContext_RecordError tests error recording with categorization
func TestTracedContext_RecordError(t *testing.T) {
	tp, spanRecorder := setupTestTracer(t)
	defer tp.Shutdown(context.Background())

	ctx, span := tp.Tracer("test").Start(context.Background(), "test-span")

	tc := WithSpan(ctx, span)

	testErr := errors.New("test error")
	tc.RecordError(testErr)

	span.End()

	spans := spanRecorder.Ended()
	assert.Len(t, spans, 1)

	// Verify error was recorded
	events := spans[0].Events()
	assert.NotEmpty(t, events)

	// Verify error attributes
	attrs := spans[0].Attributes()
	assert.Contains(t, attrs, attribute.String("error.message", "test error"))
}

// TestTracedContext_MarkSuccess tests marking operation as successful
func TestTracedContext_MarkSuccess(t *testing.T) {
	tp, spanRecorder := setupTestTracer(t)
	defer tp.Shutdown(context.Background())

	ctx, span := tp.Tracer("test").Start(context.Background(), "test-span")

	tc := WithSpan(ctx, span)
	tc.MarkSuccess()

	span.End()

	spans := spanRecorder.Ended()
	assert.Len(t, spans, 1)

	attrs := spans[0].Attributes()
	assert.Contains(t, attrs, attribute.Bool("operation.success", true))
}

// TestTracedContext_MarkFailure tests marking operation as failed
func TestTracedContext_MarkFailure(t *testing.T) {
	tp, spanRecorder := setupTestTracer(t)
	defer tp.Shutdown(context.Background())

	ctx, span := tp.Tracer("test").Start(context.Background(), "test-span")

	tc := WithSpan(ctx, span)
	tc.MarkFailure("test failure reason")

	span.End()

	spans := spanRecorder.Ended()
	assert.Len(t, spans, 1)

	attrs := spans[0].Attributes()
	assert.Contains(t, attrs, attribute.Bool("operation.success", false))
	assert.Contains(t, attrs, attribute.String("operation.failure_reason", "test failure reason"))
}

// TestOperation_Execute tests basic operation execution
func TestOperation_Execute(t *testing.T) {
	tp, spanRecorder := setupTestTracer(t)
	defer tp.Shutdown(context.Background())

	executed := false

	err := NewOperation("test-operation").
		WithContext(context.Background()).
		AddStage("stage1", func(tc *TracedContext) error {
			executed = true
			tc.AddAttr("stage1_executed", true)
			return nil
		}).
		Execute()

	assert.NoError(t, err)
	assert.True(t, executed)

	spans := spanRecorder.Ended()
	assert.NotEmpty(t, spans)
}

// TestOperation_ExecuteWithError tests operation execution with error
func TestOperation_ExecuteWithError(t *testing.T) {
	tp, spanRecorder := setupTestTracer(t)
	defer tp.Shutdown(context.Background())

	testErr := errors.New("stage error")

	err := NewOperation("test-operation").
		WithContext(context.Background()).
		AddStage("failing-stage", func(_ *TracedContext) error {
			return testErr
		}).
		Execute()

	assert.Error(t, err)
	assert.Equal(t, testErr, err)

	spans := spanRecorder.Ended()
	assert.NotEmpty(t, spans)
}

// TestOperation_MultipleStages tests operation with multiple stages
func TestOperation_MultipleStages(t *testing.T) {
	tp, spanRecorder := setupTestTracer(t)
	defer tp.Shutdown(context.Background())

	stage1Executed := false
	stage2Executed := false
	stage3Executed := false

	err := NewOperation("multi-stage-operation").
		WithContext(context.Background()).
		AddStage("stage1", func(_ *TracedContext) error {
			stage1Executed = true
			return nil
		}).
		AddStage("stage2", func(_ *TracedContext) error {
			stage2Executed = true
			return nil
		}).
		AddStage("stage3", func(_ *TracedContext) error {
			stage3Executed = true
			return nil
		}).
		Execute()

	assert.NoError(t, err)
	assert.True(t, stage1Executed)
	assert.True(t, stage2Executed)
	assert.True(t, stage3Executed)

	spans := spanRecorder.Ended()
	assert.NotEmpty(t, spans)
}

// TestOperation_OptionalStageFailure tests optional stage that fails
func TestOperation_OptionalStageFailure(t *testing.T) {
	tp, spanRecorder := setupTestTracer(t)
	defer tp.Shutdown(context.Background())

	stage1Executed := false
	optionalExecuted := false
	stage3Executed := false

	err := NewOperation("optional-stage-operation").
		WithContext(context.Background()).
		AddStage("stage1", func(_ *TracedContext) error {
			stage1Executed = true
			return nil
		}).
		AddOptionalStage("optional-failing", func(_ *TracedContext) error {
			optionalExecuted = true
			return errors.New("optional stage failed")
		}).
		AddStage("stage3", func(_ *TracedContext) error {
			stage3Executed = true
			return nil
		}).
		Execute()

	// Operation should succeed despite optional stage failing
	assert.NoError(t, err)
	assert.True(t, stage1Executed)
	assert.True(t, optionalExecuted)
	assert.True(t, stage3Executed)

	spans := spanRecorder.Ended()
	assert.NotEmpty(t, spans)
}

// TestOperation_WithAttributes tests adding root attributes
func TestOperation_WithAttributes(t *testing.T) {
	tp, spanRecorder := setupTestTracer(t)
	defer tp.Shutdown(context.Background())

	err := NewOperation("test-operation").
		WithContext(context.Background()).
		WithAttributes(map[string]interface{}{
			"attr1": "value1",
			"attr2": 42,
		}).
		WithAttribute("attr3", true).
		AddStage("stage1", func(_ *TracedContext) error {
			return nil
		}).
		Execute()

	assert.NoError(t, err)

	spans := spanRecorder.Ended()
	assert.NotEmpty(t, spans)

	// Find root span (will have operation.name attribute)
	for _, span := range spans {
		attrs := span.Attributes()
		for _, attr := range attrs {
			if attr.Key == "operation.name" {
				// This is the root span
				assert.Contains(t, attrs, attribute.String("attr1", "value1"))
				assert.Contains(t, attrs, attribute.Int("attr2", 42))
				assert.Contains(t, attrs, attribute.Bool("attr3", true))
				return
			}
		}
	}
}

// TestSimpleOperation tests simple operation helper
func TestSimpleOperation(t *testing.T) {
	tp, spanRecorder := setupTestTracer(t)
	defer tp.Shutdown(context.Background())

	executed := false

	err := SimpleOperation(context.Background(), "simple-op", func(_ *TracedContext) error {
		executed = true
		return nil
	})

	assert.NoError(t, err)
	assert.True(t, executed)

	spans := spanRecorder.Ended()
	assert.NotEmpty(t, spans)
}

// TestTwoStageOperation tests two-stage operation helper
func TestTwoStageOperation(t *testing.T) {
	tp, spanRecorder := setupTestTracer(t)
	defer tp.Shutdown(context.Background())

	stage1Executed := false
	stage2Executed := false

	err := TwoStageOperation(
		context.Background(),
		"two-stage-op",
		"stage1", "stage2",
		func(_ *TracedContext) error {
			stage1Executed = true
			return nil
		},
		func(_ *TracedContext) error {
			stage2Executed = true
			return nil
		},
	)

	assert.NoError(t, err)
	assert.True(t, stage1Executed)
	assert.True(t, stage2Executed)

	spans := spanRecorder.Ended()
	assert.NotEmpty(t, spans)
}

// TestHTTPRequestAttributes tests HTTP request attribute extraction
func TestHTTPRequestAttributes(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/test", nil)
	req.Header.Set("User-Agent", "test-agent")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	attrs := HTTPRequestAttributes(c)

	assert.Equal(t, "POST", attrs["http.method"])
	assert.Equal(t, "/api/test", attrs["http.path"])
	assert.Equal(t, "test-agent", attrs["http.user_agent"])
	assert.NotNil(t, attrs["http.remote_addr"])
}

// TestEmailAttributes tests email attribute extraction
func TestEmailAttributes(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected map[string]interface{}
	}{
		{
			name:  "valid email",
			email: "user@example.com",
			expected: map[string]interface{}{
				"email.provided":          true,
				"email.domain":            "example.com",
				"email.local_part_length": 4,
				"email.format_valid":      true,
				"email.length":            16,
			},
		},
		{
			name:  "invalid email",
			email: "invalid-email",
			expected: map[string]interface{}{
				"email.provided":     true,
				"email.domain":       "invalid",
				"email.format_valid": false,
				"email.length":       13,
			},
		},
		{
			name:  "empty email",
			email: "",
			expected: map[string]interface{}{
				"email.provided": false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := EmailAttributes(tt.email)

			for key, expected := range tt.expected {
				assert.Equal(t, expected, attrs[key], "mismatch for key: %s", key)
			}
		})
	}
}

// TestUsernameAttributes tests username attribute extraction
func TestUsernameAttributes(t *testing.T) {
	tests := []struct {
		name     string
		username string
		checks   map[string]interface{}
	}{
		{
			name:     "simple username",
			username: "testuser",
			checks: map[string]interface{}{
				"username.provided":          true,
				"username.length":            8,
				"username.has_special_chars": false,
				"username.has_numbers":       false,
				"username.is_lowercase":      true,
			},
		},
		{
			name:     "username with numbers",
			username: "user123",
			checks: map[string]interface{}{
				"username.provided":    true,
				"username.has_numbers": true,
			},
		},
		{
			name:     "username with special chars",
			username: "user@name",
			checks: map[string]interface{}{
				"username.provided":          true,
				"username.has_special_chars": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := UsernameAttributes(tt.username)

			for key, expected := range tt.checks {
				assert.Equal(t, expected, attrs[key], "mismatch for key: %s", key)
			}
		})
	}
}

// TestTokenAttributes tests token attribute extraction
func TestTokenAttributes(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		tokenType string
		checks    map[string]interface{}
	}{
		{
			name:      "JWT token",
			token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			tokenType: "access",
			checks: map[string]interface{}{
				"token.type":     "access",
				"token.provided": true,
				"token.format":   "jwt",
				"token.prefix":   "eyJhbGci",
			},
		},
		{
			name:      "opaque token",
			token:     "abc123xyz789",
			tokenType: "refresh",
			checks: map[string]interface{}{
				"token.type":     "refresh",
				"token.provided": true,
				"token.format":   "opaque",
				"token.length":   12,
			},
		},
		{
			name:      "empty token",
			token:     "",
			tokenType: "access",
			checks: map[string]interface{}{
				"token.type":     "access",
				"token.provided": false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := TokenAttributes(tt.token, tt.tokenType)

			for key, expected := range tt.checks {
				assert.Equal(t, expected, attrs[key], "mismatch for key: %s", key)
			}
		})
	}
}

// TestValidationResultAttrs tests validation result attributes
func TestValidationResultAttrs(t *testing.T) {
	attrs := ValidationResultAttrs("email", false, "invalid format")

	assert.Equal(t, "email", attrs["validation.field"])
	assert.Equal(t, false, attrs["validation.valid"])
	assert.Equal(t, "invalid format", attrs["validation.failure_reason"])
}

// TestDatabaseOperationAttrs tests database operation attributes
func TestDatabaseOperationAttrs(t *testing.T) {
	attrs := DatabaseOperationAttrs("INSERT", "users", 1)

	assert.Equal(t, "INSERT", attrs["db.operation"])
	assert.Equal(t, "users", attrs["db.table"])
	assert.Equal(t, int64(1), attrs["db.rows_affected"])
}

// TestAuthenticationAttrs tests authentication attributes
func TestAuthenticationAttrs(t *testing.T) {
	attrs := AuthenticationAttrs("testuser", "jwt", true)

	assert.Equal(t, "jwt", attrs["auth.type"])
	assert.Equal(t, true, attrs["auth.success"])
	assert.Equal(t, "testuser", attrs["auth.username"])
}

// TestTracedContext_NilSpan tests that operations with nil span don't panic
func TestTracedContext_NilSpan(_ *testing.T) {
	tc := &TracedContext{
		Context: context.Background(),
		span:    trace.SpanFromContext(context.Background()), // No-op span
	}

	// These should not panic
	tc.AddAttr("key", "value")
	tc.AddAttrs(map[string]interface{}{"key": "value"})
	tc.RecordError(errors.New("test error"))
	tc.MarkSuccess()
	tc.MarkFailure("test")
	tc.AddEvent("test-event")
}

// TestOperation_StageErrorPropagation tests that stage errors stop execution
func TestOperation_StageErrorPropagation(t *testing.T) {
	tp, spanRecorder := setupTestTracer(t)
	defer tp.Shutdown(context.Background())

	stage1Executed := false
	stage2Executed := false
	stage3Executed := false

	testErr := errors.New("stage 2 failed")

	err := NewOperation("error-propagation-test").
		WithContext(context.Background()).
		AddStage("stage1", func(_ *TracedContext) error {
			stage1Executed = true
			return nil
		}).
		AddStage("stage2", func(_ *TracedContext) error {
			stage2Executed = true
			return testErr
		}).
		AddStage("stage3", func(_ *TracedContext) error {
			stage3Executed = true
			return nil
		}).
		Execute()

	assert.Error(t, err)
	assert.Equal(t, testErr, err)
	assert.True(t, stage1Executed)
	assert.True(t, stage2Executed)
	assert.False(t, stage3Executed, "stage3 should not execute after stage2 error")

	spans := spanRecorder.Ended()
	assert.NotEmpty(t, spans)
}
