// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package tracing

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

func TestNewBusinessTracer(t *testing.T) {
	tests := []struct {
		name           string
		config         BusinessTracerConfig
		expectedName   string
		expectedTracer bool
	}{
		{
			name: "valid config with custom service name",
			config: BusinessTracerConfig{
				TracerProvider: otel.GetTracerProvider(),
				ServiceName:    "test-service",
			},
			expectedName:   "test-service",
			expectedTracer: true,
		},
		{
			name: "valid config with default service name",
			config: BusinessTracerConfig{
				TracerProvider: otel.GetTracerProvider(),
			},
			expectedName:   "cservice-api",
			expectedTracer: true,
		},
		{
			name: "nil tracer provider uses default",
			config: BusinessTracerConfig{
				ServiceName: "test-service",
			},
			expectedName:   "test-service",
			expectedTracer: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracer := NewBusinessTracer(tt.config)

			assert.NotNil(t, tracer)
			assert.Equal(t, tt.expectedName, tracer.serviceName)
			if tt.expectedTracer {
				assert.NotNil(t, tracer.tracer)
			}
		})
	}
}

func TestBusinessTracer_TraceOperation(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(resource.Default()),
	)

	tracer := NewBusinessTracer(BusinessTracerConfig{
		TracerProvider: tp,
		ServiceName:    "test-service",
	})

	tests := []struct {
		name          string
		operationName string
		operation     func(context.Context) error
		expectError   bool
		expectedError string
	}{
		{
			name:          "successful operation",
			operationName: "TestOperation",
			operation: func(_ context.Context) error {
				return nil
			},
			expectError: false,
		},
		{
			name:          "failed operation",
			operationName: "FailedOperation",
			operation: func(_ context.Context) error {
				return errors.New("operation failed")
			},
			expectError:   true,
			expectedError: "operation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			exporter.Reset()

			err := tracer.TraceOperation(ctx, tt.operationName, tt.operation)

			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err.Error())
			} else {
				assert.NoError(t, err)
			}

			// Verify span was created
			spans := exporter.GetSpans()
			require.Len(t, spans, 1)

			span := spans[0]
			assert.Equal(t, tt.operationName, span.Name)
			assert.Equal(t, trace.SpanKindInternal, span.SpanKind)

			// Check attributes
			attrs := span.Attributes
			assert.Contains(t, attrs, attribute.String("service.name", "test-service"))
			assert.Contains(t, attrs, attribute.String("service.component", "business-logic"))
			assert.Contains(t, attrs, attribute.String("operation.name", tt.operationName))

			if tt.expectError {
				assert.Contains(t, attrs, attribute.Bool("operation.success", false))
				assert.Equal(t, codes.Error, span.Status.Code)
			} else {
				assert.Contains(t, attrs, attribute.Bool("operation.success", true))
				assert.Equal(t, codes.Ok, span.Status.Code)
			}
		})
	}
}

func TestBusinessTracer_TraceUserRegistration(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(resource.Default()),
	)

	tracer := NewBusinessTracer(BusinessTracerConfig{
		TracerProvider: tp,
		ServiceName:    "test-service",
	})

	tests := []struct {
		name      string
		username  string
		email     string
		stage     string
		operation func(context.Context) error
		expectErr bool
	}{
		{
			name:     "successful registration",
			username: "testuser",
			email:    "test@example.com",
			stage:    "create",
			operation: func(_ context.Context) error {
				return nil
			},
			expectErr: false,
		},
		{
			name:     "failed registration",
			username: "testuser",
			email:    "test@example.com",
			stage:    "validate",
			operation: func(_ context.Context) error {
				return errors.New("validation failed")
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			exporter.Reset()

			err := tracer.TraceUserRegistration(ctx, tt.username, tt.email, tt.stage, tt.operation)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify span was created
			spans := exporter.GetSpans()
			require.Len(t, spans, 1)

			span := spans[0]
			expectedName := "UserRegistration." + tt.stage
			assert.Equal(t, expectedName, span.Name)

			// Check attributes
			attrs := span.Attributes
			assert.Contains(t, attrs, attribute.String("service.name", "test-service"))
			assert.Contains(t, attrs, attribute.String("service.component", "user-registration"))
			assert.Contains(t, attrs, attribute.String("user.username", tt.username))
			assert.Contains(t, attrs, attribute.String("user.email", tt.email))
			assert.Contains(t, attrs, attribute.String("registration.stage", tt.stage))
			assert.Contains(t, attrs, attribute.String("operation.type", "user_registration"))

			// Check duration attribute exists
			found := false
			for _, attr := range attrs {
				if attr.Key == "operation.duration_ms" {
					found = true
					break
				}
			}
			assert.True(t, found, "operation.duration_ms attribute should be present")

			if tt.expectErr {
				assert.Contains(t, attrs, attribute.Bool("registration.success", false))
				assert.Equal(t, codes.Error, span.Status.Code)
			} else {
				assert.Contains(t, attrs, attribute.Bool("registration.success", true))
				assert.Equal(t, codes.Ok, span.Status.Code)
			}
		})
	}
}

func TestBusinessTracer_TraceUserActivation(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(resource.Default()),
	)

	tracer := NewBusinessTracer(BusinessTracerConfig{
		TracerProvider: tp,
		ServiceName:    "test-service",
	})

	ctx := context.Background()
	username := "testuser"
	token := "activation-token-123"

	err := tracer.TraceUserActivation(ctx, username, token, func(_ context.Context) error {
		return nil
	})

	assert.NoError(t, err)

	// Verify span was created
	spans := exporter.GetSpans()
	require.Len(t, spans, 1)

	span := spans[0]
	assert.Equal(t, "UserActivation", span.Name)

	// Check attributes
	attrs := span.Attributes
	assert.Contains(t, attrs, attribute.String("service.name", "test-service"))
	assert.Contains(t, attrs, attribute.String("service.component", "user-activation"))
	assert.Contains(t, attrs, attribute.String("user.username", username))
	assert.Contains(t, attrs, attribute.String("activation.token_length", "20"))
	assert.Contains(t, attrs, attribute.String("operation.type", "user_activation"))
	assert.Contains(t, attrs, attribute.Bool("activation.success", true))
}

func TestBusinessTracer_TraceChannelOperation(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(resource.Default()),
	)

	tracer := NewBusinessTracer(BusinessTracerConfig{
		TracerProvider: tp,
		ServiceName:    "test-service",
	})

	ctx := context.Background()
	channelID := int32(123)
	userID := int32(456)
	operation := "join"

	err := tracer.TraceChannelOperation(ctx, channelID, userID, operation, func(_ context.Context) error {
		return nil
	})

	assert.NoError(t, err)

	// Verify span was created
	spans := exporter.GetSpans()
	require.Len(t, spans, 1)

	span := spans[0]
	assert.Equal(t, "ChannelOperation.join", span.Name)

	// Check attributes
	attrs := span.Attributes
	assert.Contains(t, attrs, attribute.String("service.name", "test-service"))
	assert.Contains(t, attrs, attribute.String("service.component", "channel-operations"))
	assert.Contains(t, attrs, attribute.Int64("channel.id", 123))
	assert.Contains(t, attrs, attribute.Int64("user.id", 456))
	assert.Contains(t, attrs, attribute.String("channel.operation", operation))
	assert.Contains(t, attrs, attribute.String("operation.type", "channel_operation"))
	assert.Contains(t, attrs, attribute.Bool("operation.success", true))
}

func TestBusinessTracer_TraceChannelSearch(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(resource.Default()),
	)

	tracer := NewBusinessTracer(BusinessTracerConfig{
		TracerProvider: tp,
		ServiceName:    "test-service",
	})

	ctx := context.Background()
	userID := int32(456)
	query := "test query"
	expectedResults := 5

	resultCount, err := tracer.TraceChannelSearch(ctx, userID, query, func(_ context.Context) (int, error) {
		return expectedResults, nil
	})

	assert.NoError(t, err)
	assert.Equal(t, expectedResults, resultCount)

	// Verify span was created
	spans := exporter.GetSpans()
	require.Len(t, spans, 1)

	span := spans[0]
	assert.Equal(t, "ChannelSearch", span.Name)

	// Check attributes
	attrs := span.Attributes
	assert.Contains(t, attrs, attribute.String("service.name", "test-service"))
	assert.Contains(t, attrs, attribute.String("service.component", "channel-search"))
	assert.Contains(t, attrs, attribute.Int64("user.id", 456))
	assert.Contains(t, attrs, attribute.String("search.query", query))
	assert.Contains(t, attrs, attribute.String("search.query_type", "medium"))
	assert.Contains(t, attrs, attribute.String("operation.type", "channel_search"))
	assert.Contains(t, attrs, attribute.Int("search.result_count", expectedResults))
	assert.Contains(t, attrs, attribute.Bool("search.success", true))
}

func TestBusinessTracer_TraceAuthentication(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(resource.Default()),
	)

	tracer := NewBusinessTracer(BusinessTracerConfig{
		TracerProvider: tp,
		ServiceName:    "test-service",
	})

	ctx := context.Background()
	username := "testuser"
	authType := "password"

	err := tracer.TraceAuthentication(ctx, username, authType, func(_ context.Context) error {
		return nil
	})

	assert.NoError(t, err)

	// Verify span was created
	spans := exporter.GetSpans()
	require.Len(t, spans, 1)

	span := spans[0]
	assert.Equal(t, "Authentication.password", span.Name)

	// Check attributes
	attrs := span.Attributes
	assert.Contains(t, attrs, attribute.String("service.name", "test-service"))
	assert.Contains(t, attrs, attribute.String("service.component", "authentication"))
	assert.Contains(t, attrs, attribute.String("user.username", username))
	assert.Contains(t, attrs, attribute.String("auth.type", authType))
	assert.Contains(t, attrs, attribute.String("operation.type", "authentication"))
	assert.Contains(t, attrs, attribute.Bool("auth.success", true))
}

func TestBusinessTracer_TraceBusinessTransaction(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(resource.Default()),
	)

	tracer := NewBusinessTracer(BusinessTracerConfig{
		TracerProvider: tp,
		ServiceName:    "test-service",
	})

	ctx := context.Background()
	transactionName := "UserOnboarding"

	err := tracer.TraceBusinessTransaction(ctx, transactionName, func(_ context.Context) error {
		// Simulate some work
		time.Sleep(1 * time.Millisecond)
		return nil
	})

	assert.NoError(t, err)

	// Verify span was created
	spans := exporter.GetSpans()
	require.Len(t, spans, 1)

	span := spans[0]
	assert.Equal(t, "BusinessTransaction.UserOnboarding", span.Name)

	// Check attributes
	attrs := span.Attributes
	assert.Contains(t, attrs, attribute.String("service.name", "test-service"))
	assert.Contains(t, attrs, attribute.String("service.component", "business-transaction"))
	assert.Contains(t, attrs, attribute.String("transaction.name", transactionName))
	assert.Contains(t, attrs, attribute.String("operation.type", "business_transaction"))
	assert.Contains(t, attrs, attribute.Bool("transaction.success", true))

	// Check that duration was recorded
	found := false
	for _, attr := range attrs {
		if attr.Key == "transaction.duration_ms" {
			found = true
			assert.True(t, attr.Value.AsInt64() >= 1) // Should be at least 1ms
			break
		}
	}
	assert.True(t, found, "transaction.duration_ms attribute should be present")
}

func TestBusinessTracer_StartSpan(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(resource.Default()),
	)

	tracer := NewBusinessTracer(BusinessTracerConfig{
		TracerProvider: tp,
		ServiceName:    "test-service",
	})

	ctx := context.Background()
	operationName := "CustomOperation"

	newCtx, span := tracer.StartSpan(ctx, operationName)
	span.End()

	assert.NotEqual(t, ctx, newCtx)
	assert.NotNil(t, span)

	// Verify span was created
	spans := exporter.GetSpans()
	require.Len(t, spans, 1)

	createdSpan := spans[0]
	assert.Equal(t, operationName, createdSpan.Name)
	assert.Equal(t, trace.SpanKindInternal, createdSpan.SpanKind)

	// Check default attributes
	attrs := createdSpan.Attributes
	assert.Contains(t, attrs, attribute.String("service.name", "test-service"))
	assert.Contains(t, attrs, attribute.String("service.component", "business-logic"))
}

func TestBusinessTracer_RecordError(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(resource.Default()),
	)

	tracer := NewBusinessTracer(BusinessTracerConfig{
		TracerProvider: tp,
		ServiceName:    "test-service",
	})

	ctx := context.Background()
	ctx, span := tracer.StartSpan(ctx, "TestOperation")

	testError := errors.New("test error")
	tracer.RecordError(ctx, testError)

	span.End()

	// Verify span was created with error
	spans := exporter.GetSpans()
	require.Len(t, spans, 1)

	createdSpan := spans[0]
	assert.Equal(t, codes.Error, createdSpan.Status.Code)
	assert.Equal(t, "test error", createdSpan.Status.Description)

	// Check that error event was recorded
	assert.Len(t, createdSpan.Events, 1)
	event := createdSpan.Events[0]
	assert.Equal(t, "exception", event.Name)
}

func TestBusinessTracer_AddAttributes(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(resource.Default()),
	)

	tracer := NewBusinessTracer(BusinessTracerConfig{
		TracerProvider: tp,
		ServiceName:    "test-service",
	})

	ctx := context.Background()
	ctx, span := tracer.StartSpan(ctx, "TestOperation")

	customAttrs := []attribute.KeyValue{
		attribute.String("custom.key", "custom.value"),
		attribute.Int("custom.number", 42),
	}
	tracer.AddAttributes(ctx, customAttrs...)

	span.End()

	// Verify span was created with custom attributes
	spans := exporter.GetSpans()
	require.Len(t, spans, 1)

	createdSpan := spans[0]
	attrs := createdSpan.Attributes

	// Check custom attributes were added
	assert.Contains(t, attrs, attribute.String("custom.key", "custom.value"))
	assert.Contains(t, attrs, attribute.Int("custom.number", 42))
}

func TestBusinessTracer_SetStatus(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(resource.Default()),
	)

	tracer := NewBusinessTracer(BusinessTracerConfig{
		TracerProvider: tp,
		ServiceName:    "test-service",
	})

	ctx := context.Background()
	ctx, span := tracer.StartSpan(ctx, "TestOperation")

	tracer.SetStatus(ctx, codes.Error, "custom error message")

	span.End()

	// Verify span was created with custom status
	spans := exporter.GetSpans()
	require.Len(t, spans, 1)

	createdSpan := spans[0]
	assert.Equal(t, codes.Error, createdSpan.Status.Code)
	assert.Equal(t, "custom error message", createdSpan.Status.Description)
}

func TestGetQueryType(t *testing.T) {
	tests := []struct {
		query    string
		expected string
	}{
		{"", "empty"},
		{"a", "single_char"},
		{"ab", "short"},
		{"abc", "short"},
		{"abcd", "medium"},
		{"abcdefghij", "medium"},
		{"abcdefghijk", "long"},
		{"this is a very long query", "long"},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			result := getQueryType(tt.query)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGlobalBusinessTracer(t *testing.T) {
	// Reset global tracer
	globalBusinessTracer = nil

	// Test getting global tracer when not initialized
	tracer1 := GetGlobalBusinessTracer()
	assert.NotNil(t, tracer1)
	assert.Equal(t, "cservice-api", tracer1.serviceName)

	// Test getting the same instance
	tracer2 := GetGlobalBusinessTracer()
	assert.Same(t, tracer1, tracer2)

	// Test initializing global tracer
	InitGlobalBusinessTracer(BusinessTracerConfig{
		ServiceName: "custom-service",
	})

	tracer3 := GetGlobalBusinessTracer()
	assert.NotNil(t, tracer3)
	assert.Equal(t, "custom-service", tracer3.serviceName)
	assert.NotSame(t, tracer1, tracer3)
}

func TestGlobalTracingFunctions(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(resource.Default()),
	)

	// Initialize global tracer
	InitGlobalBusinessTracer(BusinessTracerConfig{
		TracerProvider: tp,
		ServiceName:    "test-service",
	})

	ctx := context.Background()

	t.Run("TraceOperation", func(t *testing.T) {
		exporter.Reset()
		err := TraceOperation(ctx, "GlobalTest", func(_ context.Context) error {
			return nil
		})
		assert.NoError(t, err)

		spans := exporter.GetSpans()
		require.Len(t, spans, 1)
		assert.Equal(t, "GlobalTest", spans[0].Name)
	})

	t.Run("TraceUserRegistration", func(t *testing.T) {
		exporter.Reset()
		err := TraceUserRegistration(ctx, "user", "email", "stage", func(_ context.Context) error {
			return nil
		})
		assert.NoError(t, err)

		spans := exporter.GetSpans()
		require.Len(t, spans, 1)
		assert.Equal(t, "UserRegistration.stage", spans[0].Name)
	})

	t.Run("TraceUserActivation", func(t *testing.T) {
		exporter.Reset()
		err := TraceUserActivation(ctx, "user", "token", func(_ context.Context) error {
			return nil
		})
		assert.NoError(t, err)

		spans := exporter.GetSpans()
		require.Len(t, spans, 1)
		assert.Equal(t, "UserActivation", spans[0].Name)
	})

	t.Run("TraceChannelOperation", func(t *testing.T) {
		exporter.Reset()
		err := TraceChannelOperation(ctx, 123, 456, "test", func(_ context.Context) error {
			return nil
		})
		assert.NoError(t, err)

		spans := exporter.GetSpans()
		require.Len(t, spans, 1)
		assert.Equal(t, "ChannelOperation.test", spans[0].Name)
	})

	t.Run("TraceChannelSearch", func(t *testing.T) {
		exporter.Reset()
		count, err := TraceChannelSearch(ctx, 456, "query", func(_ context.Context) (int, error) {
			return 5, nil
		})
		assert.NoError(t, err)
		assert.Equal(t, 5, count)

		spans := exporter.GetSpans()
		require.Len(t, spans, 1)
		assert.Equal(t, "ChannelSearch", spans[0].Name)
	})

	t.Run("TraceAuthentication", func(t *testing.T) {
		exporter.Reset()
		err := TraceAuthentication(ctx, "user", "password", func(_ context.Context) error {
			return nil
		})
		assert.NoError(t, err)

		spans := exporter.GetSpans()
		require.Len(t, spans, 1)
		assert.Equal(t, "Authentication.password", spans[0].Name)
	})

	t.Run("TraceBusinessTransaction", func(t *testing.T) {
		exporter.Reset()
		err := TraceBusinessTransaction(ctx, "TestTransaction", func(_ context.Context) error {
			return nil
		})
		assert.NoError(t, err)

		spans := exporter.GetSpans()
		require.Len(t, spans, 1)
		assert.Equal(t, "BusinessTransaction.TestTransaction", spans[0].Name)
	})
}

func TestBusinessTracerWithNilContext(t *testing.T) {
	// Setup test tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(resource.Default()),
	)

	tracer := NewBusinessTracer(BusinessTracerConfig{
		TracerProvider: tp,
		ServiceName:    "test-service",
	})

	// Test with background context (not nil, but no active span)
	ctx := context.Background()

	// These should not panic and should work correctly
	tracer.RecordError(ctx, errors.New("test error"))
	tracer.AddAttributes(ctx, attribute.String("test", "value"))
	tracer.SetStatus(ctx, codes.Error, "test")

	// No spans should be created since there's no active span
	spans := exporter.GetSpans()
	assert.Len(t, spans, 0)
}

func TestBusinessTracer_RecordDetailedError(t *testing.T) {
	tests := []struct {
		name      string
		errorInfo ErrorInfo
		wantAttrs map[string]interface{}
	}{
		{
			name: "detailed error with all fields",
			errorInfo: ErrorInfo{
				Error:     errors.New("test database error"),
				Category:  ErrorCategoryDatabase,
				Severity:  ErrorSeverityHigh,
				UserID:    &[]int64{12345}[0],
				Operation: "user_lookup",
				StackTrace: []string{
					"main.TestFunction (test.go:123)",
					"runtime.main (runtime.go:456)",
				},
				Context: map[string]interface{}{
					"query":    "SELECT * FROM users",
					"duration": "500ms",
				},
			},
			wantAttrs: map[string]interface{}{
				"error.message":          "test database error",
				"error.category":         ErrorCategoryDatabase,
				"error.severity":         ErrorSeverityHigh,
				"error.operation":        "user_lookup",
				"error.user_id":          int64(12345),
				"error.stack_depth":      int64(2), // OpenTelemetry converts int to int64
				"error.stack_top":        "main.TestFunction (test.go:123)",
				"error.context.query":    "SELECT * FROM users",
				"error.context.duration": "500ms",
			},
		},
		{
			name: "minimal error info",
			errorInfo: ErrorInfo{
				Error:     errors.New("simple error"),
				Category:  ErrorCategoryValidation,
				Severity:  ErrorSeverityLow,
				Operation: "validation",
			},
			wantAttrs: map[string]interface{}{
				"error.message":   "simple error",
				"error.category":  ErrorCategoryValidation,
				"error.severity":  ErrorSeverityLow,
				"error.operation": "validation",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test tracer
			exporter := tracetest.NewInMemoryExporter()
			tp := sdktrace.NewTracerProvider(
				sdktrace.WithSyncer(exporter),
			)

			tracer := NewBusinessTracer(BusinessTracerConfig{
				TracerProvider: tp,
				ServiceName:    "test-service",
			})

			// Create span and record error
			ctx, span := tracer.StartSpan(context.Background(), "test-operation")
			tracer.RecordDetailedError(ctx, tt.errorInfo)
			span.End()

			// Get recorded spans
			spans := exporter.GetSpans()
			require.Len(t, spans, 1)

			recordedSpan := spans[0]

			// Check span status
			assert.Equal(t, codes.Error, recordedSpan.Status.Code)
			assert.Equal(t, tt.errorInfo.Error.Error(), recordedSpan.Status.Description)

			// Check attributes
			attrs := make(map[string]interface{})
			for _, attr := range recordedSpan.Attributes {
				attrs[string(attr.Key)] = attr.Value.AsInterface()
			}

			for key, expectedValue := range tt.wantAttrs {
				assert.Equal(t, expectedValue, attrs[key], "attribute %s", key)
			}

			// Check that error was recorded
			assert.Len(t, recordedSpan.Events, 1)
			assert.Equal(t, "exception", recordedSpan.Events[0].Name)
		})
	}
}

func TestBusinessTracer_RecordErrorWithCategory(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		operation    string
		userID       *int64
		wantCategory string
		wantSeverity string
	}{
		{
			name:         "database error",
			err:          errors.New("pgx: connection timeout"),
			operation:    "user_query",
			userID:       &[]int64{123}[0],
			wantCategory: ErrorCategoryDatabase,
			wantSeverity: ErrorSeverityCritical,
		},
		{
			name:         "validation error",
			err:          errors.New("validation failed: invalid email format"),
			operation:    "user_registration",
			wantCategory: ErrorCategoryValidation,
			wantSeverity: ErrorSeverityLow,
		},
		{
			name:         "authentication error",
			err:          errors.New("unauthorized: invalid password"),
			operation:    "login",
			wantCategory: ErrorCategoryAuthentication,
			wantSeverity: ErrorSeverityHigh,
		},
		{
			name:         "network error",
			err:          errors.New("network timeout: connection refused"),
			operation:    "external_api_call",
			wantCategory: ErrorCategoryNetwork,
			wantSeverity: ErrorSeverityHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test tracer
			exporter := tracetest.NewInMemoryExporter()
			tp := sdktrace.NewTracerProvider(
				sdktrace.WithSyncer(exporter),
			)

			tracer := NewBusinessTracer(BusinessTracerConfig{
				TracerProvider: tp,
				ServiceName:    "test-service",
			})

			// Create span and record error
			ctx, span := tracer.StartSpan(context.Background(), "test-operation")
			tracer.RecordErrorWithCategory(ctx, tt.err, tt.operation, tt.userID)
			span.End()

			// Get recorded spans
			spans := exporter.GetSpans()
			require.Len(t, spans, 1)

			recordedSpan := spans[0]

			// Check span status
			assert.Equal(t, codes.Error, recordedSpan.Status.Code)

			// Check attributes
			attrs := make(map[string]interface{})
			for _, attr := range recordedSpan.Attributes {
				attrs[string(attr.Key)] = attr.Value.AsInterface()
			}

			assert.Equal(t, tt.wantCategory, attrs["error.category"])
			assert.Equal(t, tt.wantSeverity, attrs["error.severity"])
			assert.Equal(t, tt.operation, attrs["error.operation"])

			if tt.userID != nil {
				assert.Equal(t, *tt.userID, attrs["error.user_id"])
			}

			// Check that stack trace was captured
			assert.Contains(t, attrs, "error.stack_depth")
			assert.Contains(t, attrs, "error.stack_top")
		})
	}
}

func TestBusinessTracer_CategorizeError(t *testing.T) {
	tracer := NewBusinessTracer(BusinessTracerConfig{})

	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "pgx database error",
			err:      errors.New("pgx: connection failed"),
			expected: ErrorCategoryDatabase,
		},
		{
			name:     "validation error",
			err:      errors.New("validation failed: required field missing"),
			expected: ErrorCategoryValidation,
		},
		{
			name:     "authentication error",
			err:      errors.New("unauthorized access"),
			expected: ErrorCategoryAuthentication,
		},
		{
			name:     "authorization error",
			err:      errors.New("forbidden: access denied"),
			expected: ErrorCategoryAuthorization,
		},
		{
			name:     "network error",
			err:      errors.New("network timeout occurred"),
			expected: ErrorCategoryNetwork,
		},
		{
			name:     "rate limit error",
			err:      errors.New("rate limit exceeded"),
			expected: ErrorCategoryRateLimit,
		},
		{
			name:     "external service error",
			err:      errors.New("external service unavailable"),
			expected: ErrorCategoryExternal,
		},
		{
			name:     "unknown error",
			err:      errors.New("some unknown error"),
			expected: ErrorCategoryInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tracer.categorizeError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBusinessTracer_DetermineSeverity(t *testing.T) {
	tracer := NewBusinessTracer(BusinessTracerConfig{})

	tests := []struct {
		name     string
		err      error
		category string
		expected string
	}{
		{
			name:     "critical database timeout",
			err:      errors.New("database connection timeout"),
			category: ErrorCategoryDatabase,
			expected: ErrorSeverityCritical,
		},
		{
			name:     "panic error",
			err:      errors.New("panic: runtime error"),
			category: ErrorCategoryInternal,
			expected: ErrorSeverityCritical,
		},
		{
			name:     "authentication error",
			err:      errors.New("invalid credentials"),
			category: ErrorCategoryAuthentication,
			expected: ErrorSeverityHigh,
		},
		{
			name:     "network error",
			err:      errors.New("connection refused"),
			category: ErrorCategoryNetwork,
			expected: ErrorSeverityHigh,
		},
		{
			name:     "database error",
			err:      errors.New("query failed"),
			category: ErrorCategoryDatabase,
			expected: ErrorSeverityMedium,
		},
		{
			name:     "validation error",
			err:      errors.New("invalid input"),
			category: ErrorCategoryValidation,
			expected: ErrorSeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tracer.determineSeverity(tt.err, tt.category)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBusinessTracer_CaptureStackTrace(t *testing.T) {
	tracer := NewBusinessTracer(BusinessTracerConfig{})

	stackTrace := tracer.captureStackTrace(1) // Skip 1 frame to get to this test function

	// Should capture at least one frame
	assert.NotEmpty(t, stackTrace)

	// Should contain function name and file info
	assert.Contains(t, stackTrace[0], "TestBusinessTracer_CaptureStackTrace")
	assert.Contains(t, stackTrace[0], "business_tracing_test.go")

	// Should not exceed 10 frames
	assert.LessOrEqual(t, len(stackTrace), 10)
}

func TestGlobalErrorRecordingFunctions(_ *testing.T) {
	// Initialize global tracer
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)

	InitGlobalBusinessTracer(BusinessTracerConfig{
		TracerProvider: tp,
		ServiceName:    "test-service",
	})

	ctx, span := noop.NewTracerProvider().Tracer("test").Start(context.Background(), "test")
	defer span.End()

	// Test global RecordError
	err := errors.New("test error")
	RecordError(ctx, err)

	// Test global RecordErrorWithCategory
	userID := int64(123)
	RecordErrorWithCategory(ctx, err, "test_operation", &userID)

	// Test global RecordDetailedError
	errorInfo := ErrorInfo{
		Error:     err,
		Category:  ErrorCategoryValidation,
		Severity:  ErrorSeverityLow,
		Operation: "test",
	}
	RecordDetailedError(ctx, errorInfo)

	// Functions should not panic and should work with global tracer
	// Detailed verification would require a proper span context
}
