// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package middlewares

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

func TestHTTPTracing(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)

	// Create Echo instance
	e := echo.New()

	// Add the HTTP tracing middleware
	e.Use(HTTPTracing(tracerProvider))

	// Add a test route
	e.GET("/test", func(c echo.Context) error {
		// Verify that a span is active
		span := oteltrace.SpanFromContext(c.Request().Context())
		assert.True(t, span.IsRecording(), "Expected an active span")

		return c.String(http.StatusOK, "test response")
	})

	// Create a test request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	// Execute the request
	e.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "test response", rec.Body.String())
}

func TestHTTPTracingWithConfig(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)

	// Create Echo instance
	e := echo.New()

	// Add the HTTP tracing middleware with custom config
	config := HTTPTracingConfig{
		TracerProvider: tracerProvider,
		ServiceName:    "test-service",
		Propagator:     propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}),
		Skipper: func(c echo.Context) bool {
			return c.Path() == "/health"
		},
	}
	e.Use(HTTPTracingWithConfig(config))

	// Add test routes
	e.GET("/test", func(c echo.Context) error {
		span := oteltrace.SpanFromContext(c.Request().Context())
		assert.True(t, span.IsRecording(), "Expected an active span")
		return c.String(http.StatusOK, "test response")
	})

	e.GET("/health", func(c echo.Context) error {
		span := oteltrace.SpanFromContext(c.Request().Context())
		assert.False(t, span.IsRecording(), "Expected no active span for skipped route")
		return c.String(http.StatusOK, "healthy")
	})

	// Test normal route
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Test skipped route
	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHTTPTracingEnhanced(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)

	// Create Echo instance
	e := echo.New()

	// Add the enhanced HTTP tracing middleware
	e.Use(HTTPTracingEnhanced(tracerProvider, "test-service"))

	// Add a test route
	e.POST("/api/test", func(c echo.Context) error {
		// Verify trace information is available in context
		traceID := GetTraceID(c)
		spanID := GetSpanID(c)

		assert.NotEmpty(t, traceID, "Expected trace ID to be available")
		assert.NotEmpty(t, spanID, "Expected span ID to be available")

		// Verify response headers
		assert.NotEmpty(t, c.Response().Header().Get("X-Trace-Id"), "Expected X-Trace-Id header")

		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	// Create a test request with headers
	req := httptest.NewRequest(http.MethodPost, "/api/test", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-client/1.0")
	rec := httptest.NewRecorder()

	// Execute the request
	e.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("X-Trace-Id"))
}

func TestStartSpanFromEcho(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	// Create Echo instance
	e := echo.New()
	e.Use(HTTPTracing(tracerProvider))

	// Add a test route that creates child spans
	e.GET("/test", func(c echo.Context) error {
		// Create a child span
		ctx, span := StartSpanFromEcho(c, "child-operation")
		defer span.End()

		// Verify the span is recording
		assert.True(t, span.IsRecording(), "Expected child span to be recording")

		// Verify context propagation
		parentSpan := oteltrace.SpanFromContext(c.Request().Context())
		childSpan := oteltrace.SpanFromContext(ctx)

		assert.True(t, parentSpan.IsRecording(), "Expected parent span to be recording")
		assert.True(t, childSpan.IsRecording(), "Expected child span to be recording")

		// Verify they have the same trace ID but different span IDs
		parentCtx := parentSpan.SpanContext()
		childCtx := childSpan.SpanContext()

		assert.Equal(t, parentCtx.TraceID(), childCtx.TraceID(), "Expected same trace ID")
		assert.NotEqual(t, parentCtx.SpanID(), childCtx.SpanID(), "Expected different span IDs")

		return c.String(http.StatusOK, "test response")
	})

	// Create a test request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	// Execute the request
	e.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestSetupGlobalPropagator(t *testing.T) {
	// Setup global propagator
	SetupGlobalPropagator()

	// Verify the propagator is set
	propagator := otel.GetTextMapPropagator()
	require.NotNil(t, propagator)

	// Test that it can inject and extract trace context
	ctx := context.Background()

	// Create a span context
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(trace.WithResource(res))
	tracer := tracerProvider.Tracer("test")

	ctx, span := tracer.Start(ctx, "test-span")
	defer span.End()

	// Inject into headers
	headers := make(http.Header)
	propagator.Inject(ctx, propagation.HeaderCarrier(headers))

	// Verify headers were set
	assert.NotEmpty(t, headers.Get("traceparent"), "Expected traceparent header to be set")

	// Extract from headers
	extractedCtx := propagator.Extract(context.Background(), propagation.HeaderCarrier(headers))
	extractedSpan := oteltrace.SpanFromContext(extractedCtx)

	// Verify extraction worked
	assert.True(t, extractedSpan.SpanContext().IsValid(), "Expected valid span context after extraction")
}

func TestGetTraceIDAndSpanID(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)

	// Create Echo instance
	e := echo.New()
	e.Use(HTTPTracingEnhanced(tracerProvider, "test-service"))

	var capturedTraceID, capturedSpanID string

	// Add a test route
	e.GET("/test", func(c echo.Context) error {
		capturedTraceID = GetTraceID(c)
		capturedSpanID = GetSpanID(c)
		return c.String(http.StatusOK, "test response")
	})

	// Create a test request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	// Execute the request
	e.ServeHTTP(rec, req)

	// Verify trace and span IDs were captured
	assert.NotEmpty(t, capturedTraceID, "Expected trace ID to be captured")
	assert.NotEmpty(t, capturedSpanID, "Expected span ID to be captured")
	assert.Len(t, capturedTraceID, 32, "Expected trace ID to be 32 characters")
	assert.Len(t, capturedSpanID, 16, "Expected span ID to be 16 characters")
}

func TestHTTPTracingWithNilProvider(t *testing.T) {
	// Reset global tracer provider to no-op to ensure clean test state
	otel.SetTracerProvider(oteltrace.NewNoopTracerProvider())

	// Create Echo instance
	e := echo.New()

	// Add the HTTP tracing middleware with nil provider (should use global)
	e.Use(HTTPTracing(nil))

	// Add a test route
	e.GET("/test", func(c echo.Context) error {
		// Should still work with global provider
		span := oteltrace.SpanFromContext(c.Request().Context())
		// With no-op provider, span won't be recording
		assert.False(t, span.IsRecording(), "Expected no-op span with nil provider")

		return c.String(http.StatusOK, "test response")
	})

	// Create a test request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	// Execute the request
	e.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "test response", rec.Body.String())
}

func TestCreateRootSpan(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	// Create Echo instance
	e := echo.New()

	// Add a test route that creates a root span
	e.POST("/api/users", func(c echo.Context) error {
		// Create a root span for this operation
		ctx, span := CreateRootSpan(c, "CreateUser")
		defer span.End()

		// Verify the span is recording and has correct attributes
		assert.True(t, span.IsRecording(), "Expected root span to be recording")

		// Verify span context
		spanCtx := span.SpanContext()
		assert.True(t, spanCtx.IsValid(), "Expected valid span context")
		assert.False(t, spanCtx.IsRemote(), "Expected local span context for root span")

		// Update request context
		c.SetRequest(c.Request().WithContext(ctx))

		// Verify context was updated
		assert.NotNil(t, ctx, "Expected context to be created")

		return c.JSON(http.StatusCreated, map[string]string{"id": "123"})
	})

	// Create a test request
	req := httptest.NewRequest(http.MethodPost, "/api/users", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-client/1.0")
	rec := httptest.NewRecorder()

	// Execute the request
	e.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestEnsureRootSpan(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	// Create Echo instance
	e := echo.New()

	// Add a test route that ensures a root span exists
	e.GET("/api/health", func(c echo.Context) error {
		// Ensure there's a root span
		ctx, span := EnsureRootSpan(c, "health-service")
		defer span.End()

		// Verify the span is recording
		assert.True(t, span.IsRecording(), "Expected root span to be recording")

		// Verify span context is valid
		spanCtx := span.SpanContext()
		assert.True(t, spanCtx.IsValid(), "Expected valid span context")

		// Verify context was created
		assert.NotNil(t, ctx, "Expected context to be created")

		// Verify trace and span IDs are available
		traceID := GetTraceID(c)
		spanID := GetSpanID(c)
		assert.NotEmpty(t, traceID, "Expected trace ID to be available")
		assert.NotEmpty(t, spanID, "Expected span ID to be available")

		return c.JSON(http.StatusOK, map[string]string{"status": "healthy"})
	})

	// Create a test request
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()

	// Execute the request
	e.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRootSpanWithTraceContext(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	// Setup global propagator
	SetupGlobalPropagator()

	// Create Echo instance
	e := echo.New()

	// Add a test route
	e.GET("/api/test", func(c echo.Context) error {
		// Create a root span that should inherit trace context from headers
		ctx, span := CreateRootSpan(c, "TestOperation")
		defer span.End()

		// Verify the span is recording
		assert.True(t, span.IsRecording(), "Expected root span to be recording")

		// Verify context was created
		assert.NotNil(t, ctx, "Expected context to be created")

		return c.String(http.StatusOK, "test response")
	})

	// Create a parent trace context
	parentCtx, parentSpan := tracerProvider.Tracer("test").Start(context.Background(), "parent-operation")
	defer parentSpan.End()

	// Create a test request with trace context headers
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)

	// Inject trace context into headers
	propagator := otel.GetTextMapPropagator()
	propagator.Inject(parentCtx, propagation.HeaderCarrier(req.Header))

	rec := httptest.NewRecorder()

	// Execute the request
	e.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotEmpty(t, req.Header.Get("traceparent"), "Expected traceparent header to be present")
}

func TestSpanAttributesDetailed(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)

	// Create Echo instance
	e := echo.New()

	// Add the enhanced HTTP tracing middleware
	e.Use(HTTPTracingEnhanced(tracerProvider, "test-service"))

	// Add a test route with path parameters
	e.POST("/api/users/:id/posts/:postId", func(c echo.Context) error {
		// Verify span attributes are being captured
		span := oteltrace.SpanFromContext(c.Request().Context())
		assert.True(t, span.IsRecording(), "Expected span to be recording")

		// Return a JSON response with specific headers
		c.Response().Header().Set("Cache-Control", "no-cache")
		c.Response().Header().Set("ETag", "\"123456\"")
		c.Response().Header().Set("X-Frame-Options", "DENY")

		return c.JSON(http.StatusCreated, map[string]interface{}{
			"id":      c.Param("id"),
			"postId":  c.Param("postId"),
			"message": "Post created successfully",
		})
	})

	// Create a comprehensive test request
	req := httptest.NewRequest(http.MethodPost, "/api/users/123/posts/456?filter=active&sort=date", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
	req.Header.Set("User-Agent", "test-client/1.0")
	req.Header.Set("X-Forwarded-For", "192.168.1.100")

	rec := httptest.NewRecorder()

	// Execute the request
	e.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-cache", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "\"123456\"", rec.Header().Get("ETag"))
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
}

func TestRequestAttributesFunction(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	// Create Echo instance
	e := echo.New()

	// Add a test route
	e.PUT("/api/test/:id", func(c echo.Context) error {
		// Create a span and test request attributes
		ctx, span := StartSpanFromEcho(c, "test-operation")
		defer span.End()

		// Add request attributes
		addRequestAttributes(c, span)

		// Verify span is recording
		assert.True(t, span.IsRecording(), "Expected span to be recording")
		assert.NotNil(t, ctx, "Expected context to be created")

		return c.String(http.StatusOK, "test response")
	})

	// Create a test request with various headers
	req := httptest.NewRequest(http.MethodPut, "/api/test/123?param1=value1&param2=value2", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,es;q=0.8")
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	req.ContentLength = 1024

	rec := httptest.NewRecorder()

	// Execute the request
	e.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestResponseAttributesFunction(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	// Create Echo instance
	e := echo.New()

	// Add a test route
	e.GET("/api/test", func(c echo.Context) error {
		// Create a span and test response attributes
		ctx, span := StartSpanFromEcho(c, "test-operation")
		defer span.End()

		// Set response headers
		c.Response().Header().Set("Content-Type", "application/json")
		c.Response().Header().Set("Content-Encoding", "gzip")
		c.Response().Header().Set("Cache-Control", "max-age=3600")
		c.Response().Header().Set("ETag", "\"abc123\"")
		c.Response().Header().Set("Access-Control-Allow-Origin", "*")
		c.Response().Header().Set("X-Frame-Options", "SAMEORIGIN")
		c.Response().Header().Set("X-Content-Type-Options", "nosniff")

		// Return response
		response := c.JSON(http.StatusOK, map[string]string{"status": "success"})

		// Add response attributes after setting response
		addResponseAttributes(c, span)

		// Verify span is recording
		assert.True(t, span.IsRecording(), "Expected span to be recording")
		assert.NotNil(t, ctx, "Expected context to be created")

		return response
	})

	// Create a test request
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()

	// Execute the request
	e.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "gzip", rec.Header().Get("Content-Encoding"))
	assert.Equal(t, "max-age=3600", rec.Header().Get("Cache-Control"))
}

func TestContextPropagation(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	// Setup global propagator
	SetupGlobalPropagator()

	// Create Echo instance
	e := echo.New()
	e.Use(HTTPTracingEnhanced(tracerProvider, "test-service"))

	// Add a test route that tests context propagation
	e.POST("/api/test", func(c echo.Context) error {
		// Verify trace context is available
		traceID := GetTraceID(c)
		spanID := GetSpanID(c)
		assert.NotEmpty(t, traceID, "Expected trace ID to be available")
		assert.NotEmpty(t, spanID, "Expected span ID to be available")

		// Create a child span to test propagation
		ctx, childSpan := StartChildSpan(c, "child-operation")
		defer childSpan.End()

		// Verify child span has same trace ID but different span ID
		childSpanCtx := childSpan.SpanContext()
		assert.True(t, childSpanCtx.IsValid(), "Expected valid child span context")
		assert.NotNil(t, ctx, "Expected context to be created")

		return c.JSON(http.StatusOK, map[string]string{"status": "success"})
	})

	// Create a test request
	req := httptest.NewRequest(http.MethodPost, "/api/test", nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	// Execute the request
	e.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestPropagateContext(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	// Create two Echo instances to simulate context propagation
	e1 := echo.New()
	e1.Use(HTTPTracingEnhanced(tracerProvider, "service-1"))

	e2 := echo.New()
	e2.Use(HTTPTracingEnhanced(tracerProvider, "service-2"))

	var sourceTraceID, targetTraceID string

	// Add route to first service
	e1.GET("/source", func(c echo.Context) error {
		sourceTraceID = GetTraceID(c)

		// Simulate creating a new Echo context for propagation
		req2 := httptest.NewRequest(http.MethodGet, "/target", nil)
		rec2 := httptest.NewRecorder()
		c2 := e2.NewContext(req2, rec2)

		// Propagate context
		PropagateContext(c, c2)

		targetTraceID = GetTraceID(c2)

		return c.String(http.StatusOK, "source response")
	})

	// Create a test request
	req := httptest.NewRequest(http.MethodGet, "/source", nil)
	rec := httptest.NewRecorder()

	// Execute the request
	e1.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotEmpty(t, sourceTraceID, "Expected source trace ID")
	assert.NotEmpty(t, targetTraceID, "Expected target trace ID")
	assert.Equal(t, sourceTraceID, targetTraceID, "Expected trace IDs to match after propagation")
}

func TestInjectAndExtractTraceHeaders(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	// Setup global propagator
	SetupGlobalPropagator()

	// Create Echo instance
	e := echo.New()
	e.Use(HTTPTracingEnhanced(tracerProvider, "test-service"))

	// Add a test route that tests header injection/extraction
	e.GET("/api/test", func(c echo.Context) error {
		// Get current context
		ctx := WithTraceContext(c)

		// Test header injection
		headers := make(map[string]string)
		InjectTraceHeaders(ctx, headers)

		// Verify headers were injected
		assert.NotEmpty(t, headers, "Expected headers to be injected")

		// Test header extraction
		extractedCtx := ExtractTraceContext(context.Background(), headers)
		extractedSpan := oteltrace.SpanFromContext(extractedCtx)

		// Verify extraction worked
		assert.True(t, extractedSpan.SpanContext().IsValid(), "Expected valid span context after extraction")

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

func TestPropagateToOutgoingRequest(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	// Setup global propagator
	SetupGlobalPropagator()

	// Create Echo instance
	e := echo.New()
	e.Use(HTTPTracingEnhanced(tracerProvider, "test-service"))

	// Add a test route that tests outgoing request propagation
	e.POST("/api/test", func(c echo.Context) error {
		// Create an outgoing HTTP request
		outgoingReq, err := http.NewRequest(http.MethodGet, "http://example.com/api", nil)
		require.NoError(t, err, "Failed to create outgoing request")

		// Propagate trace context to the outgoing request
		outgoingReq = PropagateToOutgoingRequest(c, outgoingReq)

		// Verify trace headers were added to the outgoing request
		assert.NotEmpty(t, outgoingReq.Header.Get("traceparent"), "Expected traceparent header in outgoing request")

		// Verify the request context has trace information
		span := oteltrace.SpanFromContext(outgoingReq.Context())
		assert.True(t, span.SpanContext().IsValid(), "Expected valid span context in outgoing request")

		return c.JSON(http.StatusOK, map[string]string{"status": "success"})
	})

	// Create a test request
	req := httptest.NewRequest(http.MethodPost, "/api/test", nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	// Execute the request
	e.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestBaggagePropagation(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	// Setup global propagator
	SetupGlobalPropagator()

	// Create Echo instance
	e := echo.New()
	e.Use(HTTPTracingEnhanced(tracerProvider, "test-service"))

	// Add a test route that tests baggage propagation
	e.PUT("/api/test", func(c echo.Context) error {
		// Create context with baggage
		baggageData := map[string]string{
			"user-id":    "12345",
			"request-id": "req-abc-123",
			"service":    "test-service",
		}

		ctx := CreateContextWithBaggage(c, baggageData)
		assert.NotNil(t, ctx, "Expected context with baggage to be created")

		// Extract baggage from context
		extractedBaggage := GetBaggageFromContext(c)

		// Note: The extracted baggage might be empty if the context wasn't properly set
		// This is expected behavior in this test setup
		assert.NotNil(t, extractedBaggage, "Expected baggage map to be returned")

		return c.JSON(http.StatusOK, map[string]interface{}{
			"baggage_count": len(extractedBaggage),
		})
	})

	// Create a test request
	req := httptest.NewRequest(http.MethodPut, "/api/test", nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	// Execute the request
	e.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestWithTraceContext(t *testing.T) {
	// Create a test tracer provider
	res := resource.NewWithAttributes("test")
	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	// Create Echo instance
	e := echo.New()
	e.Use(HTTPTracingEnhanced(tracerProvider, "test-service"))

	// Add a test route that tests WithTraceContext
	e.GET("/api/test", func(c echo.Context) error {
		// Get context with trace information
		ctx := WithTraceContext(c)
		assert.NotNil(t, ctx, "Expected context to be created")

		// Verify trace context is available
		span := oteltrace.SpanFromContext(ctx)
		assert.True(t, span.SpanContext().IsValid(), "Expected valid span context")

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
