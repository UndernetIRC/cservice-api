// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package middlewares

import (
	"context"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// HTTPTracingConfig holds configuration for HTTP tracing middleware
type HTTPTracingConfig struct {
	// Skipper defines a function to skip middleware
	Skipper func(echo.Context) bool
	// TracerProvider is the OpenTelemetry tracer provider
	TracerProvider trace.TracerProvider
	// ServiceName is used for span naming and attributes
	ServiceName string
	// Propagator is used for trace context propagation
	Propagator propagation.TextMapPropagator
}

// DefaultHTTPTracingConfig provides default configuration
var DefaultHTTPTracingConfig = HTTPTracingConfig{
	Skipper:     func(echo.Context) bool { return false },
	ServiceName: "cservice-api",
}

// HTTPTracing returns a middleware that instruments HTTP requests with OpenTelemetry tracing
func HTTPTracing(tracerProvider trace.TracerProvider) echo.MiddlewareFunc {
	return HTTPTracingWithConfig(HTTPTracingConfig{
		Skipper:        DefaultHTTPTracingConfig.Skipper,
		TracerProvider: tracerProvider,
		ServiceName:    DefaultHTTPTracingConfig.ServiceName,
		Propagator:     otel.GetTextMapPropagator(),
	})
}

// HTTPTracingWithConfig returns a middleware with custom configuration
func HTTPTracingWithConfig(config HTTPTracingConfig) echo.MiddlewareFunc {
	// Set defaults
	if config.Skipper == nil {
		config.Skipper = DefaultHTTPTracingConfig.Skipper
	}
	if config.ServiceName == "" {
		config.ServiceName = DefaultHTTPTracingConfig.ServiceName
	}
	if config.Propagator == nil {
		config.Propagator = otel.GetTextMapPropagator()
	}
	if config.TracerProvider == nil {
		config.TracerProvider = otel.GetTracerProvider()
	}

	// Use otelecho middleware as the base, but with custom configuration
	return otelecho.Middleware(
		config.ServiceName,
		otelecho.WithTracerProvider(config.TracerProvider),
		otelecho.WithPropagators(config.Propagator),
		otelecho.WithSkipper(func(c echo.Context) bool {
			return config.Skipper(c)
		}),
	)
}

// HTTPTracingEnhanced returns an enhanced tracing middleware that adds custom attributes and log correlation
func HTTPTracingEnhanced(tracerProvider trace.TracerProvider, serviceName string) echo.MiddlewareFunc {
	// First apply the base otelecho middleware
	baseMiddleware := HTTPTracingWithConfig(HTTPTracingConfig{
		TracerProvider: tracerProvider,
		ServiceName:    serviceName,
		Propagator:     otel.GetTextMapPropagator(),
	})

	// Then add our custom enhancement middleware
	enhancementMiddleware := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get or create the root span for this HTTP request
			span := trace.SpanFromContext(c.Request().Context())
			if !span.IsRecording() {
				return next(c)
			}

			// Ensure this is properly configured as a root span for HTTP requests
			configureRootSpan(c, span, serviceName)

			// Add custom attributes to the span
			addCustomSpanAttributes(c, span)

			// Store trace information in context for log correlation
			addTraceInfoToContext(c, span)

			// Execute the handler
			err := next(c)

			// Add response attributes after handler execution
			addResponseAttributes(c, span)

			// Record error in span if present
			if err != nil {
				recordErrorInSpan(span, err)
			}

			return err
		}
	}

	// Combine both middlewares
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return baseMiddleware(enhancementMiddleware(next))
	}
}

// configureRootSpan configures the span as a proper HTTP root span
func configureRootSpan(c echo.Context, span trace.Span, serviceName string) {
	req := c.Request()

	// Set the span name to follow HTTP semantic conventions
	// Format: HTTP {method} {route}
	spanName := fmt.Sprintf("HTTP %s", req.Method)
	if route := c.Path(); route != "" {
		spanName = fmt.Sprintf("HTTP %s %s", req.Method, route)
	}
	span.SetName(spanName)

	// Add root span specific attributes
	span.SetAttributes(
		attribute.String("span.kind", "server"),
		attribute.String("service.name", serviceName),
		attribute.String("http.server.name", serviceName),
		attribute.Bool("http.request.is_root", true),
	)

	// Add request timing information
	span.SetAttributes(
		attribute.String("http.request.received_at", req.Header.Get("Date")),
	)
}

// addCustomSpanAttributes adds custom attributes to the span (request-time attributes only)
func addCustomSpanAttributes(c echo.Context, span trace.Span) {
	req := c.Request()

	// Add standard HTTP attributes that might not be covered by otelecho
	span.SetAttributes(
		attribute.String("http.user_agent", req.UserAgent()),
		attribute.String("http.client_ip", c.RealIP()),
		attribute.String("http.request_id", c.Response().Header().Get(echo.HeaderXRequestID)),
	)

	// Add custom application attributes
	span.SetAttributes(
		attribute.String("service.name", "cservice-api"),
		attribute.String("service.component", "http"),
	)

	// Add route information if available
	if route := c.Path(); route != "" {
		span.SetAttributes(
			attribute.String("http.route", route),
		)
	}

	// Add detailed request attributes
	addRequestAttributes(c, span)
}

// addRequestAttributes adds detailed request attributes to the span
func addRequestAttributes(c echo.Context, span trace.Span) {
	req := c.Request()

	// Content type and encoding
	if contentType := req.Header.Get("Content-Type"); contentType != "" {
		span.SetAttributes(
			attribute.String("http.request.content_type", contentType),
		)
	}

	if contentEncoding := req.Header.Get("Content-Encoding"); contentEncoding != "" {
		span.SetAttributes(
			attribute.String("http.request.content_encoding", contentEncoding),
		)
	}

	// Content length
	if req.ContentLength > 0 {
		span.SetAttributes(
			attribute.Int64("http.request.content_length", req.ContentLength),
		)
	}

	// Request headers (selective)
	if accept := req.Header.Get("Accept"); accept != "" {
		span.SetAttributes(
			attribute.String("http.request.accept", accept),
		)
	}

	if acceptEncoding := req.Header.Get("Accept-Encoding"); acceptEncoding != "" {
		span.SetAttributes(
			attribute.String("http.request.accept_encoding", acceptEncoding),
		)
	}

	if acceptLanguage := req.Header.Get("Accept-Language"); acceptLanguage != "" {
		span.SetAttributes(
			attribute.String("http.request.accept_language", acceptLanguage),
		)
	}

	// Authentication related headers (without sensitive data)
	if authType := req.Header.Get("Authorization"); authType != "" {
		// Only capture the auth type, not the actual token
		if len(authType) > 6 && authType[:6] == "Bearer" {
			span.SetAttributes(
				attribute.String("http.request.auth_type", "Bearer"),
			)
		} else if len(authType) > 5 && authType[:5] == "Basic" {
			span.SetAttributes(
				attribute.String("http.request.auth_type", "Basic"),
			)
		} else {
			span.SetAttributes(
				attribute.String("http.request.auth_type", "Other"),
			)
		}
	}

	// Request timing
	span.SetAttributes(
		attribute.String("http.request.timestamp", req.Header.Get("Date")),
	)

	// Protocol information
	span.SetAttributes(
		attribute.String("http.protocol", req.Proto),
		attribute.Int("http.protocol_version_major", req.ProtoMajor),
		attribute.Int("http.protocol_version_minor", req.ProtoMinor),
	)

	// Query parameters count (without exposing actual values)
	if queryParams := req.URL.Query(); len(queryParams) > 0 {
		span.SetAttributes(
			attribute.Int("http.request.query_params_count", len(queryParams)),
		)
	}

	// Request path parameters (if available from Echo)
	if paramNames := c.ParamNames(); len(paramNames) > 0 {
		span.SetAttributes(
			attribute.Int("http.request.path_params_count", len(paramNames)),
		)
		// Add parameter names (not values for security)
		span.SetAttributes(
			attribute.StringSlice("http.request.path_param_names", paramNames),
		)
	}
}

// addResponseAttributes adds response attributes to the span
func addResponseAttributes(c echo.Context, span trace.Span) {
	res := c.Response()

	// Response status code (will be set after handler execution)
	span.SetAttributes(
		attribute.Int("http.response.status_code", res.Status),
	)

	// Response content type
	if contentType := res.Header().Get("Content-Type"); contentType != "" {
		span.SetAttributes(
			attribute.String("http.response.content_type", contentType),
		)
	}

	// Response content encoding
	if contentEncoding := res.Header().Get("Content-Encoding"); contentEncoding != "" {
		span.SetAttributes(
			attribute.String("http.response.content_encoding", contentEncoding),
		)
	}

	// Response size
	if res.Size > 0 {
		span.SetAttributes(
			attribute.Int64("http.response.content_length", res.Size),
		)
	}

	// Cache related headers
	if cacheControl := res.Header().Get("Cache-Control"); cacheControl != "" {
		span.SetAttributes(
			attribute.String("http.response.cache_control", cacheControl),
		)
	}

	if etag := res.Header().Get("ETag"); etag != "" {
		span.SetAttributes(
			attribute.String("http.response.etag", etag),
		)
	}

	// CORS headers
	if corsOrigin := res.Header().Get("Access-Control-Allow-Origin"); corsOrigin != "" {
		span.SetAttributes(
			attribute.String("http.response.cors_origin", corsOrigin),
		)
	}

	// Security headers
	if xFrameOptions := res.Header().Get("X-Frame-Options"); xFrameOptions != "" {
		span.SetAttributes(
			attribute.String("http.response.x_frame_options", xFrameOptions),
		)
	}

	if xContentTypeOptions := res.Header().Get("X-Content-Type-Options"); xContentTypeOptions != "" {
		span.SetAttributes(
			attribute.String("http.response.x_content_type_options", xContentTypeOptions),
		)
	}

	// Response timing information
	if res.Header().Get("Date") != "" {
		span.SetAttributes(
			attribute.String("http.response.timestamp", res.Header().Get("Date")),
		)
	}
}

// addTraceInfoToContext stores trace information in the Echo context for log correlation
func addTraceInfoToContext(c echo.Context, span trace.Span) {
	spanContext := span.SpanContext()
	if spanContext.IsValid() {
		// Store trace and span IDs for log correlation
		c.Set("trace.id", spanContext.TraceID().String())
		c.Set("span.id", spanContext.SpanID().String())
		c.Set("trace.flags", spanContext.TraceFlags().String())

		// Also set in response headers for debugging (optional)
		c.Response().Header().Set("X-Trace-Id", spanContext.TraceID().String())
	}
}

// recordErrorInSpan records an error in the span with appropriate status
func recordErrorInSpan(span trace.Span, err error) {
	span.RecordError(err)

	// Set span status based on error type
	if echoErr, ok := err.(*echo.HTTPError); ok {
		// For HTTP errors, set status based on status code
		if echoErr.Code >= 500 {
			span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d: %v", echoErr.Code, echoErr.Message))
		} else {
			// 4xx errors are not considered span errors in OpenTelemetry
			span.SetStatus(codes.Unset, "")
		}

		// Add HTTP status code as attribute
		span.SetAttributes(
			attribute.Int("http.status_code", echoErr.Code),
		)
	} else {
		// For other errors, mark as error
		span.SetStatus(codes.Error, err.Error())
	}
}

// StartSpan creates a new child span from the current context
func StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	tracer := otel.Tracer("cservice-api")
	return tracer.Start(ctx, name, opts...)
}

// StartSpanFromEcho creates a new child span from the Echo context
func StartSpanFromEcho(c echo.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return StartSpan(c.Request().Context(), name, opts...)
}

// GetTraceID returns the trace ID from the Echo context
func GetTraceID(c echo.Context) string {
	if traceID, ok := c.Get("trace.id").(string); ok {
		return traceID
	}

	// Fallback: extract from current span
	span := trace.SpanFromContext(c.Request().Context())
	if span.SpanContext().IsValid() {
		return span.SpanContext().TraceID().String()
	}

	return ""
}

// GetSpanID returns the span ID from the Echo context
func GetSpanID(c echo.Context) string {
	if spanID, ok := c.Get("span.id").(string); ok {
		return spanID
	}

	// Fallback: extract from current span
	span := trace.SpanFromContext(c.Request().Context())
	if span.SpanContext().IsValid() {
		return span.SpanContext().SpanID().String()
	}

	return ""
}

// CreateRootSpan creates a new root span for HTTP requests
func CreateRootSpan(c echo.Context, operationName string) (context.Context, trace.Span) {
	tracer := otel.Tracer("cservice-api")
	req := c.Request()

	// Extract any existing trace context from headers
	ctx := otel.GetTextMapPropagator().Extract(req.Context(), propagation.HeaderCarrier(req.Header))

	// Create span with SERVER kind to indicate this is a root span for incoming requests
	ctx, span := tracer.Start(ctx, operationName,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			attribute.String("http.method", req.Method),
			attribute.String("http.url", req.URL.String()),
			attribute.String("http.scheme", req.URL.Scheme),
			attribute.String("http.host", req.Host),
			attribute.String("http.target", req.URL.Path),
			attribute.String("http.user_agent", req.UserAgent()),
			attribute.String("http.client_ip", c.RealIP()),
			attribute.Bool("http.request.is_root", true),
		),
	)

	return ctx, span
}

// EnsureRootSpan ensures there's a root span for the HTTP request, creating one if needed
func EnsureRootSpan(c echo.Context, serviceName string) (context.Context, trace.Span) {
	// Check if there's already an active span
	existingSpan := trace.SpanFromContext(c.Request().Context())
	if existingSpan.IsRecording() {
		// Configure the existing span as a root span
		configureRootSpan(c, existingSpan, serviceName)
		return c.Request().Context(), existingSpan
	}

	// Create a new root span
	operationName := fmt.Sprintf("HTTP %s %s", c.Request().Method, c.Path())
	ctx, span := CreateRootSpan(c, operationName)

	// Update the request context
	c.SetRequest(c.Request().WithContext(ctx))

	return ctx, span
}

// PropagateContext propagates trace context from one Echo context to another
func PropagateContext(from echo.Context, to echo.Context) {
	// Get the trace context from the source
	sourceCtx := from.Request().Context()

	// Update the target request with the propagated context
	to.SetRequest(to.Request().WithContext(sourceCtx))

	// Also copy trace information stored in Echo context
	if traceID, ok := from.Get("trace.id").(string); ok {
		to.Set("trace.id", traceID)
	}
	if spanID, ok := from.Get("span.id").(string); ok {
		to.Set("span.id", spanID)
	}
	if traceFlags, ok := from.Get("trace.flags").(string); ok {
		to.Set("trace.flags", traceFlags)
	}
}

// InjectTraceHeaders injects trace context into HTTP headers for outgoing requests
func InjectTraceHeaders(ctx context.Context, headers map[string]string) {
	// Create a header carrier for injection
	carrier := make(propagation.MapCarrier)

	// Inject trace context into the carrier
	otel.GetTextMapPropagator().Inject(ctx, carrier)

	// Copy the injected headers to the provided map
	for key, value := range carrier {
		headers[key] = value
	}
}

// ExtractTraceContext extracts trace context from HTTP headers
func ExtractTraceContext(ctx context.Context, headers map[string]string) context.Context {
	// Create a header carrier from the headers map
	carrier := propagation.MapCarrier(headers)

	// Extract trace context from the carrier
	return otel.GetTextMapPropagator().Extract(ctx, carrier)
}

// WithTraceContext creates a new context with trace information from Echo context
func WithTraceContext(c echo.Context) context.Context {
	// Start with the request context which should already have trace information
	ctx := c.Request().Context()

	// Verify that trace context is present
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		// If no valid span context, try to create one from stored trace info
		if _, ok := c.Get("trace.id").(string); ok {
			if _, ok := c.Get("span.id").(string); ok {
				// Note: This is a simplified approach. In practice, you might want to
				// create a proper span context from the stored IDs
				ctx = trace.ContextWithSpanContext(ctx, trace.SpanContext{})
			}
		}
	}

	return ctx
}

// StartChildSpan creates a child span from the current Echo context
func StartChildSpan(c echo.Context, operationName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	// Get the current context with trace information
	ctx := WithTraceContext(c)

	// Create a child span
	tracer := otel.Tracer("cservice-api")
	return tracer.Start(ctx, operationName, opts...)
}

// PropagateToOutgoingRequest propagates trace context to an outgoing HTTP request
func PropagateToOutgoingRequest(c echo.Context, req *http.Request) *http.Request {
	// Get the current context with trace information
	ctx := WithTraceContext(c)

	// Update the outgoing request context
	req = req.WithContext(ctx)

	// Inject trace headers into the outgoing request
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	return req
}

// CreateContextWithBaggage creates a context with baggage for cross-service communication
func CreateContextWithBaggage(c echo.Context, baggageMap map[string]string) context.Context {
	ctx := WithTraceContext(c)

	// Add baggage to the context
	for key, value := range baggageMap {
		member, err := baggage.NewMember(key, value)
		if err != nil {
			continue // Skip invalid baggage members
		}
		bag, err := baggage.New(member)
		if err != nil {
			continue
		}
		ctx = baggage.ContextWithBaggage(ctx, bag)
	}

	return ctx
}

// GetBaggageFromContext extracts baggage from the current context
func GetBaggageFromContext(c echo.Context) map[string]string {
	ctx := WithTraceContext(c)
	bag := baggage.FromContext(ctx)

	result := make(map[string]string)
	for _, member := range bag.Members() {
		result[member.Key()] = member.Value()
	}

	return result
}

// SetupGlobalPropagator configures the global trace propagator
func SetupGlobalPropagator() {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
}
