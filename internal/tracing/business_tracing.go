// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

// Package tracing provides business-specific distributed tracing utilities
package tracing

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// ErrorInfo contains detailed information about an error for tracing
type ErrorInfo struct {
	Error      error
	Category   string
	Severity   string
	UserID     *int64
	Operation  string
	StackTrace []string
	Context    map[string]interface{}
}

// ErrorCategory constants for categorizing errors
const (
	ErrorCategoryValidation     = "validation"
	ErrorCategoryDatabase       = "database"
	ErrorCategoryAuthentication = "authentication"
	ErrorCategoryAuthorization  = "authorization"
	ErrorCategoryExternal       = "external_service"
	ErrorCategoryInternal       = "internal"
	ErrorCategoryNetwork        = "network"
	ErrorCategoryTimeout        = "timeout"
	ErrorCategoryRateLimit      = "rate_limit"
	ErrorCategoryBusiness       = "business_logic"
)

// ErrorSeverity constants for error severity levels
const (
	ErrorSeverityLow      = "low"
	ErrorSeverityMedium   = "medium"
	ErrorSeverityHigh     = "high"
	ErrorSeverityCritical = "critical"
)

// BusinessTracer provides tracing utilities for business logic operations
type BusinessTracer struct {
	tracer      trace.Tracer
	serviceName string
}

// BusinessTracerConfig holds configuration for business tracing
type BusinessTracerConfig struct {
	TracerProvider trace.TracerProvider
	ServiceName    string
}

// NewBusinessTracer creates a new business tracer
func NewBusinessTracer(config BusinessTracerConfig) *BusinessTracer {
	if config.TracerProvider == nil {
		config.TracerProvider = otel.GetTracerProvider()
	}

	if config.ServiceName == "" {
		config.ServiceName = "cservice-api"
	}

	tracer := config.TracerProvider.Tracer(
		"business-logic",
		trace.WithInstrumentationVersion("1.0.0"),
		trace.WithSchemaURL("https://opentelemetry.io/schemas/1.21.0"),
	)

	return &BusinessTracer{
		tracer:      tracer,
		serviceName: config.ServiceName,
	}
}

// TraceOperation wraps a business operation with tracing
func (bt *BusinessTracer) TraceOperation(ctx context.Context, operationName string, f func(context.Context) error) error {
	ctx, span := bt.tracer.Start(ctx, operationName, trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	// Add service attributes
	span.SetAttributes(
		attribute.String("service.name", bt.serviceName),
		attribute.String("service.component", "business-logic"),
		attribute.String("operation.name", operationName),
	)

	// Execute the operation
	err := f(ctx)

	// Record the result
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.Bool("operation.success", false))
	} else {
		span.SetStatus(codes.Ok, "")
		span.SetAttributes(attribute.Bool("operation.success", true))
	}

	return err
}

// TraceUserRegistration traces user registration operations
func (bt *BusinessTracer) TraceUserRegistration(ctx context.Context, username, email string, stage string, f func(context.Context) error) error {
	operationName := fmt.Sprintf("UserRegistration.%s", stage)
	ctx, span := bt.tracer.Start(ctx, operationName, trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	// Add user registration specific attributes
	span.SetAttributes(
		attribute.String("service.name", bt.serviceName),
		attribute.String("service.component", "user-registration"),
		attribute.String("user.username", username),
		attribute.String("user.email", email),
		attribute.String("registration.stage", stage),
		attribute.String("operation.type", "user_registration"),
	)

	// Execute the operation
	start := time.Now()
	err := f(ctx)
	duration := time.Since(start)

	// Record timing and result
	span.SetAttributes(
		attribute.Int64("operation.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(
			attribute.Bool("registration.success", false),
			attribute.String("registration.failure_reason", err.Error()),
		)
	} else {
		span.SetStatus(codes.Ok, "")
		span.SetAttributes(attribute.Bool("registration.success", true))
	}

	return err
}

// TraceUserActivation traces user activation operations
func (bt *BusinessTracer) TraceUserActivation(ctx context.Context, username, token string, f func(context.Context) error) error {
	operationName := "UserActivation"
	ctx, span := bt.tracer.Start(ctx, operationName, trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	// Add user activation specific attributes
	span.SetAttributes(
		attribute.String("service.name", bt.serviceName),
		attribute.String("service.component", "user-activation"),
		attribute.String("user.username", username),
		attribute.String("activation.token_length", fmt.Sprintf("%d", len(token))),
		attribute.String("operation.type", "user_activation"),
	)

	// Execute the operation
	start := time.Now()
	err := f(ctx)
	duration := time.Since(start)

	// Record timing and result
	span.SetAttributes(
		attribute.Int64("operation.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(
			attribute.Bool("activation.success", false),
			attribute.String("activation.failure_reason", err.Error()),
		)
	} else {
		span.SetStatus(codes.Ok, "")
		span.SetAttributes(attribute.Bool("activation.success", true))
	}

	return err
}

// TraceChannelOperation traces channel-related operations
func (bt *BusinessTracer) TraceChannelOperation(ctx context.Context, channelID int32, userID int32, operation string, f func(context.Context) error) error {
	operationName := fmt.Sprintf("ChannelOperation.%s", operation)
	ctx, span := bt.tracer.Start(ctx, operationName, trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	// Add channel operation specific attributes
	span.SetAttributes(
		attribute.String("service.name", bt.serviceName),
		attribute.String("service.component", "channel-operations"),
		attribute.Int64("channel.id", int64(channelID)),
		attribute.Int64("user.id", int64(userID)),
		attribute.String("channel.operation", operation),
		attribute.String("operation.type", "channel_operation"),
	)

	// Execute the operation
	start := time.Now()
	err := f(ctx)
	duration := time.Since(start)

	// Record timing and result
	span.SetAttributes(
		attribute.Int64("operation.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(
			attribute.Bool("operation.success", false),
			attribute.String("operation.failure_reason", err.Error()),
		)
	} else {
		span.SetStatus(codes.Ok, "")
		span.SetAttributes(attribute.Bool("operation.success", true))
	}

	return err
}

// TraceChannelSearch traces channel search operations
func (bt *BusinessTracer) TraceChannelSearch(ctx context.Context, userID int32, query string, f func(context.Context) (int, error)) (int, error) {
	operationName := "ChannelSearch"
	ctx, span := bt.tracer.Start(ctx, operationName, trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	// Add channel search specific attributes
	span.SetAttributes(
		attribute.String("service.name", bt.serviceName),
		attribute.String("service.component", "channel-search"),
		attribute.Int64("user.id", int64(userID)),
		attribute.String("search.query", query),
		attribute.String("search.query_type", getQueryType(query)),
		attribute.String("operation.type", "channel_search"),
	)

	// Execute the operation
	start := time.Now()
	resultCount, err := f(ctx)
	duration := time.Since(start)

	// Record timing and result
	span.SetAttributes(
		attribute.Int64("operation.duration_ms", duration.Milliseconds()),
		attribute.Int("search.result_count", resultCount),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(
			attribute.Bool("search.success", false),
			attribute.String("search.failure_reason", err.Error()),
		)
	} else {
		span.SetStatus(codes.Ok, "")
		span.SetAttributes(attribute.Bool("search.success", true))
	}

	return resultCount, err
}

// TraceAuthentication traces authentication operations
func (bt *BusinessTracer) TraceAuthentication(ctx context.Context, username string, authType string, f func(context.Context) error) error {
	operationName := fmt.Sprintf("Authentication.%s", authType)
	ctx, span := bt.tracer.Start(ctx, operationName, trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	// Add authentication specific attributes
	span.SetAttributes(
		attribute.String("service.name", bt.serviceName),
		attribute.String("service.component", "authentication"),
		attribute.String("user.username", username),
		attribute.String("auth.type", authType),
		attribute.String("operation.type", "authentication"),
	)

	// Execute the operation
	start := time.Now()
	err := f(ctx)
	duration := time.Since(start)

	// Record timing and result
	span.SetAttributes(
		attribute.Int64("operation.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(
			attribute.Bool("auth.success", false),
			attribute.String("auth.failure_reason", err.Error()),
		)
	} else {
		span.SetStatus(codes.Ok, "")
		span.SetAttributes(attribute.Bool("auth.success", true))
	}

	return err
}

// TraceBusinessTransaction traces multi-step business transactions
func (bt *BusinessTracer) TraceBusinessTransaction(ctx context.Context, transactionName string, f func(context.Context) error) error {
	operationName := fmt.Sprintf("BusinessTransaction.%s", transactionName)
	ctx, span := bt.tracer.Start(ctx, operationName, trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	// Add transaction specific attributes
	span.SetAttributes(
		attribute.String("service.name", bt.serviceName),
		attribute.String("service.component", "business-transaction"),
		attribute.String("transaction.name", transactionName),
		attribute.String("operation.type", "business_transaction"),
	)

	// Execute the transaction
	start := time.Now()
	err := f(ctx)
	duration := time.Since(start)

	// Record timing and result
	span.SetAttributes(
		attribute.Int64("transaction.duration_ms", duration.Milliseconds()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(
			attribute.Bool("transaction.success", false),
			attribute.String("transaction.failure_reason", err.Error()),
		)
	} else {
		span.SetStatus(codes.Ok, "")
		span.SetAttributes(attribute.Bool("transaction.success", true))
	}

	return err
}

// StartSpan creates a new child span for business operations
func (bt *BusinessTracer) StartSpan(ctx context.Context, operationName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	// Add default options for business logic spans
	defaultOpts := []trace.SpanStartOption{
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("service.name", bt.serviceName),
			attribute.String("service.component", "business-logic"),
		),
	}

	// Combine default options with provided options
	allOpts := append(defaultOpts, opts...)

	return bt.tracer.Start(ctx, operationName, allOpts...)
}

// RecordError records an error in the current span
func (bt *BusinessTracer) RecordError(ctx context.Context, err error) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
}

// RecordDetailedError records an error with detailed information in the current span
func (bt *BusinessTracer) RecordDetailedError(ctx context.Context, errorInfo ErrorInfo) {
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}

	// Record the basic error
	span.RecordError(errorInfo.Error)
	span.SetStatus(codes.Error, errorInfo.Error.Error())

	// Add detailed error attributes
	attrs := []attribute.KeyValue{
		attribute.String("error.message", errorInfo.Error.Error()),
		attribute.String("error.category", errorInfo.Category),
		attribute.String("error.severity", errorInfo.Severity),
		attribute.String("error.operation", errorInfo.Operation),
		attribute.String("error.type", fmt.Sprintf("%T", errorInfo.Error)),
	}

	// Add user ID if provided
	if errorInfo.UserID != nil {
		attrs = append(attrs, attribute.Int64("error.user_id", *errorInfo.UserID))
	}

	// Add stack trace information
	if len(errorInfo.StackTrace) > 0 {
		attrs = append(attrs,
			attribute.Int("error.stack_depth", len(errorInfo.StackTrace)),
			attribute.String("error.stack_top", errorInfo.StackTrace[0]),
		)

		// Add first few stack frames for debugging
		for i, frame := range errorInfo.StackTrace {
			if i >= 5 { // Limit to first 5 frames to avoid too much data
				break
			}
			attrs = append(attrs, attribute.String(fmt.Sprintf("error.stack.%d", i), frame))
		}
	}

	// Add context information
	for key, value := range errorInfo.Context {
		attrs = append(attrs, attribute.String(fmt.Sprintf("error.context.%s", key), fmt.Sprintf("%v", value)))
	}

	span.SetAttributes(attrs...)
}

// RecordErrorWithCategory records an error with automatic categorization
func (bt *BusinessTracer) RecordErrorWithCategory(ctx context.Context, err error, operation string, userID *int64) {
	category := bt.categorizeError(err)
	severity := bt.determineSeverity(err, category)
	stackTrace := bt.captureStackTrace(2) // Skip 2 frames to get to the caller

	errorInfo := ErrorInfo{
		Error:      err,
		Category:   category,
		Severity:   severity,
		UserID:     userID,
		Operation:  operation,
		StackTrace: stackTrace,
		Context:    make(map[string]interface{}),
	}

	bt.RecordDetailedError(ctx, errorInfo)
}

// categorizeError automatically categorizes an error based on its type and message
func (bt *BusinessTracer) categorizeError(err error) string {
	if err == nil {
		return ErrorCategoryInternal
	}

	errMsg := strings.ToLower(err.Error())
	errType := fmt.Sprintf("%T", err)

	// Database errors - check type first, then specific database-related messages
	if strings.Contains(errType, "pgx") || strings.Contains(errType, "sql") ||
		strings.Contains(errMsg, "database") || strings.Contains(errMsg, "pgx:") ||
		(strings.Contains(errMsg, "connection") && strings.Contains(errMsg, "timeout") && strings.Contains(errMsg, "pgx")) {
		return ErrorCategoryDatabase
	}

	// Authentication errors - check before general validation
	if strings.Contains(errMsg, "unauthorized") || strings.Contains(errMsg, "authentication") ||
		strings.Contains(errMsg, "login") ||
		(strings.Contains(errMsg, "password") && !strings.Contains(errMsg, "validation")) ||
		(strings.Contains(errMsg, "token") && !strings.Contains(errMsg, "validation")) {
		return ErrorCategoryAuthentication
	}

	// Authorization errors
	if strings.Contains(errMsg, "forbidden") || strings.Contains(errMsg, "permission") ||
		strings.Contains(errMsg, "access denied") || strings.Contains(errMsg, "not allowed") {
		return ErrorCategoryAuthorization
	}

	// Network/timeout errors - be more specific to avoid conflicts
	if (strings.Contains(errMsg, "network") && strings.Contains(errMsg, "timeout")) ||
		strings.Contains(errMsg, "connection refused") || strings.Contains(errMsg, "unreachable") ||
		(strings.Contains(errMsg, "network") && !strings.Contains(errMsg, "database")) {
		return ErrorCategoryNetwork
	}

	// Validation errors
	if strings.Contains(errMsg, "validation") || strings.Contains(errMsg, "invalid") ||
		strings.Contains(errMsg, "required") || strings.Contains(errMsg, "format") {
		return ErrorCategoryValidation
	}

	// Rate limiting errors
	if strings.Contains(errMsg, "rate limit") || strings.Contains(errMsg, "too many requests") ||
		strings.Contains(errMsg, "throttle") {
		return ErrorCategoryRateLimit
	}

	// External service errors
	if strings.Contains(errMsg, "external") || strings.Contains(errMsg, "service unavailable") ||
		strings.Contains(errMsg, "bad gateway") {
		return ErrorCategoryExternal
	}

	// Default to internal error
	return ErrorCategoryInternal
}

// determineSeverity determines the severity of an error based on its category and content
func (bt *BusinessTracer) determineSeverity(err error, category string) string {
	if err == nil {
		return ErrorSeverityLow
	}

	errMsg := strings.ToLower(err.Error())

	// Critical errors
	if category == ErrorCategoryDatabase && (strings.Contains(errMsg, "connection") || strings.Contains(errMsg, "timeout")) {
		return ErrorSeverityCritical
	}
	if strings.Contains(errMsg, "panic") || strings.Contains(errMsg, "fatal") {
		return ErrorSeverityCritical
	}

	// High severity errors
	if category == ErrorCategoryAuthentication || category == ErrorCategoryAuthorization {
		return ErrorSeverityHigh
	}
	if category == ErrorCategoryExternal || category == ErrorCategoryNetwork {
		return ErrorSeverityHigh
	}

	// Medium severity errors
	if category == ErrorCategoryDatabase || category == ErrorCategoryBusiness {
		return ErrorSeverityMedium
	}

	// Low severity errors (validation, etc.)
	return ErrorSeverityLow
}

// captureStackTrace captures the current stack trace
func (bt *BusinessTracer) captureStackTrace(skip int) []string {
	var stackTrace []string

	// Capture up to 10 stack frames
	for i := skip; i < skip+10; i++ {
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}

		fn := runtime.FuncForPC(pc)
		if fn == nil {
			continue
		}

		// Format: function_name (file:line)
		frame := fmt.Sprintf("%s (%s:%d)", fn.Name(), file, line)
		stackTrace = append(stackTrace, frame)
	}

	return stackTrace
}

// AddAttributes adds attributes to the current span
func (bt *BusinessTracer) AddAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.SetAttributes(attrs...)
	}
}

// SetStatus sets the status of the current span
func (bt *BusinessTracer) SetStatus(ctx context.Context, code codes.Code, description string) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.SetStatus(code, description)
	}
}

// Helper functions

// getQueryType determines the type of search query
func getQueryType(query string) string {
	if query == "" {
		return "empty"
	}
	if len(query) == 1 {
		return "single_char"
	}
	if len(query) <= 3 {
		return "short"
	}
	if len(query) <= 10 {
		return "medium"
	}
	return "long"
}

// Global business tracer instance (initialized when needed)
var globalBusinessTracer *BusinessTracer

// InitGlobalBusinessTracer initializes the global business tracer
func InitGlobalBusinessTracer(config BusinessTracerConfig) {
	globalBusinessTracer = NewBusinessTracer(config)
}

// GetGlobalBusinessTracer returns the global business tracer
func GetGlobalBusinessTracer() *BusinessTracer {
	if globalBusinessTracer == nil {
		// Initialize with default configuration if not already initialized
		globalBusinessTracer = NewBusinessTracer(BusinessTracerConfig{})
	}
	return globalBusinessTracer
}

// Convenience functions that use the global tracer

// TraceOperation wraps a business operation with tracing using the global tracer
func TraceOperation(ctx context.Context, operationName string, f func(context.Context) error) error {
	return GetGlobalBusinessTracer().TraceOperation(ctx, operationName, f)
}

// TraceUserRegistration traces user registration operations using the global tracer
func TraceUserRegistration(ctx context.Context, username, email string, stage string, f func(context.Context) error) error {
	return GetGlobalBusinessTracer().TraceUserRegistration(ctx, username, email, stage, f)
}

// TraceUserActivation traces user activation operations using the global tracer
func TraceUserActivation(ctx context.Context, username, token string, f func(context.Context) error) error {
	return GetGlobalBusinessTracer().TraceUserActivation(ctx, username, token, f)
}

// TraceChannelOperation traces channel-related operations using the global tracer
func TraceChannelOperation(ctx context.Context, channelID int32, userID int32, operation string, f func(context.Context) error) error {
	return GetGlobalBusinessTracer().TraceChannelOperation(ctx, channelID, userID, operation, f)
}

// TraceChannelSearch traces channel search operations using the global tracer
func TraceChannelSearch(ctx context.Context, userID int32, query string, f func(context.Context) (int, error)) (int, error) {
	return GetGlobalBusinessTracer().TraceChannelSearch(ctx, userID, query, f)
}

// TraceAuthentication traces authentication operations using the global tracer
func TraceAuthentication(ctx context.Context, username string, authType string, f func(context.Context) error) error {
	return GetGlobalBusinessTracer().TraceAuthentication(ctx, username, authType, f)
}

// TraceBusinessTransaction traces multi-step business transactions using the global tracer
func TraceBusinessTransaction(ctx context.Context, transactionName string, f func(context.Context) error) error {
	return GetGlobalBusinessTracer().TraceBusinessTransaction(ctx, transactionName, f)
}

// RecordError records an error in the current span using the global tracer
func RecordError(ctx context.Context, err error) {
	GetGlobalBusinessTracer().RecordError(ctx, err)
}

// RecordDetailedError records an error with detailed information using the global tracer
func RecordDetailedError(ctx context.Context, errorInfo ErrorInfo) {
	GetGlobalBusinessTracer().RecordDetailedError(ctx, errorInfo)
}

// RecordErrorWithCategory records an error with automatic categorization using the global tracer
func RecordErrorWithCategory(ctx context.Context, err error, operation string, userID *int64) {
	GetGlobalBusinessTracer().RecordErrorWithCategory(ctx, err, operation, userID)
}
