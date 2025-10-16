// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package tracing

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Operation represents a traced business operation that can be composed of multiple stages
type Operation struct {
	name       string
	ctx        context.Context
	tracer     *BusinessTracer
	stages     []Stage
	attributes map[string]interface{}
}

// Stage represents a single stage within an operation
type Stage struct {
	name     string
	function StageFunc
	optional bool
}

// StageFunc is the function signature for operation stages
type StageFunc func(*TracedContext) error

// NewOperation creates a new traced operation
func NewOperation(name string) *Operation {
	return &Operation{
		name:       name,
		tracer:     GetGlobalBusinessTracer(),
		stages:     make([]Stage, 0),
		attributes: make(map[string]interface{}),
	}
}

// WithContext sets the context for the operation
func (op *Operation) WithContext(ctx context.Context) *Operation {
	op.ctx = ctx
	return op
}

// WithAttributes adds attributes that will be applied to the root span
func (op *Operation) WithAttributes(attrs map[string]interface{}) *Operation {
	for k, v := range attrs {
		op.attributes[k] = v
	}
	return op
}

// WithAttribute adds a single attribute to the root span
func (op *Operation) WithAttribute(key string, value interface{}) *Operation {
	op.attributes[key] = value
	return op
}

// AddStage adds a required stage to the operation
func (op *Operation) AddStage(name string, fn StageFunc) *Operation {
	op.stages = append(op.stages, Stage{
		name:     name,
		function: fn,
		optional: false,
	})
	return op
}

// AddOptionalStage adds an optional stage to the operation
// Optional stages that fail will log the error but won't fail the operation
func (op *Operation) AddOptionalStage(name string, fn StageFunc) *Operation {
	op.stages = append(op.stages, Stage{
		name:     name,
		function: fn,
		optional: true,
	})
	return op
}

// Execute runs all stages of the operation within a traced context
func (op *Operation) Execute() error {
	if op.ctx == nil {
		op.ctx = context.Background()
	}

	// Create root span for the entire operation
	ctx, span := op.tracer.tracer.Start(op.ctx, op.name, trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	// Add root attributes
	attrs := []attribute.KeyValue{
		attribute.String("service.name", op.tracer.serviceName),
		attribute.String("service.component", "business-logic"),
		attribute.String("operation.name", op.name),
		attribute.Int("operation.stage_count", len(op.stages)),
	}
	for key, value := range op.attributes {
		attrs = append(attrs, convertToAttribute(key, value))
	}
	span.SetAttributes(attrs...)

	// Execute each stage
	start := time.Now()
	for i, stage := range op.stages {
		stageStart := time.Now()

		// Create child span for this stage
		stageCtx, stageSpan := op.tracer.tracer.Start(ctx, fmt.Sprintf("%s.%s", op.name, stage.name),
			trace.WithSpanKind(trace.SpanKindInternal))

		stageSpan.SetAttributes(
			attribute.String("stage.name", stage.name),
			attribute.Int("stage.index", i),
			attribute.Bool("stage.optional", stage.optional),
		)

		// Create traced context for the stage function
		tracedCtx := WithSpan(stageCtx, stageSpan)

		// Execute the stage
		err := stage.function(tracedCtx)
		stageDuration := time.Since(stageStart)

		// Record stage timing
		stageSpan.SetAttributes(attribute.Int64("stage.duration_ms", stageDuration.Milliseconds()))

		if err != nil {
			stageSpan.RecordError(err)
			stageSpan.SetStatus(codes.Error, err.Error())
			stageSpan.SetAttributes(attribute.Bool("stage.success", false))
			stageSpan.End()

			// If this is an optional stage, log and continue
			if stage.optional {
				span.AddEvent("optional_stage_failed",
					trace.WithAttributes(
						attribute.String("stage.name", stage.name),
						attribute.String("error.message", err.Error()),
					))
				continue
			}

			// Required stage failed - mark operation as failed
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			span.SetAttributes(
				attribute.Bool("operation.success", false),
				attribute.String("operation.failed_stage", stage.name),
				attribute.Int("operation.completed_stages", i),
				attribute.Int64("operation.duration_ms", time.Since(start).Milliseconds()),
			)
			return err
		}

		// Stage succeeded
		stageSpan.SetStatus(codes.Ok, "")
		stageSpan.SetAttributes(attribute.Bool("stage.success", true))
		stageSpan.End()
	}

	// All stages completed successfully
	duration := time.Since(start)
	span.SetStatus(codes.Ok, "")
	span.SetAttributes(
		attribute.Bool("operation.success", true),
		attribute.Int("operation.completed_stages", len(op.stages)),
		attribute.Int64("operation.duration_ms", duration.Milliseconds()),
	)

	return nil
}

// ExecuteWithResult runs all stages and returns a result
// This is useful for operations that need to return a value
func ExecuteWithResult[T any](op *Operation, resultStage string, resultFn func(*TracedContext) (T, error)) (T, error) {
	var result T
	var resultErr error

	// Add the result stage as the final stage
	op.AddStage(resultStage, func(tc *TracedContext) error {
		var err error
		result, err = resultFn(tc)
		resultErr = err
		return err
	})

	// Execute the operation
	err := op.Execute()
	if err != nil {
		return result, err
	}

	return result, resultErr
}

// Helper functions for creating common operation patterns

// SimpleOperation creates and executes a single-stage operation
func SimpleOperation(ctx context.Context, name string, fn StageFunc) error {
	return NewOperation(name).
		WithContext(ctx).
		AddStage("execute", fn).
		Execute()
}

// TwoStageOperation creates an operation with two stages
func TwoStageOperation(ctx context.Context, name, stage1Name, stage2Name string, stage1, stage2 StageFunc) error {
	return NewOperation(name).
		WithContext(ctx).
		AddStage(stage1Name, stage1).
		AddStage(stage2Name, stage2).
		Execute()
}

// ThreeStageOperation creates an operation with three stages
func ThreeStageOperation(ctx context.Context, name, stage1Name, stage2Name, stage3Name string,
	stage1, stage2, stage3 StageFunc) error {
	return NewOperation(name).
		WithContext(ctx).
		AddStage(stage1Name, stage1).
		AddStage(stage2Name, stage2).
		AddStage(stage3Name, stage3).
		Execute()
}
