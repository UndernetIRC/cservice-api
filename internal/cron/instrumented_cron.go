// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package cron

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/robfig/cron/v3"
	"github.com/undernetirc/cservice-api/internal/auth/reset"
	"github.com/undernetirc/cservice-api/internal/metrics"
)

// InstrumentedScheduler wraps the cron scheduler with metrics collection
type InstrumentedScheduler struct {
	scheduler     *Scheduler
	systemMetrics *metrics.SystemHealthMetrics
	activeJobs    int64 // atomic counter for currently running jobs
	totalJobs     int64 // atomic counter for total scheduled jobs
}

// NewInstrumentedScheduler creates a new instrumented cron scheduler
func NewInstrumentedScheduler(config Config, logger *slog.Logger, systemMetrics *metrics.SystemHealthMetrics) (*InstrumentedScheduler, error) {
	scheduler, err := NewScheduler(config, logger)
	if err != nil {
		return nil, err
	}

	return &InstrumentedScheduler{
		scheduler:     scheduler,
		systemMetrics: systemMetrics,
		activeJobs:    0,
		totalJobs:     0,
	}, nil
}

// GetActiveJobCount returns the current number of running cron jobs
func (is *InstrumentedScheduler) GetActiveJobCount() int64 {
	return atomic.LoadInt64(&is.activeJobs)
}

// GetTotalJobCount returns the total number of scheduled cron jobs
func (is *InstrumentedScheduler) GetTotalJobCount() int64 {
	return atomic.LoadInt64(&is.totalJobs)
}

// AddPasswordResetCleanupJob adds an instrumented password reset cleanup job
func (is *InstrumentedScheduler) AddPasswordResetCleanupJob(cronExpr string, cleanupService CleanupServiceInterface) error {
	err := is.scheduler.AddPasswordResetCleanupJob(cronExpr, &instrumentedCleanupService{
		service:       cleanupService,
		systemMetrics: is.systemMetrics,
		activeJobs:    &is.activeJobs,
		jobName:       "password_reset_cleanup",
	})

	if err == nil {
		atomic.AddInt64(&is.totalJobs, 1)
	}

	return err
}

// AddPasswordResetCleanupJobWithService adds an instrumented password reset cleanup job with *reset.CleanupService
func (is *InstrumentedScheduler) AddPasswordResetCleanupJobWithService(cronExpr string, cleanupService *reset.CleanupService) error {
	return is.AddPasswordResetCleanupJob(cronExpr, cleanupService)
}

// AddJob adds an instrumented generic cron job
func (is *InstrumentedScheduler) AddJob(cronExpr string, jobName string, job func()) error {
	instrumentedJob := func() {
		// Increment active job counter
		atomic.AddInt64(&is.activeJobs, 1)
		defer atomic.AddInt64(&is.activeJobs, -1)

		ctx := context.Background()
		if is.systemMetrics != nil {
			// Measure job execution with metrics
			_ = is.systemMetrics.MeasureCronJobExecution(ctx, jobName, func() error {
				job()
				return nil // Original job function doesn't return error
			})
		} else {
			// Fallback to original job execution
			job()
		}
	}

	err := is.scheduler.AddJob(cronExpr, jobName, instrumentedJob)
	if err == nil {
		atomic.AddInt64(&is.totalJobs, 1)
	}

	return err
}

// AddJobWithError adds an instrumented cron job that can return an error
func (is *InstrumentedScheduler) AddJobWithError(cronExpr string, jobName string, job func() error) error {
	instrumentedJob := func() {
		// Increment active job counter
		atomic.AddInt64(&is.activeJobs, 1)
		defer atomic.AddInt64(&is.activeJobs, -1)

		ctx := context.Background()
		if is.systemMetrics != nil {
			// Measure job execution with metrics
			err := is.systemMetrics.MeasureCronJobExecution(ctx, jobName, job)
			if err != nil {
				is.scheduler.logger.Error("Cron job failed", "job", jobName, "error", err)
			}
		} else {
			// Fallback to original job execution
			err := job()
			if err != nil {
				is.scheduler.logger.Error("Cron job failed", "job", jobName, "error", err)
			}
		}
	}

	err := is.scheduler.AddJob(cronExpr, jobName, instrumentedJob)
	if err == nil {
		atomic.AddInt64(&is.totalJobs, 1)
	}

	return err
}

// Start starts the instrumented cron scheduler
func (is *InstrumentedScheduler) Start() {
	is.scheduler.Start()
}

// Stop stops the instrumented cron scheduler
func (is *InstrumentedScheduler) Stop() {
	is.scheduler.Stop()
}

// GetEntries returns information about scheduled jobs
func (is *InstrumentedScheduler) GetEntries() []cron.Entry {
	return is.scheduler.GetEntries()
}

// GetSystemHealthCallbacks returns callback functions for system health metrics
func (is *InstrumentedScheduler) GetSystemHealthCallbacks() (
	getActiveJobCount func() int64,
	getTotalJobCount func() int64,
) {
	return is.GetActiveJobCount, is.GetTotalJobCount
}

// GetSystemStatus returns the overall cron system health status
// Returns 1 if healthy, 0 if unhealthy
func (is *InstrumentedScheduler) GetSystemStatus() int64 {
	// Check if scheduler is properly initialized
	if is.scheduler == nil || is.scheduler.cron == nil {
		return 0 // Unhealthy - scheduler not initialized
	}

	// Check if we have any jobs scheduled
	entries := is.GetEntries()
	if len(entries) == 0 {
		return 0 // Unhealthy - no jobs scheduled (might indicate configuration issue)
	}

	// Check if too many jobs are running simultaneously (potential deadlock)
	activeJobs := is.GetActiveJobCount()
	totalJobs := is.GetTotalJobCount()

	if totalJobs > 0 && activeJobs >= totalJobs {
		// All jobs are running simultaneously - might indicate stuck jobs
		return 0 // Unhealthy - potential job deadlock
	}

	return 1 // Healthy
}

// instrumentedCleanupService wraps CleanupServiceInterface with metrics
type instrumentedCleanupService struct {
	service       CleanupServiceInterface
	systemMetrics *metrics.SystemHealthMetrics
	activeJobs    *int64
	jobName       string
}

// RunOnce executes the cleanup service with metrics collection
func (ics *instrumentedCleanupService) RunOnce(ctx context.Context) error {
	// Increment active job counter
	atomic.AddInt64(ics.activeJobs, 1)
	defer atomic.AddInt64(ics.activeJobs, -1)

	if ics.systemMetrics != nil {
		// Measure cleanup execution with metrics
		return ics.systemMetrics.MeasureCronJobExecution(ctx, ics.jobName, func() error {
			return ics.service.RunOnce(ctx)
		})
	}

	// Fallback to original service execution
	return ics.service.RunOnce(ctx)
}
