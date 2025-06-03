// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

// Package cron provides cron job scheduling using the robfig/cron library
package cron

import (
	"context"
	"log/slog"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/undernetirc/cservice-api/internal/auth/reset"
)

// CleanupServiceInterface defines the interface for cleanup services
type CleanupServiceInterface interface {
	RunOnce(ctx context.Context) error
}

// Scheduler manages cron jobs using the robfig/cron library
type Scheduler struct {
	cron   *cron.Cron
	logger *slog.Logger
}

// Config holds configuration for the cron scheduler
type Config struct {
	// PasswordResetCleanupCron is the cron expression for password reset token cleanup
	// Default: "*/5 * * * *" (every 5 minutes)
	PasswordResetCleanupCron string
	// TimeZone for cron jobs (default: UTC)
	TimeZone string
}

// DefaultConfig returns default configuration
func DefaultConfig() Config {
	return Config{
		PasswordResetCleanupCron: "*/5 * * * *", // Every 5 minutes
		TimeZone:                 "UTC",
	}
}

// NewScheduler creates a new cron scheduler
func NewScheduler(config Config, logger *slog.Logger) (*Scheduler, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Parse timezone
	location, err := time.LoadLocation(config.TimeZone)
	if err != nil {
		return nil, err
	}

	// Create cron with timezone and logger
	c := cron.New(
		cron.WithLocation(location),
		cron.WithLogger(&cronLogger{logger}),
		cron.WithChain(
			cron.Recover(&cronLogger{logger}),             // Recover from panics
			cron.DelayIfStillRunning(&cronLogger{logger}), // Don't run if previous job is still running
		),
	)

	return &Scheduler{
		cron:   c,
		logger: logger,
	}, nil
}

// AddPasswordResetCleanupJob adds a job to clean up expired password reset tokens
func (s *Scheduler) AddPasswordResetCleanupJob(cronExpr string, cleanupService CleanupServiceInterface) error {
	_, err := s.cron.AddFunc(cronExpr, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		s.logger.Info("Starting password reset token cleanup job")
		start := time.Now()

		err := cleanupService.RunOnce(ctx)
		duration := time.Since(start)

		if err != nil {
			s.logger.Error("Password reset token cleanup job failed",
				"error", err,
				"duration", duration)
		} else {
			s.logger.Info("Password reset token cleanup job completed successfully",
				"duration", duration)
		}
	})

	if err != nil {
		return err
	}

	s.logger.Info("Added password reset cleanup job", "cron", cronExpr)
	return nil
}

// AddPasswordResetCleanupJobWithService is a convenience method that accepts *reset.CleanupService directly
func (s *Scheduler) AddPasswordResetCleanupJobWithService(cronExpr string, cleanupService *reset.CleanupService) error {
	return s.AddPasswordResetCleanupJob(cronExpr, cleanupService)
}

// AddJob adds a generic cron job
func (s *Scheduler) AddJob(cronExpr string, jobName string, job func()) error {
	_, err := s.cron.AddFunc(cronExpr, func() {
		s.logger.Info("Starting cron job", "job", jobName)
		start := time.Now()

		job()

		duration := time.Since(start)
		s.logger.Info("Cron job completed", "job", jobName, "duration", duration)
	})

	if err != nil {
		return err
	}

	s.logger.Info("Added cron job", "job", jobName, "cron", cronExpr)
	return nil
}

// Start starts the cron scheduler
func (s *Scheduler) Start() {
	s.cron.Start()
	s.logger.Info("Cron scheduler started")
}

// Stop stops the cron scheduler gracefully
func (s *Scheduler) Stop() {
	ctx := s.cron.Stop()
	<-ctx.Done()
	s.logger.Info("Cron scheduler stopped")
}

// GetEntries returns information about scheduled jobs
func (s *Scheduler) GetEntries() []cron.Entry {
	return s.cron.Entries()
}

// cronLogger adapts slog.Logger to work with robfig/cron
type cronLogger struct {
	logger *slog.Logger
}

// Info logs an info message
func (l *cronLogger) Info(msg string, keysAndValues ...interface{}) {
	l.logger.Info(msg, keysAndValues...)
}

// Error logs an error message
func (l *cronLogger) Error(err error, msg string, keysAndValues ...interface{}) {
	attrs := []interface{}{"error", err}
	attrs = append(attrs, keysAndValues...)
	l.logger.Error(msg, attrs...)
}
