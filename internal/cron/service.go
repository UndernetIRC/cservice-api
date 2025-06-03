// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

// Package cron provides service integration for cron scheduling
package cron

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/undernetirc/cservice-api/internal/auth/reset"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/models"
)

// Service manages cron jobs for the application
type Service struct {
	scheduler *Scheduler
	logger    *slog.Logger
}

// ServiceConfig holds configuration for the cron service
type ServiceConfig struct {
	// PasswordResetCleanupCron is the cron expression for password reset token cleanup
	// Default: "*/5 * * * *" (every 5 minutes)
	PasswordResetCleanupCron string
	// TimeZone for cron jobs (default: UTC)
	TimeZone string
	// Enabled determines if cron jobs should run
	Enabled bool
}

// NewService creates a new cron service
func NewService(config ServiceConfig, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}

	if !config.Enabled {
		logger.Info("Cron service is disabled")
		return &Service{
			scheduler: nil,
			logger:    logger,
		}, nil
	}

	schedulerConfig := Config{
		PasswordResetCleanupCron: config.PasswordResetCleanupCron,
		TimeZone:                 config.TimeZone,
	}

	scheduler, err := NewScheduler(schedulerConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create cron scheduler: %w", err)
	}

	return &Service{
		scheduler: scheduler,
		logger:    logger,
	}, nil
}

// Start starts the cron service and all scheduled jobs
func (s *Service) Start() error {
	if s.scheduler == nil {
		s.logger.Info("Cron service not started (disabled)")
		return nil
	}

	s.scheduler.Start()
	s.logger.Info("Cron service started")
	return nil
}

// Stop stops the cron service and all scheduled jobs
func (s *Service) Stop() {
	if s.scheduler == nil {
		return
	}

	s.scheduler.Stop()
	s.logger.Info("Cron service stopped")
}

// SetupPasswordResetCleanup configures password reset token cleanup job
func (s *Service) SetupPasswordResetCleanup(queries models.Querier, config ServiceConfig) error {
	if s.scheduler == nil {
		s.logger.Info("Skipping password reset cleanup setup (cron service disabled)")
		return nil
	}

	// Load reset token configuration
	resetConfig, err := reset.LoadConfigFromViper()
	if err != nil {
		return fmt.Errorf("failed to load password reset config: %w", err)
	}

	// Create token manager and cleanup service
	tokenManager := reset.NewTokenManager(queries, resetConfig)
	cleanupService := reset.NewCleanupService(tokenManager, resetConfig.CleanupInterval, s.logger)

	// Schedule the cleanup job
	err = s.scheduler.AddPasswordResetCleanupJobWithService(config.PasswordResetCleanupCron, cleanupService)
	if err != nil {
		return fmt.Errorf("failed to schedule password reset cleanup job: %w", err)
	}

	s.logger.Info("Password reset token cleanup job scheduled",
		"cron", config.PasswordResetCleanupCron,
		"cleanup_interval", resetConfig.CleanupInterval)

	return nil
}

// AddCustomJob adds a custom cron job
func (s *Service) AddCustomJob(cronExpr string, jobName string, job func()) error {
	if s.scheduler == nil {
		return fmt.Errorf("cron service is disabled")
	}

	return s.scheduler.AddJob(cronExpr, jobName, job)
}

// GetJobEntries returns information about scheduled jobs
func (s *Service) GetJobEntries() []JobInfo {
	if s.scheduler == nil {
		return nil
	}

	entries := s.scheduler.GetEntries()
	jobInfos := make([]JobInfo, len(entries))

	for i, entry := range entries {
		jobInfos[i] = JobInfo{
			ID:       entry.ID,
			Next:     entry.Next,
			Prev:     entry.Prev,
			Valid:    entry.Valid(),
			Schedule: fmt.Sprintf("%v", entry.Schedule),
		}
	}

	return jobInfos
}

// JobInfo represents information about a scheduled job
type JobInfo struct {
	ID       cron.EntryID
	Next     time.Time
	Prev     time.Time
	Valid    bool
	Schedule string
}

// IsEnabled returns whether the cron service is enabled
func (s *Service) IsEnabled() bool {
	return s.scheduler != nil
}

// LoadServiceConfigFromViper loads cron service configuration from viper
func LoadServiceConfigFromViper() ServiceConfig {
	return ServiceConfig{
		PasswordResetCleanupCron: config.ServiceCronPasswordResetCleanup.GetString(),
		TimeZone:                 config.ServiceCronTimeZone.GetString(),
		Enabled:                  config.ServiceCronEnabled.GetBool(),
	}
}

// RunPasswordResetCleanupOnce runs the password reset cleanup job once (useful for testing)
func (s *Service) RunPasswordResetCleanupOnce(ctx context.Context, queries models.Querier) error {
	if s.scheduler == nil {
		return fmt.Errorf("cron service is disabled")
	}

	// Load reset token configuration
	resetConfig, err := reset.LoadConfigFromViper()
	if err != nil {
		return fmt.Errorf("failed to load password reset config: %w", err)
	}

	// Create token manager and cleanup service
	tokenManager := reset.NewTokenManager(queries, resetConfig)
	cleanupService := reset.NewCleanupService(tokenManager, resetConfig.CleanupInterval, s.logger)

	// Run cleanup once
	return cleanupService.RunOnce(ctx)
}
