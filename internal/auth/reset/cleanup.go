// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package reset

import (
	"context"
	"log/slog"
	"time"
)

// CleanupService handles periodic cleanup of expired password reset tokens
type CleanupService struct {
	tokenManager *TokenManager
	interval     time.Duration
	logger       *slog.Logger
	stopCh       chan struct{}
	doneCh       chan struct{}
}

// NewCleanupService creates a new cleanup service
func NewCleanupService(tokenManager *TokenManager, interval time.Duration, logger *slog.Logger) *CleanupService {
	if logger == nil {
		logger = slog.Default()
	}

	return &CleanupService{
		tokenManager: tokenManager,
		interval:     interval,
		logger:       logger,
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
	}
}

// Start begins the cleanup service in a background goroutine
func (cs *CleanupService) Start(ctx context.Context) {
	go cs.run(ctx)
}

// Stop gracefully stops the cleanup service
func (cs *CleanupService) Stop() {
	close(cs.stopCh)
	<-cs.doneCh
}

// run is the main cleanup loop
func (cs *CleanupService) run(ctx context.Context) {
	defer close(cs.doneCh)

	ticker := time.NewTicker(cs.interval)
	defer ticker.Stop()

	cs.logger.Info("Password reset token cleanup service started",
		"interval", cs.interval)

	// Run initial cleanup
	cs.performCleanup(ctx)

	for {
		select {
		case <-ctx.Done():
			cs.logger.Info("Password reset token cleanup service stopped due to context cancellation")
			return
		case <-cs.stopCh:
			cs.logger.Info("Password reset token cleanup service stopped")
			return
		case <-ticker.C:
			cs.performCleanup(ctx)
		}
	}
}

// performCleanup executes the token cleanup operation
func (cs *CleanupService) performCleanup(ctx context.Context) {
	start := time.Now()

	// Get stats before cleanup
	statsBefore, err := cs.tokenManager.GetTokenStats(ctx)
	if err != nil {
		cs.logger.Error("Failed to get token stats before cleanup", "error", err)
		return
	}

	// Perform cleanup
	err = cs.tokenManager.CleanupExpiredTokens(ctx)
	if err != nil {
		cs.logger.Error("Failed to cleanup expired tokens", "error", err)
		return
	}

	// Get stats after cleanup
	statsAfter, err := cs.tokenManager.GetTokenStats(ctx)
	if err != nil {
		cs.logger.Error("Failed to get token stats after cleanup", "error", err)
		return
	}

	duration := time.Since(start)
	cleanedTokens := statsBefore.ExpiredTokens - statsAfter.ExpiredTokens

	cs.logger.Info("Password reset token cleanup completed",
		"duration", duration,
		"cleaned_tokens", cleanedTokens,
		"total_tokens", statsAfter.TotalTokens,
		"active_tokens", statsAfter.ActiveTokens,
		"expired_tokens", statsAfter.ExpiredTokens,
		"used_tokens", statsAfter.UsedTokens)
}

// RunOnce performs a single cleanup operation (useful for testing or manual cleanup)
func (cs *CleanupService) RunOnce(ctx context.Context) error {
	cs.performCleanup(ctx)
	return nil
}
