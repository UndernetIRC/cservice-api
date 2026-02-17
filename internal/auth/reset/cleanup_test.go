// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package reset

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/models"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewCleanupService(t *testing.T) {
	t.Run("with_logger", func(t *testing.T) {
		tm := NewTokenManager(nil, nil)
		logger := discardLogger()
		cs := NewCleanupService(tm, time.Hour, logger)

		require.NotNil(t, cs)
		assert.Equal(t, tm, cs.tokenManager)
		assert.Equal(t, time.Hour, cs.interval)
		assert.Equal(t, logger, cs.logger)
		assert.NotNil(t, cs.stopCh)
		assert.NotNil(t, cs.doneCh)
	})

	t.Run("nil_logger_uses_default", func(t *testing.T) {
		tm := NewTokenManager(nil, nil)
		cs := NewCleanupService(tm, time.Hour, nil)

		require.NotNil(t, cs)
		assert.NotNil(t, cs.logger)
	})
}

func TestCleanupService_RunOnce(t *testing.T) {
	t.Run("successful_cleanup", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)
		cs := NewCleanupService(tm, time.Hour, discardLogger())

		statsBefore := models.GetPasswordResetTokenStatsRow{
			TotalTokens:   10,
			UsedTokens:    2,
			ExpiredTokens: 3,
			ActiveTokens:  5,
		}
		statsAfter := models.GetPasswordResetTokenStatsRow{
			TotalTokens:   7,
			UsedTokens:    2,
			ExpiredTokens: 0,
			ActiveTokens:  5,
		}

		// GetTokenStats called twice: before and after cleanup
		db.On("GetPasswordResetTokenStats", mock.Anything, mock.Anything).
			Return(statsBefore, nil).Once()
		db.On("CleanupExpiredPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()
		db.On("DeleteExpiredPasswordResetTokens", mock.Anything, mock.Anything).
			Return(nil).Once()
		db.On("GetPasswordResetTokenStats", mock.Anything, mock.Anything).
			Return(statsAfter, nil).Once()

		err := cs.RunOnce(context.Background())
		assert.NoError(t, err)
	})
}

func TestCleanupService_RunOnce_DBError(t *testing.T) {
	t.Run("stats_before_error", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)
		cs := NewCleanupService(tm, time.Hour, discardLogger())

		db.On("GetPasswordResetTokenStats", mock.Anything, mock.Anything).
			Return(models.GetPasswordResetTokenStatsRow{}, errors.New("db down")).Once()

		// RunOnce returns nil — errors are logged, not returned
		err := cs.RunOnce(context.Background())
		assert.NoError(t, err)
	})

	t.Run("cleanup_error", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)
		cs := NewCleanupService(tm, time.Hour, discardLogger())

		db.On("GetPasswordResetTokenStats", mock.Anything, mock.Anything).
			Return(models.GetPasswordResetTokenStatsRow{TotalTokens: 5}, nil).Once()
		db.On("CleanupExpiredPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything).
			Return(errors.New("cleanup failed")).Once()

		err := cs.RunOnce(context.Background())
		assert.NoError(t, err)
	})
}

func TestCleanupService_StartStop(t *testing.T) {
	db := mocks.NewQuerier(t)
	tm := NewTokenManager(db, nil)
	cs := NewCleanupService(tm, 50*time.Millisecond, discardLogger())

	// The initial performCleanup will call GetTokenStats — mock it to allow the goroutine to proceed
	db.On("GetPasswordResetTokenStats", mock.Anything, mock.Anything).
		Return(models.GetPasswordResetTokenStatsRow{}, nil).Maybe()
	db.On("CleanupExpiredPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything).
		Return(nil).Maybe()
	db.On("DeleteExpiredPasswordResetTokens", mock.Anything, mock.Anything).
		Return(nil).Maybe()

	ctx := context.Background()
	cs.Start(ctx)

	// Give it time to run the initial cleanup and at least one tick
	time.Sleep(100 * time.Millisecond)

	// Stop should return (doneCh closes)
	done := make(chan struct{})
	go func() {
		cs.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Success — Stop returned
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return in time — goroutine may be stuck")
	}
}

func TestPerformCleanup(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)
		cs := NewCleanupService(tm, time.Hour, discardLogger())

		statsBefore := models.GetPasswordResetTokenStatsRow{
			TotalTokens: 20, ExpiredTokens: 5, ActiveTokens: 10, UsedTokens: 5,
		}
		statsAfter := models.GetPasswordResetTokenStatsRow{
			TotalTokens: 15, ExpiredTokens: 0, ActiveTokens: 10, UsedTokens: 5,
		}

		db.On("GetPasswordResetTokenStats", mock.Anything, mock.Anything).
			Return(statsBefore, nil).Once()
		db.On("CleanupExpiredPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()
		db.On("DeleteExpiredPasswordResetTokens", mock.Anything, mock.Anything).
			Return(nil).Once()
		db.On("GetPasswordResetTokenStats", mock.Anything, mock.Anything).
			Return(statsAfter, nil).Once()

		cs.performCleanup(context.Background())
		db.AssertExpectations(t)
	})

	t.Run("stats_before_error_returns_early", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)
		cs := NewCleanupService(tm, time.Hour, discardLogger())

		db.On("GetPasswordResetTokenStats", mock.Anything, mock.Anything).
			Return(models.GetPasswordResetTokenStatsRow{}, errors.New("stats failed")).Once()

		cs.performCleanup(context.Background())
		// CleanupExpiredPasswordResetTokens should NOT be called
		db.AssertNotCalled(t, "CleanupExpiredPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("cleanup_error_returns_early", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)
		cs := NewCleanupService(tm, time.Hour, discardLogger())

		db.On("GetPasswordResetTokenStats", mock.Anything, mock.Anything).
			Return(models.GetPasswordResetTokenStatsRow{TotalTokens: 10}, nil).Once()
		db.On("CleanupExpiredPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything).
			Return(errors.New("cleanup failed")).Once()

		cs.performCleanup(context.Background())
		// DeleteExpiredPasswordResetTokens should NOT be called
		db.AssertNotCalled(t, "DeleteExpiredPasswordResetTokens", mock.Anything, mock.Anything)
	})

	t.Run("stats_after_error", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		tm := NewTokenManager(db, nil)
		cs := NewCleanupService(tm, time.Hour, discardLogger())

		db.On("GetPasswordResetTokenStats", mock.Anything, mock.Anything).
			Return(models.GetPasswordResetTokenStatsRow{TotalTokens: 10}, nil).Once()
		db.On("CleanupExpiredPasswordResetTokens", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()
		db.On("DeleteExpiredPasswordResetTokens", mock.Anything, mock.Anything).
			Return(nil).Once()
		db.On("GetPasswordResetTokenStats", mock.Anything, mock.Anything).
			Return(models.GetPasswordResetTokenStatsRow{}, errors.New("stats after failed")).Once()

		cs.performCleanup(context.Background())
		db.AssertExpectations(t)
	})
}
