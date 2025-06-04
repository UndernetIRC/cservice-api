// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package controllers

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/models"
)

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{
			name:     "seconds only",
			duration: 30 * time.Second,
			expected: "30 seconds",
		},
		{
			name:     "single second",
			duration: 1 * time.Second,
			expected: "1 seconds",
		},
		{
			name:     "minutes only",
			duration: 5 * time.Minute,
			expected: "5 minutes",
		},
		{
			name:     "single minute",
			duration: 1 * time.Minute,
			expected: "1 minutes",
		},
		{
			name:     "minutes with seconds (shows only minutes)",
			duration: 5*time.Minute + 30*time.Second,
			expected: "5 minutes",
		},
		{
			name:     "hours only",
			duration: 3 * time.Hour,
			expected: "3 hours",
		},
		{
			name:     "single hour",
			duration: 1 * time.Hour,
			expected: "1 hours",
		},
		{
			name:     "hours with minutes and seconds (shows only hours)",
			duration: 3*time.Hour + 45*time.Minute + 30*time.Second,
			expected: "3 hours",
		},
		{
			name:     "days only",
			duration: 2 * 24 * time.Hour,
			expected: "2 days",
		},
		{
			name:     "single day",
			duration: 24 * time.Hour,
			expected: "1 days",
		},
		{
			name:     "multiple days with hours (shows only days)",
			duration: 5*24*time.Hour + 8*time.Hour + 30*time.Minute,
			expected: "5 days",
		},
		{
			name:     "zero duration",
			duration: 0,
			expected: "0 seconds",
		},
		{
			name:     "very small duration",
			duration: 500 * time.Millisecond,
			expected: "0 seconds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDuration(tt.duration)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAuthenticationController_GetScopes(t *testing.T) {
	tests := []struct {
		name           string
		userID         int32
		setupMock      func(*mocks.Querier)
		expectedScopes string
		expectError    bool
	}{
		{
			name:   "user with multiple roles",
			userID: 123,
			setupMock: func(db *mocks.Querier) {
				db.On("ListUserRoles", mock.Anything, int32(123)).Return([]models.Role{
					{
						ID:   1,
						Name: "admin",
					},
					{
						ID:   2,
						Name: "moderator",
					},
					{
						ID:   3,
						Name: "helper",
					},
				}, nil)
			},
			expectedScopes: "admin moderator helper",
			expectError:    false,
		},
		{
			name:   "user with single role",
			userID: 124,
			setupMock: func(db *mocks.Querier) {
				db.On("ListUserRoles", mock.Anything, int32(124)).Return([]models.Role{
					{
						ID:   2,
						Name: "user",
					},
				}, nil)
			},
			expectedScopes: "user",
			expectError:    false,
		},
		{
			name:   "user with no roles",
			userID: 125,
			setupMock: func(db *mocks.Querier) {
				db.On("ListUserRoles", mock.Anything, int32(125)).Return([]models.Role{}, nil)
			},
			expectedScopes: "",
			expectError:    false,
		},
		{
			name:   "user not found (no rows error)",
			userID: 126,
			setupMock: func(db *mocks.Querier) {
				db.On("ListUserRoles", mock.Anything, int32(126)).Return([]models.Role{}, pgx.ErrNoRows)
			},
			expectedScopes: "",
			expectError:    false,
		},
		{
			name:   "database error",
			userID: 127,
			setupMock: func(db *mocks.Querier) {
				db.On("ListUserRoles", mock.Anything, int32(127)).Return([]models.Role{}, assert.AnError)
			},
			expectedScopes: "",
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			db := mocks.NewQuerier(t)
			tt.setupMock(db)

			controller := NewAuthenticationController(db, nil, nil)

			// Execute
			ctx := context.Background()
			scopes, err := controller.getScopes(ctx, tt.userID)

			// Assert
			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, scopes)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedScopes, scopes)
			}

			db.AssertExpectations(t)
		})
	}
}

func TestAuthenticationController_Now(t *testing.T) {
	tests := []struct {
		name         string
		mockClock    func() time.Time
		expectedTime time.Time
	}{
		{
			name:         "with nil clock function",
			mockClock:    nil,
			expectedTime: time.Time{}, // We'll check that it's recent, not exact
		},
		{
			name: "with custom clock function",
			mockClock: func() time.Time {
				return time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
			},
			expectedTime: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			controller := NewAuthenticationController(nil, nil, tt.mockClock)

			// Execute
			result := controller.now()

			// Assert
			if tt.mockClock == nil {
				// When using real time, just check it's recent (within last 5 seconds)
				now := time.Now()
				assert.True(t, result.After(now.Add(-5*time.Second)))
				assert.True(t, result.Before(now.Add(5*time.Second)))
			} else {
				assert.Equal(t, tt.expectedTime, result)
			}
		})
	}
}

func TestNewAuthenticationController(t *testing.T) {
	tests := []struct {
		name      string
		clockFunc func() time.Time
	}{
		{
			name:      "with clock function",
			clockFunc: func() time.Time { return time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC) },
		},
		{
			name:      "with nil clock function",
			clockFunc: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			db := mocks.NewQuerier(t)

			// Execute
			controller := NewAuthenticationController(db, nil, tt.clockFunc)

			// Assert
			assert.NotNil(t, controller)
			assert.Equal(t, db, controller.s)
			assert.NotNil(t, controller.tokenManager)

			// Test the clock function
			if tt.clockFunc == nil {
				// Should use real time
				now := time.Now()
				result := controller.now()
				assert.True(t, result.After(now.Add(-5*time.Second)))
				assert.True(t, result.Before(now.Add(5*time.Second)))
			} else {
				// Should use the provided clock function
				expected := tt.clockFunc()
				result := controller.now()
				assert.Equal(t, expected, result)
			}
		})
	}
}
