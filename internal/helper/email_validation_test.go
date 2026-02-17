// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package helper

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/models"
)

func setupEmailValidationTest() (*EmailLockValidator, *mocks.Querier) {
	mockDB := &mocks.Querier{}
	validator := NewEmailLockValidator(mockDB)

	// Set default config values for email lock
	config.ServiceChannelRegLockedEmailDomains.Set([]string{"locked.com", "blocked.org"})
	config.ServiceChannelRegLockedEmailPatterns.Set([]string{"spam", "throwaway"})

	return validator, mockDB
}

func TestNewEmailLockValidator(t *testing.T) {
	mockDB := &mocks.Querier{}
	validator := NewEmailLockValidator(mockDB)

	require.NotNil(t, validator)
	assert.Equal(t, mockDB, validator.db)
}

func TestIsEmailLocked(t *testing.T) {
	validator, _ := setupEmailValidationTest()
	ctx := context.Background()

	tests := []struct {
		name     string
		email    string
		expected bool
	}{
		{
			name:     "empty email returns false",
			email:    "",
			expected: false,
		},
		{
			name:     "unlocked email domain",
			email:    "user@example.com",
			expected: false,
		},
		{
			name:     "locked email domain",
			email:    "user@locked.com",
			expected: true,
		},
		{
			name:     "locked email domain - blocked.org",
			email:    "user@blocked.org",
			expected: true,
		},
		{
			name:     "email matching locked pattern",
			email:    "spamuser@example.com",
			expected: true,
		},
		{
			name:     "email matching throwaway pattern",
			email:    "throwaway123@example.com",
			expected: true,
		},
		{
			name:     "normal email not matching any pattern",
			email:    "legitimate@example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			locked, err := validator.IsEmailLocked(ctx, tt.email)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, locked)
		})
	}
}

func TestIsEmailLocked_CaseSensitivity(t *testing.T) {
	validator, _ := setupEmailValidationTest()
	ctx := context.Background()

	tests := []struct {
		name     string
		email    string
		expected bool
	}{
		{
			name:     "uppercase locked domain",
			email:    "USER@LOCKED.COM",
			expected: true,
		},
		{
			name:     "mixed case locked domain",
			email:    "User@Locked.Com",
			expected: true,
		},
		{
			name:     "uppercase locked pattern",
			email:    "SPAMUSER@example.com",
			expected: true,
		},
		{
			name:     "mixed case locked pattern",
			email:    "ThrowAway@example.com",
			expected: true,
		},
		{
			name:     "email with leading/trailing spaces",
			email:    "  user@locked.com  ",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			locked, err := validator.IsEmailLocked(ctx, tt.email)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, locked)
		})
	}
}

func TestValidateUserEmailNotLocked(t *testing.T) {
	ctx := context.Background()
	userID := int32(100)

	t.Run("user with unlocked email", func(t *testing.T) {
		validator, mockDB := setupEmailValidationTest()

		mockDB.On("GetUser", mock.Anything, models.GetUserParams{
			ID: userID,
		}).Return(models.GetUserRow{
			ID:       userID,
			Username: "testuser",
			Email:    pgtype.Text{String: "user@example.com", Valid: true},
		}, nil).Once()

		err := validator.ValidateUserEmailNotLocked(ctx, userID)
		assert.NoError(t, err)
		mockDB.AssertExpectations(t)
	})

	t.Run("user with locked email", func(t *testing.T) {
		validator, mockDB := setupEmailValidationTest()

		mockDB.On("GetUser", mock.Anything, models.GetUserParams{
			ID: userID,
		}).Return(models.GetUserRow{
			ID:       userID,
			Username: "testuser",
			Email:    pgtype.Text{String: "user@locked.com", Valid: true},
		}, nil).Once()

		err := validator.ValidateUserEmailNotLocked(ctx, userID)
		assert.Error(t, err)
		var validationErr *ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "EMAIL_LOCKED", validationErr.Code)
		mockDB.AssertExpectations(t)
	})

	t.Run("user with invalid email", func(t *testing.T) {
		validator, mockDB := setupEmailValidationTest()

		mockDB.On("GetUser", mock.Anything, models.GetUserParams{
			ID: userID,
		}).Return(models.GetUserRow{
			ID:       userID,
			Username: "testuser",
			Email:    pgtype.Text{Valid: false},
		}, nil).Once()

		err := validator.ValidateUserEmailNotLocked(ctx, userID)
		assert.Error(t, err)
		var validationErr *ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "INVALID_EMAIL", validationErr.Code)
		mockDB.AssertExpectations(t)
	})
}

func TestValidateUserEmailNotLocked_DBError(t *testing.T) {
	validator, mockDB := setupEmailValidationTest()
	ctx := context.Background()
	userID := int32(100)

	dbErr := errors.New("connection refused")
	mockDB.On("GetUser", mock.Anything, models.GetUserParams{
		ID: userID,
	}).Return(models.GetUserRow{}, dbErr).Once()

	err := validator.ValidateUserEmailNotLocked(ctx, userID)
	assert.Error(t, err)
	var validationErr *ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "DATABASE_ERROR", validationErr.Code)
	mockDB.AssertExpectations(t)
}

func TestValidateSupporterEmailNotLocked(t *testing.T) {
	ctx := context.Background()
	supporterUsername := "supporter1"

	t.Run("supporter with unlocked email", func(t *testing.T) {
		validator, mockDB := setupEmailValidationTest()

		mockDB.On("GetUser", mock.Anything, models.GetUserParams{
			Username: supporterUsername,
		}).Return(models.GetUserRow{
			ID:       200,
			Username: supporterUsername,
			Email:    pgtype.Text{String: "supporter@example.com", Valid: true},
		}, nil).Once()

		err := validator.ValidateSupporterEmailNotLocked(ctx, supporterUsername)
		assert.NoError(t, err)
		mockDB.AssertExpectations(t)
	})

	t.Run("supporter with locked email", func(t *testing.T) {
		validator, mockDB := setupEmailValidationTest()

		mockDB.On("GetUser", mock.Anything, models.GetUserParams{
			Username: supporterUsername,
		}).Return(models.GetUserRow{
			ID:       200,
			Username: supporterUsername,
			Email:    pgtype.Text{String: "supporter@blocked.org", Valid: true},
		}, nil).Once()

		err := validator.ValidateSupporterEmailNotLocked(ctx, supporterUsername)
		assert.Error(t, err)
		var validationErr *ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "SUPPORTER_EMAIL_LOCKED", validationErr.Code)
		mockDB.AssertExpectations(t)
	})

	t.Run("supporter with invalid email", func(t *testing.T) {
		validator, mockDB := setupEmailValidationTest()

		mockDB.On("GetUser", mock.Anything, models.GetUserParams{
			Username: supporterUsername,
		}).Return(models.GetUserRow{
			ID:       200,
			Username: supporterUsername,
			Email:    pgtype.Text{Valid: false},
		}, nil).Once()

		err := validator.ValidateSupporterEmailNotLocked(ctx, supporterUsername)
		assert.Error(t, err)
		var validationErr *ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "INVALID_EMAIL", validationErr.Code)
		mockDB.AssertExpectations(t)
	})

	t.Run("database error", func(t *testing.T) {
		validator, mockDB := setupEmailValidationTest()

		dbErr := errors.New("timeout")
		mockDB.On("GetUser", mock.Anything, models.GetUserParams{
			Username: supporterUsername,
		}).Return(models.GetUserRow{}, dbErr).Once()

		err := validator.ValidateSupporterEmailNotLocked(ctx, supporterUsername)
		assert.Error(t, err)
		var validationErr *ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "DATABASE_ERROR", validationErr.Code)
		mockDB.AssertExpectations(t)
	})
}

func TestValidateUserEmailLock(t *testing.T) {
	ctx := context.Background()
	userID := int32(100)

	tests := []struct {
		name      string
		user      models.GetUserRow
		dbErr     error
		wantErr   bool
		errSubstr string
	}{
		{
			name: "user with unlocked email",
			user: models.GetUserRow{
				ID:       userID,
				Username: "testuser",
				Email:    pgtype.Text{String: "user@example.com", Valid: true},
			},
			wantErr: false,
		},
		{
			name: "user with locked email domain",
			user: models.GetUserRow{
				ID:       userID,
				Username: "testuser",
				Email:    pgtype.Text{String: "user@locked.com", Valid: true},
			},
			wantErr:   true,
			errSubstr: "email domain/pattern is locked",
		},
		{
			name: "user with locked email pattern",
			user: models.GetUserRow{
				ID:       userID,
				Username: "testuser",
				Email:    pgtype.Text{String: "spamuser@example.com", Valid: true},
			},
			wantErr:   true,
			errSubstr: "email domain/pattern is locked",
		},
		{
			name: "user with no email",
			user: models.GetUserRow{
				ID:       userID,
				Username: "testuser",
				Email:    pgtype.Text{Valid: false},
			},
			wantErr:   true,
			errSubstr: "user has no email address",
		},
		{
			name:      "database error",
			dbErr:     errors.New("connection refused"),
			wantErr:   true,
			errSubstr: "failed to get user email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator, mockDB := setupEmailValidationTest()

			if tt.dbErr != nil {
				mockDB.On("GetUser", mock.Anything, models.GetUserParams{
					ID: userID,
				}).Return(models.GetUserRow{}, tt.dbErr).Once()
			} else {
				mockDB.On("GetUser", mock.Anything, models.GetUserParams{
					ID: userID,
				}).Return(tt.user, nil).Once()
			}

			err := validator.ValidateUserEmailLock(ctx, userID)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
			} else {
				assert.NoError(t, err)
			}

			mockDB.AssertExpectations(t)
		})
	}
}

func TestValidateSupporterEmailLock(t *testing.T) {
	ctx := context.Background()
	supporterUsername := "supporter1"

	tests := []struct {
		name      string
		user      models.GetUserRow
		dbErr     error
		wantErr   bool
		errSubstr string
	}{
		{
			name: "supporter with unlocked email",
			user: models.GetUserRow{
				ID:       200,
				Username: supporterUsername,
				Email:    pgtype.Text{String: "supporter@example.com", Valid: true},
			},
			wantErr: false,
		},
		{
			name: "supporter with locked email domain",
			user: models.GetUserRow{
				ID:       200,
				Username: supporterUsername,
				Email:    pgtype.Text{String: "supporter@blocked.org", Valid: true},
			},
			wantErr:   true,
			errSubstr: "supporter supporter1 email domain/pattern is locked",
		},
		{
			name: "supporter with locked email pattern",
			user: models.GetUserRow{
				ID:       200,
				Username: supporterUsername,
				Email:    pgtype.Text{String: "throwaway123@example.com", Valid: true},
			},
			wantErr:   true,
			errSubstr: "supporter supporter1 email domain/pattern is locked",
		},
		{
			name: "supporter with no email",
			user: models.GetUserRow{
				ID:       200,
				Username: supporterUsername,
				Email:    pgtype.Text{Valid: false},
			},
			wantErr:   true,
			errSubstr: "supporter supporter1 has no email address",
		},
		{
			name:      "database error",
			dbErr:     errors.New("connection refused"),
			wantErr:   true,
			errSubstr: "failed to get supporter email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator, mockDB := setupEmailValidationTest()

			if tt.dbErr != nil {
				mockDB.On("GetUser", mock.Anything, models.GetUserParams{
					Username: supporterUsername,
				}).Return(models.GetUserRow{}, tt.dbErr).Once()
			} else {
				mockDB.On("GetUser", mock.Anything, models.GetUserParams{
					Username: supporterUsername,
				}).Return(tt.user, nil).Once()
			}

			err := validator.ValidateSupporterEmailLock(ctx, supporterUsername)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
			} else {
				assert.NoError(t, err)
			}

			mockDB.AssertExpectations(t)
		})
	}
}
