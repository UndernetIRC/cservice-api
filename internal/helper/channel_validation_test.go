// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package helper

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/internal/config"
	apierrors "github.com/undernetirc/cservice-api/internal/errors"
	"github.com/undernetirc/cservice-api/models"
)

// Test utilities for channel registration validation tests

func setupChannelValidationTest() (*ChannelRegistrationValidator, *mocks.Querier) {
	mockDB := &mocks.Querier{}
	validator := NewValidator()
	channelValidator := NewChannelRegistrationValidator(mockDB, validator)

	// Set test configuration values
	config.ServiceChannelRegEnabled.Set(true)
	config.ServiceChannelRegRequiredSupporters.Set(2)
	config.ServiceChannelRegMaxChannelsRegular.Set(1)
	config.ServiceChannelRegMaxChannelsSupporter.Set(5)
	config.ServiceChannelRegMaxChannelsAdmin.Set(10)
	config.ServiceChannelRegCooldownHours.Set(168) // 7 days
	config.ServiceChannelRegIrcIdleHours.Set(168)  // 7 days
	config.ServiceChannelRegAllowMultiple.Set(false)

	return channelValidator, mockDB
}

func TestValidateChannelName(t *testing.T) {
	validator, _ := setupChannelValidationTest()

	tests := []struct {
		name        string
		channelName string
		wantErr     bool
		errorCode   string
	}{
		{
			name:        "valid channel name",
			channelName: "#test",
			wantErr:     false,
		},
		{
			name:        "valid channel name with numbers",
			channelName: "#test123",
			wantErr:     false,
		},
		{
			name:        "valid channel name with underscore",
			channelName: "#test_channel",
			wantErr:     false,
		},
		{
			name:        "missing hash prefix",
			channelName: "test",
			wantErr:     true,
			errorCode:   apierrors.ErrCodeInvalidChannelName,
		},
		{
			name:        "contains space",
			channelName: "#test channel",
			wantErr:     true,
			errorCode:   apierrors.ErrCodeInvalidChannelName,
		},
		{
			name:        "contains comma",
			channelName: "#test,channel",
			wantErr:     true,
			errorCode:   apierrors.ErrCodeInvalidChannelName,
		},
		{
			name:        "contains asterisk",
			channelName: "#test*",
			wantErr:     true,
			errorCode:   apierrors.ErrCodeInvalidChannelName,
		},
		{
			name:        "contains question mark",
			channelName: "#test?",
			wantErr:     true,
			errorCode:   apierrors.ErrCodeInvalidChannelName,
		},
		{
			name:        "contains exclamation",
			channelName: "#test!",
			wantErr:     true,
			errorCode:   apierrors.ErrCodeInvalidChannelName,
		},
		{
			name:        "contains at symbol",
			channelName: "#test@",
			wantErr:     true,
			errorCode:   apierrors.ErrCodeInvalidChannelName,
		},
		{
			name:        "empty channel name",
			channelName: "",
			wantErr:     true,
			errorCode:   apierrors.ErrCodeInvalidChannelName,
		},
		{
			name:        "whitespace only channel name",
			channelName: "   ",
			wantErr:     true,
			errorCode:   apierrors.ErrCodeInvalidChannelName,
		},
		{
			name:        "too short channel name",
			channelName: "#",
			wantErr:     true,
			errorCode:   apierrors.ErrCodeInvalidChannelName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateChannelName(tt.channelName)

			if tt.wantErr {
				assert.Error(t, err)
				if validationErr, ok := err.(*ValidationError); ok {
					assert.Equal(t, tt.errorCode, validationErr.Code)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateDescription(t *testing.T) {
	validator, _ := setupChannelValidationTest()

	tests := []struct {
		name        string
		description string
		wantErr     bool
		errorCode   string
	}{
		{
			name:        "valid description",
			description: "This is a valid channel description",
			wantErr:     false,
		},
		{
			name:        "description with special characters",
			description: "Test channel for #testing & development!",
			wantErr:     false,
		},
		{
			name:        "description with script tag",
			description: "This contains <script>alert('xss')</script>",
			wantErr:     true,
			errorCode:   apierrors.ErrCodeInvalidDescription,
		},
		{
			name:        "description with javascript",
			description: "Click here: javascript:alert('xss')",
			wantErr:     true,
			errorCode:   apierrors.ErrCodeInvalidDescription,
		},
		{
			name:        "description with onclick",
			description: "Image: <img onclick='alert()' src='test.jpg'>",
			wantErr:     true,
			errorCode:   apierrors.ErrCodeInvalidDescription,
		},
		{
			name:        "description with iframe",
			description: "Embedded content: <iframe src='evil.com'></iframe>",
			wantErr:     true,
			errorCode:   apierrors.ErrCodeInvalidDescription,
		},
		{
			name:        "empty description",
			description: "",
			wantErr:     true,
			errorCode:   apierrors.ErrCodeInvalidDescription,
		},
		{
			name:        "whitespace only description",
			description: "   \n\t  ",
			wantErr:     true,
			errorCode:   apierrors.ErrCodeInvalidDescription,
		},
		{
			name:        "description with form tag",
			description: "Contact us: <form action='evil.com'>",
			wantErr:     true,
			errorCode:   apierrors.ErrCodeInvalidDescription,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateDescription(tt.description)

			if tt.wantErr {
				assert.Error(t, err)
				if validationErr, ok := err.(*ValidationError); ok {
					assert.Equal(t, tt.errorCode, validationErr.Code)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateSupporters(t *testing.T) {
	validator, mockDB := setupChannelValidationTest()
	ctx := context.Background()
	userID := int32(123)

	// Mock user data
	currentUser := models.GetUserRow{
		ID:       userID,
		Username: "testuser",
	}

	tests := []struct {
		name       string
		supporters []string
		setupMocks func()
		wantErr    bool
		errorCode  string
	}{
		{
			name:       "valid supporters",
			supporters: []string{"supporter1", "supporter2"},
			setupMocks: func() {
				mockDB.On("GetUser", mock.Anything, models.GetUserParams{
					ID: userID,
				}).Return(currentUser, nil)

				// Mock the efficient bulk validation queries
				mockDB.On("GetSupportersByUsernames", mock.Anything, []string{"supporter1", "supporter2"}, mock.AnythingOfType("int32")).Return([]models.GetSupportersByUsernamesRow{
					{Username: "supporter1", IsOldEnough: true, HasFraudFlag: false, Email: pgtype.Text{String: "supporter1@example.com", Valid: true}},
					{Username: "supporter2", IsOldEnough: true, HasFraudFlag: false, Email: pgtype.Text{String: "supporter2@example.com", Valid: true}},
				}, nil)

				mockDB.On("CheckMultipleSupportersNoregStatus", mock.Anything, []string{"supporter1", "supporter2"}).Return([]models.CheckMultipleSupportersNoregStatusRow{
					{Username: "supporter1", IsNoreg: false},
					{Username: "supporter2", IsNoreg: false},
				}, nil)

				mockDB.On("CheckMultipleSupportersConcurrentSupports", mock.Anything, []string{"supporter1", "supporter2"}, mock.AnythingOfType("int32")).Return([]models.CheckMultipleSupportersConcurrentSupportsRow{
					{Username: "supporter1", ExceedsLimit: false},
					{Username: "supporter2", ExceedsLimit: false},
				}, nil)
			},
			wantErr: false,
		},
		{
			name:       "insufficient supporters",
			supporters: []string{"supporter1"},
			setupMocks: func() {
				mockDB.On("GetUser", mock.Anything, models.GetUserParams{
					ID: userID,
				}).Return(currentUser, nil)
			},
			wantErr:   true,
			errorCode: apierrors.ErrCodeInsufficientSupporters,
		},
		{
			name:       "self support not allowed",
			supporters: []string{"testuser", "supporter2"},
			setupMocks: func() {
				mockDB.On("GetUser", mock.Anything, models.GetUserParams{
					ID: userID,
				}).Return(currentUser, nil)
			},
			wantErr:   true,
			errorCode: apierrors.ErrCodeSelfSupportNotAllowed,
		},
		{
			name:       "duplicate supporters",
			supporters: []string{"supporter1", "supporter1"},
			setupMocks: func() {
				mockDB.On("GetUser", mock.Anything, models.GetUserParams{
					ID: userID,
				}).Return(currentUser, nil)
			},
			wantErr:   true,
			errorCode: apierrors.ErrCodeDuplicateSupporters,
		},
		{
			name:       "invalid supporter",
			supporters: []string{"supporter1", "nonexistent"},
			setupMocks: func() {
				mockDB.On("GetUser", mock.Anything, models.GetUserParams{
					ID: userID,
				}).Return(currentUser, nil)

				// Mock the efficient bulk validation - only return data for supporter1, not nonexistent
				mockDB.On("GetSupportersByUsernames", mock.Anything, []string{"supporter1", "nonexistent"}, mock.AnythingOfType("int32")).Return([]models.GetSupportersByUsernamesRow{
					{Username: "supporter1", IsOldEnough: true, HasFraudFlag: false, Email: pgtype.Text{String: "supporter1@example.com", Valid: true}},
					// nonexistent user is not returned, simulating that they don't exist
				}, nil)
			},
			wantErr:   true,
			errorCode: apierrors.ErrCodeInvalidSupporters,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockDB.ExpectedCalls = nil
			tt.setupMocks()

			err := validator.validateSupporters(ctx, tt.supporters, userID)

			if tt.wantErr {
				assert.Error(t, err)
				if validationErr, ok := err.(*ValidationError); ok {
					assert.Equal(t, tt.errorCode, validationErr.Code)
				}
			} else {
				assert.NoError(t, err)
			}

			mockDB.AssertExpectations(t)
		})
	}
}

func TestValidateUserChannelLimits(t *testing.T) {
	validator, mockDB := setupChannelValidationTest()
	ctx := context.Background()
	userID := int32(123)

	tests := []struct {
		name       string
		setupMocks func()
		wantErr    bool
		errorCode  string
	}{
		{
			name: "within limits",
			setupMocks: func() {
				mockDB.On("GetUserChannelCount", mock.Anything, userID).Return(int64(0), nil)
				mockDB.On("GetUserChannelLimit", mock.Anything, mock.AnythingOfType("models.GetUserChannelLimitParams")).Return(int32(1), nil)
			},
			wantErr: false,
		},
		{
			name: "reached channel limit",
			setupMocks: func() {
				mockDB.On("GetUserChannelCount", mock.Anything, userID).Return(int64(1), nil)
				mockDB.On("GetUserChannelLimit", mock.Anything, mock.AnythingOfType("models.GetUserChannelLimitParams")).Return(int32(1), nil)
			},
			wantErr:   true,
			errorCode: apierrors.ErrCodeChannelLimitReached,
		},
		{
			name: "cooldown period active",
			setupMocks: func() {
				mockDB.On("GetUserChannelCount", mock.Anything, userID).Return(int64(1), nil)
				mockDB.On("GetUserChannelLimit", mock.Anything, mock.AnythingOfType("models.GetUserChannelLimitParams")).Return(int32(5), nil)
				// Last registration was 1 hour ago (within 7-day cooldown)
				lastReg := pgtype.Int4{Int32: int32(time.Now().Add(-1 * time.Hour).Unix()), Valid: true}
				mockDB.On("GetLastChannelRegistration", mock.Anything, userID).Return(lastReg, nil)
			},
			wantErr:   true,
			errorCode: apierrors.ErrCodeCooldownPeriod,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockDB.ExpectedCalls = nil
			tt.setupMocks()

			err := validator.ValidateUserChannelLimits(ctx, userID)

			if tt.wantErr {
				assert.Error(t, err)
				if validationErr, ok := err.(*ValidationError); ok {
					assert.Equal(t, tt.errorCode, validationErr.Code)
				}
			} else {
				assert.NoError(t, err)
			}

			mockDB.AssertExpectations(t)
		})
	}
}

func TestValidateUserIRCActivity(t *testing.T) {
	validator, mockDB := setupChannelValidationTest()
	ctx := context.Background()
	userID := int32(123)

	tests := []struct {
		name       string
		setupMocks func()
		wantErr    bool
		errorCode  string
	}{
		{
			name: "recently active user",
			setupMocks: func() {
				recentTime := pgtype.Int4{Int32: int32(time.Now().Add(-1 * time.Hour).Unix()), Valid: true}
				user := models.GetUserRow{
					ID:       userID,
					Username: "testuser",
					LastSeen: recentTime,
				}
				mockDB.On("GetUser", mock.Anything, models.GetUserParams{
					ID: userID,
				}).Return(user, nil)
			},
			wantErr: false,
		},
		{
			name: "inactive user",
			setupMocks: func() {
				oldTime := pgtype.Int4{Int32: int32(time.Now().Add(-8 * 24 * time.Hour).Unix()), Valid: true}
				user := models.GetUserRow{
					ID:       userID,
					Username: "testuser",
					LastSeen: oldTime,
				}
				mockDB.On("GetUser", mock.Anything, models.GetUserParams{
					ID: userID,
				}).Return(user, nil)
			},
			wantErr:   true,
			errorCode: apierrors.ErrCodeInactiveUser,
		},
		{
			name: "no activity data",
			setupMocks: func() {
				noTime := pgtype.Int4{Valid: false}
				user := models.GetUserRow{
					ID:       userID,
					Username: "testuser",
					LastSeen: noTime,
				}
				mockDB.On("GetUser", mock.Anything, models.GetUserParams{
					ID: userID,
				}).Return(user, nil)
			},
			wantErr:   true,
			errorCode: apierrors.ErrCodeInactiveUser,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockDB.ExpectedCalls = nil
			tt.setupMocks()

			err := validator.ValidateUserIRCActivity(ctx, userID)

			if tt.wantErr {
				assert.Error(t, err)
				if validationErr, ok := err.(*ValidationError); ok {
					assert.Equal(t, tt.errorCode, validationErr.Code)
				}
			} else {
				assert.NoError(t, err)
			}

			mockDB.AssertExpectations(t)
		})
	}
}

func TestValidateChannelNameAvailability(t *testing.T) {
	validator, mockDB := setupChannelValidationTest()
	ctx := context.Background()
	channelName := "#testchannel"

	tests := []struct {
		name       string
		setupMocks func()
		wantErr    bool
		errorCode  string
	}{
		{
			name: "channel name available",
			setupMocks: func() {
				mockDB.On("CheckChannelNameExists", mock.Anything, channelName).Return(models.CheckChannelNameExistsRow{}, assert.AnError)
			},
			wantErr: false,
		},
		{
			name: "channel name already exists",
			setupMocks: func() {
				existingChannel := models.CheckChannelNameExistsRow{
					ID:   123,
					Name: channelName,
				}
				mockDB.On("CheckChannelNameExists", mock.Anything, channelName).Return(existingChannel, nil)
			},
			wantErr:   true,
			errorCode: apierrors.ErrCodeChannelAlreadyExists,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockDB.ExpectedCalls = nil
			tt.setupMocks()

			err := validator.ValidateChannelNameAvailability(ctx, channelName)

			if tt.wantErr {
				assert.Error(t, err)
				if validationErr, ok := err.(*ValidationError); ok {
					assert.Equal(t, tt.errorCode, validationErr.Code)
				}
			} else {
				assert.NoError(t, err)
			}

			mockDB.AssertExpectations(t)
		})
	}
}

func TestValidateUserNoregStatus(t *testing.T) {
	validator, mockDB := setupChannelValidationTest()
	ctx := context.Background()
	userID := int32(123)

	currentUser := models.GetUserRow{
		ID:       userID,
		Username: "testuser",
	}

	tests := []struct {
		name       string
		setupMocks func()
		wantErr    bool
		errorCode  string
	}{
		{
			name: "user not restricted",
			setupMocks: func() {
				mockDB.On("GetUser", mock.Anything, models.GetUserParams{
					ID: userID,
				}).Return(currentUser, nil)
				mockDB.On("CheckUserNoregStatus", mock.Anything, "testuser").Return(false, nil)
			},
			wantErr: false,
		},
		{
			name: "user has NOREG restriction",
			setupMocks: func() {
				mockDB.On("GetUser", mock.Anything, models.GetUserParams{
					ID: userID,
				}).Return(currentUser, nil)
				mockDB.On("CheckUserNoregStatus", mock.Anything, "testuser").Return(true, nil)
			},
			wantErr:   true,
			errorCode: apierrors.ErrCodeUserRestricted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockDB.ExpectedCalls = nil
			tt.setupMocks()

			err := validator.ValidateUserNoregStatus(ctx, userID)

			if tt.wantErr {
				assert.Error(t, err)
				if validationErr, ok := err.(*ValidationError); ok {
					assert.Equal(t, tt.errorCode, validationErr.Code)
				}
			} else {
				assert.NoError(t, err)
			}

			mockDB.AssertExpectations(t)
		})
	}
}

func TestValidateChannelRegistrationRequest(t *testing.T) {
	ctx := context.Background()
	userID := int32(123)

	t.Run("full validation pass", func(t *testing.T) {
		validator, mockDB := setupChannelValidationTest()

		req := &ChannelRegistrationRequest{
			ChannelName: "#goodchan",
			Description: "A nice channel",
			Supporters:  []string{"supporter1", "supporter2"},
		}

		currentUser := models.GetUserRow{ID: userID, Username: "testuser"}
		mockDB.On("GetUser", mock.Anything, models.GetUserParams{ID: userID}).Return(currentUser, nil)
		mockDB.On("GetSupportersByUsernames", mock.Anything, []string{"supporter1", "supporter2"}, mock.AnythingOfType("int32")).Return([]models.GetSupportersByUsernamesRow{
			{Username: "supporter1", IsOldEnough: true, HasFraudFlag: false, Email: pgtype.Text{String: "s1@example.com", Valid: true}},
			{Username: "supporter2", IsOldEnough: true, HasFraudFlag: false, Email: pgtype.Text{String: "s2@example.com", Valid: true}},
		}, nil)
		mockDB.On("CheckMultipleSupportersNoregStatus", mock.Anything, []string{"supporter1", "supporter2"}).Return([]models.CheckMultipleSupportersNoregStatusRow{
			{Username: "supporter1", IsNoreg: false},
			{Username: "supporter2", IsNoreg: false},
		}, nil)
		mockDB.On("CheckMultipleSupportersConcurrentSupports", mock.Anything, []string{"supporter1", "supporter2"}, mock.AnythingOfType("int32")).Return([]models.CheckMultipleSupportersConcurrentSupportsRow{
			{Username: "supporter1", ExceedsLimit: false},
			{Username: "supporter2", ExceedsLimit: false},
		}, nil)

		err := validator.ValidateChannelRegistrationRequest(ctx, req, userID)
		assert.NoError(t, err)
		mockDB.AssertExpectations(t)
	})

	t.Run("basic struct validation failure", func(t *testing.T) {
		validator, _ := setupChannelValidationTest()

		req := &ChannelRegistrationRequest{
			ChannelName: "", // required field missing
			Description: "A nice channel",
			Supporters:  []string{"supporter1", "supporter2"},
		}

		err := validator.ValidateChannelRegistrationRequest(ctx, req, userID)
		assert.Error(t, err)
		validationErr, ok := err.(*ValidationError)
		assert.True(t, ok)
		assert.Equal(t, apierrors.ErrCodeValidation, validationErr.Code)
	})

	t.Run("channel name validation failure", func(t *testing.T) {
		validator, _ := setupChannelValidationTest()

		req := &ChannelRegistrationRequest{
			ChannelName: "#bad channel", // contains space
			Description: "A nice channel",
			Supporters:  []string{"supporter1", "supporter2"},
		}

		err := validator.ValidateChannelRegistrationRequest(ctx, req, userID)
		assert.Error(t, err)
		validationErr, ok := err.(*ValidationError)
		assert.True(t, ok)
		assert.Equal(t, apierrors.ErrCodeInvalidChannelName, validationErr.Code)
	})

	t.Run("description validation failure", func(t *testing.T) {
		validator, _ := setupChannelValidationTest()

		req := &ChannelRegistrationRequest{
			ChannelName: "#goodchan",
			Description: "<script>alert('xss')</script>",
			Supporters:  []string{"supporter1", "supporter2"},
		}

		err := validator.ValidateChannelRegistrationRequest(ctx, req, userID)
		assert.Error(t, err)
		validationErr, ok := err.(*ValidationError)
		assert.True(t, ok)
		assert.Equal(t, apierrors.ErrCodeInvalidDescription, validationErr.Code)
	})

	t.Run("supporter validation failure", func(t *testing.T) {
		validator, _ := setupChannelValidationTest()

		req := &ChannelRegistrationRequest{
			ChannelName: "#goodchan",
			Description: "A nice channel",
			Supporters:  []string{"supporter1"}, // insufficient, need 2
		}

		err := validator.ValidateChannelRegistrationRequest(ctx, req, userID)
		assert.Error(t, err)
		validationErr, ok := err.(*ValidationError)
		assert.True(t, ok)
		assert.Equal(t, apierrors.ErrCodeInsufficientSupporters, validationErr.Code)
	})
}

func TestValidateChannelRegistrationWithAdminBypass(t *testing.T) {
	ctx := context.Background()
	userID := int32(123)
	adminLevel := int32(800)

	t.Run("admin goes through full validation - no bypass for basic validation", func(t *testing.T) {
		validator, mockDB := setupChannelValidationTest()

		req := &ChannelRegistrationRequest{
			ChannelName: "#goodchan",
			Description: "A nice channel",
			Supporters:  []string{"supporter1", "supporter2"},
		}

		currentUser := models.GetUserRow{ID: userID, Username: "testuser"}
		mockDB.On("GetUser", mock.Anything, models.GetUserParams{ID: userID}).Return(currentUser, nil)
		mockDB.On("GetSupportersByUsernames", mock.Anything, []string{"supporter1", "supporter2"}, mock.AnythingOfType("int32")).Return([]models.GetSupportersByUsernamesRow{
			{Username: "supporter1", IsOldEnough: true, HasFraudFlag: false, Email: pgtype.Text{String: "s1@example.com", Valid: true}},
			{Username: "supporter2", IsOldEnough: true, HasFraudFlag: false, Email: pgtype.Text{String: "s2@example.com", Valid: true}},
		}, nil)
		mockDB.On("CheckMultipleSupportersNoregStatus", mock.Anything, []string{"supporter1", "supporter2"}).Return([]models.CheckMultipleSupportersNoregStatusRow{
			{Username: "supporter1", IsNoreg: false},
			{Username: "supporter2", IsNoreg: false},
		}, nil)
		mockDB.On("CheckMultipleSupportersConcurrentSupports", mock.Anything, []string{"supporter1", "supporter2"}, mock.AnythingOfType("int32")).Return([]models.CheckMultipleSupportersConcurrentSupportsRow{
			{Username: "supporter1", ExceedsLimit: false},
			{Username: "supporter2", ExceedsLimit: false},
		}, nil)

		bypasses, err := validator.ValidateChannelRegistrationWithAdminBypass(ctx, req, userID, adminLevel)
		assert.NoError(t, err)
		assert.Empty(t, bypasses)
		mockDB.AssertExpectations(t)
	})

	t.Run("non-admin fails basic validation", func(t *testing.T) {
		validator, _ := setupChannelValidationTest()

		req := &ChannelRegistrationRequest{
			ChannelName: "", // invalid
			Description: "A nice channel",
			Supporters:  []string{"supporter1", "supporter2"},
		}

		bypasses, err := validator.ValidateChannelRegistrationWithAdminBypass(ctx, req, userID, int32(0))
		assert.Error(t, err)
		assert.Nil(t, bypasses)
		validationErr, ok := err.(*ValidationError)
		assert.True(t, ok)
		assert.Equal(t, apierrors.ErrCodeValidation, validationErr.Code)
	})

	t.Run("admin also fails basic struct validation - no bypass", func(t *testing.T) {
		validator, _ := setupChannelValidationTest()

		req := &ChannelRegistrationRequest{
			ChannelName: "", // required field missing
			Description: "A nice channel",
			Supporters:  []string{"supporter1", "supporter2"},
		}

		bypasses, err := validator.ValidateChannelRegistrationWithAdminBypass(ctx, req, userID, adminLevel)
		assert.Error(t, err)
		assert.Nil(t, bypasses)
	})
}

func TestValidateUserNoregStatusWithAdminBypass(t *testing.T) {
	ctx := context.Background()
	userID := int32(123)
	currentUser := models.GetUserRow{ID: userID, Username: "testuser"}

	t.Run("admin cannot bypass noreg - user is restricted", func(t *testing.T) {
		validator, mockDB := setupChannelValidationTest()

		mockDB.On("GetUser", mock.Anything, models.GetUserParams{ID: userID}).Return(currentUser, nil)
		mockDB.On("CheckUserNoregStatus", mock.Anything, "testuser").Return(true, nil)

		bypasses, err := validator.ValidateUserNoregStatusWithAdminBypass(ctx, userID, int32(1000))
		assert.Error(t, err)
		assert.Nil(t, bypasses)
		validationErr, ok := err.(*ValidationError)
		assert.True(t, ok)
		assert.Equal(t, apierrors.ErrCodeUserRestricted, validationErr.Code)
		mockDB.AssertExpectations(t)
	})

	t.Run("user not restricted - passes", func(t *testing.T) {
		validator, mockDB := setupChannelValidationTest()

		mockDB.On("GetUser", mock.Anything, models.GetUserParams{ID: userID}).Return(currentUser, nil)
		mockDB.On("CheckUserNoregStatus", mock.Anything, "testuser").Return(false, nil)

		bypasses, err := validator.ValidateUserNoregStatusWithAdminBypass(ctx, userID, int32(0))
		assert.NoError(t, err)
		assert.Nil(t, bypasses)
		mockDB.AssertExpectations(t)
	})
}

func TestValidateUserChannelLimitsWithAdminBypass(t *testing.T) {
	ctx := context.Background()
	userID := int32(123)

	t.Run("admin bypasses multiple channel restriction", func(t *testing.T) {
		validator, mockDB := setupChannelValidationTest()
		config.ServiceChannelRegAllowMultiple.Set(false)

		mockDB.On("GetUserChannels", mock.Anything, userID).Return([]models.GetUserChannelsRow{
			{Name: "#existing", ChannelID: 1, UserID: userID},
		}, nil)

		bypasses, err := validator.ValidateUserChannelLimitsWithAdminBypass(ctx, userID, int32(1))
		assert.NoError(t, err)
		assert.Len(t, bypasses, 1)
		assert.Equal(t, "MULTIPLE_CHANNEL_BYPASS", bypasses[0].BypassType)
		mockDB.AssertExpectations(t)
	})

	t.Run("non-admin blocked by multiple channel restriction", func(t *testing.T) {
		validator, mockDB := setupChannelValidationTest()
		config.ServiceChannelRegAllowMultiple.Set(false)

		mockDB.On("GetUserChannels", mock.Anything, userID).Return([]models.GetUserChannelsRow{
			{Name: "#existing", ChannelID: 1, UserID: userID},
		}, nil)

		bypasses, err := validator.ValidateUserChannelLimitsWithAdminBypass(ctx, userID, int32(0))
		assert.Error(t, err)
		assert.Nil(t, bypasses)
		validationErr, ok := err.(*ValidationError)
		assert.True(t, ok)
		assert.Equal(t, apierrors.ErrCodeChannelLimitExceeded, validationErr.Code)
		mockDB.AssertExpectations(t)
	})

	t.Run("admin bypasses general channel limit", func(t *testing.T) {
		validator, mockDB := setupChannelValidationTest()
		config.ServiceChannelRegAllowMultiple.Set(true)

		// Simulate ValidateUserChannelLimits returning an error (at limit)
		mockDB.On("GetUserChannelCount", mock.Anything, userID).Return(int64(1), nil)
		mockDB.On("GetUserChannelLimit", mock.Anything, mock.AnythingOfType("models.GetUserChannelLimitParams")).Return(int32(1), nil)

		bypasses, err := validator.ValidateUserChannelLimitsWithAdminBypass(ctx, userID, int32(1))
		assert.NoError(t, err)
		assert.Len(t, bypasses, 1)
		assert.Equal(t, "CHANNEL_LIMIT_BYPASS", bypasses[0].BypassType)
		mockDB.AssertExpectations(t)
	})

	t.Run("non-admin blocked by general channel limit", func(t *testing.T) {
		validator, mockDB := setupChannelValidationTest()
		config.ServiceChannelRegAllowMultiple.Set(true)

		mockDB.On("GetUserChannelCount", mock.Anything, userID).Return(int64(1), nil)
		mockDB.On("GetUserChannelLimit", mock.Anything, mock.AnythingOfType("models.GetUserChannelLimitParams")).Return(int32(1), nil)

		bypasses, err := validator.ValidateUserChannelLimitsWithAdminBypass(ctx, userID, int32(0))
		assert.Error(t, err)
		assert.Nil(t, bypasses)
		validationErr, ok := err.(*ValidationError)
		assert.True(t, ok)
		assert.Equal(t, apierrors.ErrCodeChannelLimitReached, validationErr.Code)
		mockDB.AssertExpectations(t)
	})

	t.Run("no existing channels - passes without bypass", func(t *testing.T) {
		validator, mockDB := setupChannelValidationTest()
		config.ServiceChannelRegAllowMultiple.Set(false)

		mockDB.On("GetUserChannels", mock.Anything, userID).Return([]models.GetUserChannelsRow{}, nil)
		mockDB.On("GetUserChannelCount", mock.Anything, userID).Return(int64(0), nil)
		mockDB.On("GetUserChannelLimit", mock.Anything, mock.AnythingOfType("models.GetUserChannelLimitParams")).Return(int32(1), nil)

		bypasses, err := validator.ValidateUserChannelLimitsWithAdminBypass(ctx, userID, int32(0))
		assert.NoError(t, err)
		assert.Empty(t, bypasses)
		mockDB.AssertExpectations(t)
	})

	t.Run("database error on GetUserChannels", func(t *testing.T) {
		validator, mockDB := setupChannelValidationTest()
		config.ServiceChannelRegAllowMultiple.Set(false)

		mockDB.On("GetUserChannels", mock.Anything, userID).Return([]models.GetUserChannelsRow(nil), assert.AnError)

		bypasses, err := validator.ValidateUserChannelLimitsWithAdminBypass(ctx, userID, int32(0))
		assert.Error(t, err)
		assert.Nil(t, bypasses)
		validationErr, ok := err.(*ValidationError)
		assert.True(t, ok)
		assert.Equal(t, apierrors.ErrCodeDatabaseError, validationErr.Code)
		mockDB.AssertExpectations(t)
	})
}

func TestValidatePendingRegistrationsWithAdminBypass(t *testing.T) {
	ctx := context.Background()
	userID := int32(123)

	t.Run("admin bypasses pending registration restriction", func(t *testing.T) {
		validator, mockDB := setupChannelValidationTest()

		mockDB.On("GetUserPendingRegistrations", mock.Anything, pgtype.Int4{Int32: userID, Valid: true}).Return(int64(1), nil)

		bypasses, err := validator.ValidatePendingRegistrationsWithAdminBypass(ctx, userID, int32(800))
		assert.NoError(t, err)
		assert.Len(t, bypasses, 1)
		assert.Equal(t, "PENDING_REGISTRATION_BYPASS", bypasses[0].BypassType)
		mockDB.AssertExpectations(t)
	})

	t.Run("lower admin cannot bypass pending registration", func(t *testing.T) {
		validator, mockDB := setupChannelValidationTest()

		mockDB.On("GetUserPendingRegistrations", mock.Anything, pgtype.Int4{Int32: userID, Valid: true}).Return(int64(1), nil)

		bypasses, err := validator.ValidatePendingRegistrationsWithAdminBypass(ctx, userID, int32(799))
		assert.Error(t, err)
		assert.Nil(t, bypasses)
		validationErr, ok := err.(*ValidationError)
		assert.True(t, ok)
		assert.Equal(t, apierrors.ErrCodePendingExists, validationErr.Code)
		mockDB.AssertExpectations(t)
	})

	t.Run("non-admin blocked by pending registration", func(t *testing.T) {
		validator, mockDB := setupChannelValidationTest()

		mockDB.On("GetUserPendingRegistrations", mock.Anything, pgtype.Int4{Int32: userID, Valid: true}).Return(int64(2), nil)

		bypasses, err := validator.ValidatePendingRegistrationsWithAdminBypass(ctx, userID, int32(0))
		assert.Error(t, err)
		assert.Nil(t, bypasses)
		validationErr, ok := err.(*ValidationError)
		assert.True(t, ok)
		assert.Equal(t, apierrors.ErrCodePendingExists, validationErr.Code)
		mockDB.AssertExpectations(t)
	})

	t.Run("no pending registrations - passes", func(t *testing.T) {
		validator, mockDB := setupChannelValidationTest()

		mockDB.On("GetUserPendingRegistrations", mock.Anything, pgtype.Int4{Int32: userID, Valid: true}).Return(int64(0), nil)

		bypasses, err := validator.ValidatePendingRegistrationsWithAdminBypass(ctx, userID, int32(0))
		assert.NoError(t, err)
		assert.Empty(t, bypasses)
		mockDB.AssertExpectations(t)
	})

	t.Run("database error", func(t *testing.T) {
		validator, mockDB := setupChannelValidationTest()

		mockDB.On("GetUserPendingRegistrations", mock.Anything, pgtype.Int4{Int32: userID, Valid: true}).Return(int64(0), assert.AnError)

		bypasses, err := validator.ValidatePendingRegistrationsWithAdminBypass(ctx, userID, int32(0))
		assert.Error(t, err)
		assert.Nil(t, bypasses)
		validationErr, ok := err.(*ValidationError)
		assert.True(t, ok)
		assert.Equal(t, apierrors.ErrCodeDatabaseError, validationErr.Code)
		mockDB.AssertExpectations(t)
	})
}

func TestValidateChannelNameAvailabilityWithAdminBypass(t *testing.T) {
	ctx := context.Background()
	channelName := "#testchannel"

	t.Run("admin cannot bypass - name taken", func(t *testing.T) {
		validator, mockDB := setupChannelValidationTest()

		mockDB.On("CheckChannelNameExists", mock.Anything, channelName).Return(models.CheckChannelNameExistsRow{ID: 1, Name: channelName}, nil)

		bypasses, err := validator.ValidateChannelNameAvailabilityWithAdminBypass(ctx, channelName, int32(1000))
		assert.Error(t, err)
		assert.Nil(t, bypasses)
		validationErr, ok := err.(*ValidationError)
		assert.True(t, ok)
		assert.Equal(t, apierrors.ErrCodeChannelAlreadyExists, validationErr.Code)
		mockDB.AssertExpectations(t)
	})

	t.Run("name available - passes", func(t *testing.T) {
		validator, mockDB := setupChannelValidationTest()

		mockDB.On("CheckChannelNameExists", mock.Anything, channelName).Return(models.CheckChannelNameExistsRow{}, assert.AnError)

		bypasses, err := validator.ValidateChannelNameAvailabilityWithAdminBypass(ctx, channelName, int32(0))
		assert.NoError(t, err)
		assert.Nil(t, bypasses)
		mockDB.AssertExpectations(t)
	})
}

func TestValidateUserIRCActivityWithAdminBypass(t *testing.T) {
	ctx := context.Background()
	userID := int32(123)

	t.Run("admin cannot bypass - insufficient activity", func(t *testing.T) {
		validator, mockDB := setupChannelValidationTest()

		oldTime := pgtype.Int4{Int32: int32(time.Now().Add(-8 * 24 * time.Hour).Unix()), Valid: true}
		user := models.GetUserRow{ID: userID, Username: "testuser", LastSeen: oldTime}
		mockDB.On("GetUser", mock.Anything, models.GetUserParams{ID: userID}).Return(user, nil)

		bypasses, err := validator.ValidateUserIRCActivityWithAdminBypass(ctx, userID, int32(1000))
		assert.Error(t, err)
		assert.Nil(t, bypasses)
		validationErr, ok := err.(*ValidationError)
		assert.True(t, ok)
		assert.Equal(t, apierrors.ErrCodeInactiveUser, validationErr.Code)
		mockDB.AssertExpectations(t)
	})

	t.Run("recently active - passes", func(t *testing.T) {
		validator, mockDB := setupChannelValidationTest()

		recentTime := pgtype.Int4{Int32: int32(time.Now().Add(-1 * time.Hour).Unix()), Valid: true}
		user := models.GetUserRow{ID: userID, Username: "testuser", LastSeen: recentTime}
		mockDB.On("GetUser", mock.Anything, models.GetUserParams{ID: userID}).Return(user, nil)

		bypasses, err := validator.ValidateUserIRCActivityWithAdminBypass(ctx, userID, int32(0))
		assert.NoError(t, err)
		assert.Nil(t, bypasses)
		mockDB.AssertExpectations(t)
	})
}
