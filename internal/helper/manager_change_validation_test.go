// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package helper

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks "github.com/undernetirc/cservice-api/db/mocks"
	apierrors "github.com/undernetirc/cservice-api/internal/errors"
	"github.com/undernetirc/cservice-api/models"
)

func TestNewManagerChangeValidator(t *testing.T) {
	mockDB := mocks.NewServiceInterface(t)
	validator := NewManagerChangeValidator(mockDB)
	require.NotNil(t, validator)
}

// setupAllMocksForValid sets up mocks for a fully valid manager change scenario
func setupAllMocksForValid(mockDB *mocks.ServiceInterface, channelID, userID, newManagerID int32) {
	oldRegisteredTs := int32(time.Now().Add(-365 * 24 * time.Hour).Unix()) // 1 year ago
	oldSignupTs := int32(time.Now().Add(-365 * 24 * time.Hour).Unix())     // 1 year ago

	mockDB.On("CheckUserChannelOwnership", mock.Anything, userID, channelID).
		Return(models.CheckUserChannelOwnershipRow{
			Name:         "#testchannel",
			ID:           channelID,
			RegisteredTs: pgtype.Int4{Int32: oldRegisteredTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, channelID).
		Return(models.CheckChannelExistsAndRegisteredRow{
			ID:           channelID,
			Name:         "#testchannel",
			RegisteredTs: pgtype.Int4{Int32: oldRegisteredTs, Valid: true},
		}, nil).Once()

	mockDB.On("GetUser", mock.Anything, models.GetUserParams{Username: "newmanager"}).
		Return(models.GetUserRow{
			ID:       newManagerID,
			Username: "newmanager",
			SignupTs: pgtype.Int4{Int32: oldSignupTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckNewManagerChannelAccess", mock.Anything, channelID, newManagerID).
		Return(models.CheckNewManagerChannelAccessRow{
			Username: "newmanager",
			ID:       newManagerID,
			SignupTs: pgtype.Int4{Int32: oldSignupTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckExistingPendingRequests", mock.Anything, channelID).
		Return([]models.CheckExistingPendingRequestsRow{}, nil).Once()

	mockDB.On("CheckUserOwnsOtherChannels", mock.Anything, newManagerID).
		Return(false, nil).Once()

	mockDB.On("CheckChannelSingleManager", mock.Anything, channelID).
		Return(int64(1), nil).Once()

	mockDB.On("CheckUserCooldownStatus", mock.Anything, userID).
		Return(models.CheckUserCooldownStatusRow{
			PostForms:        0,
			Verificationdata: pgtype.Text{String: "verified", Valid: true},
			Email:            pgtype.Text{String: "test@example.com", Valid: true},
		}, nil).Once()
}

func TestValidateManagerChangeBusinessRules_Valid(t *testing.T) {
	mockDB := mocks.NewServiceInterface(t)
	validator := NewManagerChangeValidator(mockDB)

	channelID := int32(1)
	userID := int32(100)
	newManagerID := int32(200)

	setupAllMocksForValid(mockDB, channelID, userID, newManagerID)

	err := validator.ValidateManagerChangeBusinessRules(
		context.Background(),
		channelID,
		userID,
		"newmanager",
		"permanent",
	)

	assert.NoError(t, err)
	mockDB.AssertExpectations(t)
}

func TestValidateManagerChangeBusinessRules_InsufficientPerms(t *testing.T) {
	mockDB := mocks.NewServiceInterface(t)
	validator := NewManagerChangeValidator(mockDB)

	mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
		Return(models.CheckUserChannelOwnershipRow{}, errors.New("no rows")).Once()

	err := validator.ValidateManagerChangeBusinessRules(
		context.Background(),
		int32(1),
		int32(100),
		"newmanager",
		"permanent",
	)

	require.Error(t, err)
	var valErr *ValidationError
	require.True(t, errors.As(err, &valErr))
	assert.Equal(t, apierrors.ErrCodeForbidden, valErr.Code)
	assert.Equal(t, "User is not channel owner", valErr.Message)
	mockDB.AssertExpectations(t)
}

func TestValidateManagerChangeBusinessRules_ChannelNotFound(t *testing.T) {
	mockDB := mocks.NewServiceInterface(t)
	validator := NewManagerChangeValidator(mockDB)

	mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
		Return(models.CheckUserChannelOwnershipRow{
			Name: "#testchannel",
			ID:   1,
		}, nil).Once()

	mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, int32(1)).
		Return(models.CheckChannelExistsAndRegisteredRow{}, errors.New("no rows")).Once()

	err := validator.ValidateManagerChangeBusinessRules(
		context.Background(),
		int32(1),
		int32(100),
		"newmanager",
		"permanent",
	)

	require.Error(t, err)
	var valErr *ValidationError
	require.True(t, errors.As(err, &valErr))
	assert.Equal(t, apierrors.ErrCodeNotFound, valErr.Code)
	assert.Contains(t, valErr.Message, "Channel not found")
	mockDB.AssertExpectations(t)
}

func TestValidateManagerChangeBusinessRules_ChannelTooNew(t *testing.T) {
	mockDB := mocks.NewServiceInterface(t)
	validator := NewManagerChangeValidator(mockDB)

	recentTs := int32(time.Now().Add(-30 * 24 * time.Hour).Unix()) // 30 days ago

	mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
		Return(models.CheckUserChannelOwnershipRow{
			Name:         "#testchannel",
			ID:           1,
			RegisteredTs: pgtype.Int4{Int32: recentTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, int32(1)).
		Return(models.CheckChannelExistsAndRegisteredRow{
			ID:           1,
			Name:         "#testchannel",
			RegisteredTs: pgtype.Int4{Int32: recentTs, Valid: true},
		}, nil).Once()

	err := validator.ValidateManagerChangeBusinessRules(
		context.Background(),
		int32(1),
		int32(100),
		"newmanager",
		"permanent",
	)

	require.Error(t, err)
	var valErr *ValidationError
	require.True(t, errors.As(err, &valErr))
	assert.Equal(t, apierrors.ErrCodeForbidden, valErr.Code)
	assert.Contains(t, valErr.Message, "90 days old")
	mockDB.AssertExpectations(t)
}

func TestValidateManagerChangeBusinessRules_UserNotFound(t *testing.T) {
	mockDB := mocks.NewServiceInterface(t)
	validator := NewManagerChangeValidator(mockDB)

	oldTs := int32(time.Now().Add(-365 * 24 * time.Hour).Unix())

	mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
		Return(models.CheckUserChannelOwnershipRow{
			Name:         "#testchannel",
			ID:           1,
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, int32(1)).
		Return(models.CheckChannelExistsAndRegisteredRow{
			ID:           1,
			Name:         "#testchannel",
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("GetUser", mock.Anything, models.GetUserParams{Username: "unknownuser"}).
		Return(models.GetUserRow{}, errors.New("no rows")).Once()

	err := validator.ValidateManagerChangeBusinessRules(
		context.Background(),
		int32(1),
		int32(100),
		"unknownuser",
		"permanent",
	)

	require.Error(t, err)
	var valErr *ValidationError
	require.True(t, errors.As(err, &valErr))
	assert.Equal(t, apierrors.ErrCodeNotFound, valErr.Code)
	assert.Contains(t, valErr.Message, "New manager username not found")
	mockDB.AssertExpectations(t)
}

func TestValidateManagerChangeBusinessRules_NewManagerNoAccess(t *testing.T) {
	mockDB := mocks.NewServiceInterface(t)
	validator := NewManagerChangeValidator(mockDB)

	oldTs := int32(time.Now().Add(-365 * 24 * time.Hour).Unix())

	mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
		Return(models.CheckUserChannelOwnershipRow{
			Name:         "#testchannel",
			ID:           1,
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, int32(1)).
		Return(models.CheckChannelExistsAndRegisteredRow{
			ID:           1,
			Name:         "#testchannel",
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("GetUser", mock.Anything, models.GetUserParams{Username: "newmanager"}).
		Return(models.GetUserRow{
			ID:       200,
			Username: "newmanager",
			SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckNewManagerChannelAccess", mock.Anything, int32(1), int32(200)).
		Return(models.CheckNewManagerChannelAccessRow{}, errors.New("no rows")).Once()

	err := validator.ValidateManagerChangeBusinessRules(
		context.Background(),
		int32(1),
		int32(100),
		"newmanager",
		"permanent",
	)

	require.Error(t, err)
	var valErr *ValidationError
	require.True(t, errors.As(err, &valErr))
	assert.Equal(t, apierrors.ErrCodeForbidden, valErr.Code)
	assert.Contains(t, valErr.Message, "level 499 access")
	mockDB.AssertExpectations(t)
}

func TestValidateManagerChangeBusinessRules_PendingExists(t *testing.T) {
	mockDB := mocks.NewServiceInterface(t)
	validator := NewManagerChangeValidator(mockDB)

	oldTs := int32(time.Now().Add(-365 * 24 * time.Hour).Unix())

	mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
		Return(models.CheckUserChannelOwnershipRow{
			Name:         "#testchannel",
			ID:           1,
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, int32(1)).
		Return(models.CheckChannelExistsAndRegisteredRow{
			ID:           1,
			Name:         "#testchannel",
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("GetUser", mock.Anything, models.GetUserParams{Username: "newmanager"}).
		Return(models.GetUserRow{
			ID:       200,
			Username: "newmanager",
			SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckNewManagerChannelAccess", mock.Anything, int32(1), int32(200)).
		Return(models.CheckNewManagerChannelAccessRow{
			Username: "newmanager",
			ID:       200,
			SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckExistingPendingRequests", mock.Anything, int32(1)).
		Return([]models.CheckExistingPendingRequestsRow{
			{ChannelID: 1},
		}, nil).Once()

	err := validator.ValidateManagerChangeBusinessRules(
		context.Background(),
		int32(1),
		int32(100),
		"newmanager",
		"permanent",
	)

	require.Error(t, err)
	var valErr *ValidationError
	require.True(t, errors.As(err, &valErr))
	assert.Equal(t, apierrors.ErrCodeConflict, valErr.Code)
	assert.Contains(t, valErr.Message, "pending manager change")
	mockDB.AssertExpectations(t)
}

func TestValidateManagerChangeBusinessRules_SelfAssignment(t *testing.T) {
	// Self-assignment is tested through the new manager account age and ownership checks.
	// The validation doesn't explicitly check for self-assignment since a user with level 500
	// can't also have level 499 on the same channel. We test that error path via
	// CheckNewManagerChannelAccess returning an error when the same user is both owner and target.
	mockDB := mocks.NewServiceInterface(t)
	validator := NewManagerChangeValidator(mockDB)

	oldTs := int32(time.Now().Add(-365 * 24 * time.Hour).Unix())

	mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
		Return(models.CheckUserChannelOwnershipRow{
			Name:         "#testchannel",
			ID:           1,
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, int32(1)).
		Return(models.CheckChannelExistsAndRegisteredRow{
			ID:           1,
			Name:         "#testchannel",
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	// User looks up themselves
	mockDB.On("GetUser", mock.Anything, models.GetUserParams{Username: "selfuser"}).
		Return(models.GetUserRow{
			ID:       100,
			Username: "selfuser",
			SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	// Self-assignment: user 100 trying to assign to user 100 - they can't have level 499
	mockDB.On("CheckNewManagerChannelAccess", mock.Anything, int32(1), int32(100)).
		Return(models.CheckNewManagerChannelAccessRow{}, errors.New("user does not have level 499")).Once()

	err := validator.ValidateManagerChangeBusinessRules(
		context.Background(),
		int32(1),
		int32(100),
		"selfuser",
		"permanent",
	)

	require.Error(t, err)
	var valErr *ValidationError
	require.True(t, errors.As(err, &valErr))
	assert.Equal(t, apierrors.ErrCodeForbidden, valErr.Code)
	mockDB.AssertExpectations(t)
}

func TestValidateManagerChangeBusinessRules_NewManagerAccountTooNew_Permanent(t *testing.T) {
	mockDB := mocks.NewServiceInterface(t)
	validator := NewManagerChangeValidator(mockDB)

	oldTs := int32(time.Now().Add(-365 * 24 * time.Hour).Unix())
	recentSignupTs := int32(time.Now().Add(-30 * 24 * time.Hour).Unix()) // 30 days ago

	mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
		Return(models.CheckUserChannelOwnershipRow{
			Name:         "#testchannel",
			ID:           1,
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, int32(1)).
		Return(models.CheckChannelExistsAndRegisteredRow{
			ID:           1,
			Name:         "#testchannel",
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("GetUser", mock.Anything, models.GetUserParams{Username: "newmanager"}).
		Return(models.GetUserRow{
			ID:       200,
			Username: "newmanager",
			SignupTs: pgtype.Int4{Int32: recentSignupTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckNewManagerChannelAccess", mock.Anything, int32(1), int32(200)).
		Return(models.CheckNewManagerChannelAccessRow{
			Username: "newmanager",
			ID:       200,
			SignupTs: pgtype.Int4{Int32: recentSignupTs, Valid: true},
		}, nil).Once()

	err := validator.ValidateManagerChangeBusinessRules(
		context.Background(),
		int32(1),
		int32(100),
		"newmanager",
		"permanent",
	)

	require.Error(t, err)
	var valErr *ValidationError
	require.True(t, errors.As(err, &valErr))
	assert.Equal(t, apierrors.ErrCodeForbidden, valErr.Code)
	assert.Contains(t, valErr.Message, "90 days old for permanent")
	mockDB.AssertExpectations(t)
}

func TestValidateManagerChangeBusinessRules_NewManagerAccountTooNew_Temporary(t *testing.T) {
	mockDB := mocks.NewServiceInterface(t)
	validator := NewManagerChangeValidator(mockDB)

	oldTs := int32(time.Now().Add(-365 * 24 * time.Hour).Unix())
	veryRecentSignupTs := int32(time.Now().Add(-10 * 24 * time.Hour).Unix()) // 10 days ago

	mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
		Return(models.CheckUserChannelOwnershipRow{
			Name:         "#testchannel",
			ID:           1,
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, int32(1)).
		Return(models.CheckChannelExistsAndRegisteredRow{
			ID:           1,
			Name:         "#testchannel",
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("GetUser", mock.Anything, models.GetUserParams{Username: "newmanager"}).
		Return(models.GetUserRow{
			ID:       200,
			Username: "newmanager",
			SignupTs: pgtype.Int4{Int32: veryRecentSignupTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckNewManagerChannelAccess", mock.Anything, int32(1), int32(200)).
		Return(models.CheckNewManagerChannelAccessRow{
			Username: "newmanager",
			ID:       200,
			SignupTs: pgtype.Int4{Int32: veryRecentSignupTs, Valid: true},
		}, nil).Once()

	err := validator.ValidateManagerChangeBusinessRules(
		context.Background(),
		int32(1),
		int32(100),
		"newmanager",
		"temporary",
	)

	require.Error(t, err)
	var valErr *ValidationError
	require.True(t, errors.As(err, &valErr))
	assert.Equal(t, apierrors.ErrCodeForbidden, valErr.Code)
	assert.Contains(t, valErr.Message, "30 days old for temporary")
	mockDB.AssertExpectations(t)
}

func TestValidateManagerChangeBusinessRules_OwnsOtherChannels(t *testing.T) {
	mockDB := mocks.NewServiceInterface(t)
	validator := NewManagerChangeValidator(mockDB)

	oldTs := int32(time.Now().Add(-365 * 24 * time.Hour).Unix())

	mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
		Return(models.CheckUserChannelOwnershipRow{
			Name:         "#testchannel",
			ID:           1,
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, int32(1)).
		Return(models.CheckChannelExistsAndRegisteredRow{
			ID:           1,
			Name:         "#testchannel",
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("GetUser", mock.Anything, models.GetUserParams{Username: "newmanager"}).
		Return(models.GetUserRow{
			ID:       200,
			Username: "newmanager",
			SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckNewManagerChannelAccess", mock.Anything, int32(1), int32(200)).
		Return(models.CheckNewManagerChannelAccessRow{
			Username: "newmanager",
			ID:       200,
			SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckExistingPendingRequests", mock.Anything, int32(1)).
		Return([]models.CheckExistingPendingRequestsRow{}, nil).Once()

	mockDB.On("CheckUserOwnsOtherChannels", mock.Anything, int32(200)).
		Return(true, nil).Once()

	err := validator.ValidateManagerChangeBusinessRules(
		context.Background(),
		int32(1),
		int32(100),
		"newmanager",
		"permanent",
	)

	require.Error(t, err)
	var valErr *ValidationError
	require.True(t, errors.As(err, &valErr))
	assert.Equal(t, apierrors.ErrCodeForbidden, valErr.Code)
	assert.Contains(t, valErr.Message, "already owns other channels")
	mockDB.AssertExpectations(t)
}

func TestValidateManagerChangeBusinessRules_MultipleManagers(t *testing.T) {
	mockDB := mocks.NewServiceInterface(t)
	validator := NewManagerChangeValidator(mockDB)

	oldTs := int32(time.Now().Add(-365 * 24 * time.Hour).Unix())

	mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
		Return(models.CheckUserChannelOwnershipRow{
			Name:         "#testchannel",
			ID:           1,
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, int32(1)).
		Return(models.CheckChannelExistsAndRegisteredRow{
			ID:           1,
			Name:         "#testchannel",
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("GetUser", mock.Anything, models.GetUserParams{Username: "newmanager"}).
		Return(models.GetUserRow{
			ID:       200,
			Username: "newmanager",
			SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckNewManagerChannelAccess", mock.Anything, int32(1), int32(200)).
		Return(models.CheckNewManagerChannelAccessRow{
			Username: "newmanager",
			ID:       200,
			SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckExistingPendingRequests", mock.Anything, int32(1)).
		Return([]models.CheckExistingPendingRequestsRow{}, nil).Once()

	mockDB.On("CheckUserOwnsOtherChannels", mock.Anything, int32(200)).
		Return(false, nil).Once()

	mockDB.On("CheckChannelSingleManager", mock.Anything, int32(1)).
		Return(int64(3), nil).Once()

	err := validator.ValidateManagerChangeBusinessRules(
		context.Background(),
		int32(1),
		int32(100),
		"newmanager",
		"permanent",
	)

	require.Error(t, err)
	var valErr *ValidationError
	require.True(t, errors.As(err, &valErr))
	assert.Equal(t, apierrors.ErrCodeForbidden, valErr.Code)
	assert.Contains(t, valErr.Message, "multiple managers")
	mockDB.AssertExpectations(t)
}

func TestValidateManagerChangeBusinessRules_NoVerificationData(t *testing.T) {
	mockDB := mocks.NewServiceInterface(t)
	validator := NewManagerChangeValidator(mockDB)

	oldTs := int32(time.Now().Add(-365 * 24 * time.Hour).Unix())

	mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
		Return(models.CheckUserChannelOwnershipRow{
			Name:         "#testchannel",
			ID:           1,
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, int32(1)).
		Return(models.CheckChannelExistsAndRegisteredRow{
			ID:           1,
			Name:         "#testchannel",
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("GetUser", mock.Anything, models.GetUserParams{Username: "newmanager"}).
		Return(models.GetUserRow{
			ID:       200,
			Username: "newmanager",
			SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckNewManagerChannelAccess", mock.Anything, int32(1), int32(200)).
		Return(models.CheckNewManagerChannelAccessRow{
			Username: "newmanager",
			ID:       200,
			SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckExistingPendingRequests", mock.Anything, int32(1)).
		Return([]models.CheckExistingPendingRequestsRow{}, nil).Once()

	mockDB.On("CheckUserOwnsOtherChannels", mock.Anything, int32(200)).
		Return(false, nil).Once()

	mockDB.On("CheckChannelSingleManager", mock.Anything, int32(1)).
		Return(int64(1), nil).Once()

	mockDB.On("CheckUserCooldownStatus", mock.Anything, int32(100)).
		Return(models.CheckUserCooldownStatusRow{
			PostForms:        0,
			Verificationdata: pgtype.Text{String: "", Valid: false},
			Email:            pgtype.Text{String: "test@example.com", Valid: true},
		}, nil).Once()

	err := validator.ValidateManagerChangeBusinessRules(
		context.Background(),
		int32(1),
		int32(100),
		"newmanager",
		"permanent",
	)

	require.Error(t, err)
	var valErr *ValidationError
	require.True(t, errors.As(err, &valErr))
	assert.Equal(t, apierrors.ErrCodeForbidden, valErr.Code)
	assert.Contains(t, valErr.Message, "verification information")
	mockDB.AssertExpectations(t)
}

func TestValidateManagerChangeBusinessRules_NoEmail(t *testing.T) {
	mockDB := mocks.NewServiceInterface(t)
	validator := NewManagerChangeValidator(mockDB)

	oldTs := int32(time.Now().Add(-365 * 24 * time.Hour).Unix())

	mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
		Return(models.CheckUserChannelOwnershipRow{
			Name:         "#testchannel",
			ID:           1,
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, int32(1)).
		Return(models.CheckChannelExistsAndRegisteredRow{
			ID:           1,
			Name:         "#testchannel",
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("GetUser", mock.Anything, models.GetUserParams{Username: "newmanager"}).
		Return(models.GetUserRow{
			ID:       200,
			Username: "newmanager",
			SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckNewManagerChannelAccess", mock.Anything, int32(1), int32(200)).
		Return(models.CheckNewManagerChannelAccessRow{
			Username: "newmanager",
			ID:       200,
			SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckExistingPendingRequests", mock.Anything, int32(1)).
		Return([]models.CheckExistingPendingRequestsRow{}, nil).Once()

	mockDB.On("CheckUserOwnsOtherChannels", mock.Anything, int32(200)).
		Return(false, nil).Once()

	mockDB.On("CheckChannelSingleManager", mock.Anything, int32(1)).
		Return(int64(1), nil).Once()

	mockDB.On("CheckUserCooldownStatus", mock.Anything, int32(100)).
		Return(models.CheckUserCooldownStatusRow{
			PostForms:        0,
			Verificationdata: pgtype.Text{String: "verified", Valid: true},
			Email:            pgtype.Text{String: "", Valid: false},
		}, nil).Once()

	err := validator.ValidateManagerChangeBusinessRules(
		context.Background(),
		int32(1),
		int32(100),
		"newmanager",
		"permanent",
	)

	require.Error(t, err)
	var valErr *ValidationError
	require.True(t, errors.As(err, &valErr))
	assert.Equal(t, apierrors.ErrCodeForbidden, valErr.Code)
	assert.Contains(t, valErr.Message, "email set")
	mockDB.AssertExpectations(t)
}

func TestValidateManagerChangeBusinessRules_CooldownActive(t *testing.T) {
	mockDB := mocks.NewServiceInterface(t)
	validator := NewManagerChangeValidator(mockDB)

	oldTs := int32(time.Now().Add(-365 * 24 * time.Hour).Unix())
	futureTs := int32(time.Now().Add(24 * time.Hour).Unix()) // 1 day from now

	mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
		Return(models.CheckUserChannelOwnershipRow{
			Name:         "#testchannel",
			ID:           1,
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, int32(1)).
		Return(models.CheckChannelExistsAndRegisteredRow{
			ID:           1,
			Name:         "#testchannel",
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("GetUser", mock.Anything, models.GetUserParams{Username: "newmanager"}).
		Return(models.GetUserRow{
			ID:       200,
			Username: "newmanager",
			SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckNewManagerChannelAccess", mock.Anything, int32(1), int32(200)).
		Return(models.CheckNewManagerChannelAccessRow{
			Username: "newmanager",
			ID:       200,
			SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckExistingPendingRequests", mock.Anything, int32(1)).
		Return([]models.CheckExistingPendingRequestsRow{}, nil).Once()

	mockDB.On("CheckUserOwnsOtherChannels", mock.Anything, int32(200)).
		Return(false, nil).Once()

	mockDB.On("CheckChannelSingleManager", mock.Anything, int32(1)).
		Return(int64(1), nil).Once()

	mockDB.On("CheckUserCooldownStatus", mock.Anything, int32(100)).
		Return(models.CheckUserCooldownStatusRow{
			PostForms:        futureTs,
			Verificationdata: pgtype.Text{String: "verified", Valid: true},
			Email:            pgtype.Text{String: "test@example.com", Valid: true},
		}, nil).Once()

	err := validator.ValidateManagerChangeBusinessRules(
		context.Background(),
		int32(1),
		int32(100),
		"newmanager",
		"permanent",
	)

	require.Error(t, err)
	var valErr *ValidationError
	require.True(t, errors.As(err, &valErr))
	assert.Equal(t, apierrors.ErrCodeBadRequest, valErr.Code)
	assert.Contains(t, valErr.Message, "form request after")
	mockDB.AssertExpectations(t)
}

func TestValidateManagerChangeBusinessRules_AccountLocked(t *testing.T) {
	mockDB := mocks.NewServiceInterface(t)
	validator := NewManagerChangeValidator(mockDB)

	oldTs := int32(time.Now().Add(-365 * 24 * time.Hour).Unix())

	mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
		Return(models.CheckUserChannelOwnershipRow{
			Name:         "#testchannel",
			ID:           1,
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, int32(1)).
		Return(models.CheckChannelExistsAndRegisteredRow{
			ID:           1,
			Name:         "#testchannel",
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("GetUser", mock.Anything, models.GetUserParams{Username: "newmanager"}).
		Return(models.GetUserRow{
			ID:       200,
			Username: "newmanager",
			SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckNewManagerChannelAccess", mock.Anything, int32(1), int32(200)).
		Return(models.CheckNewManagerChannelAccessRow{
			Username: "newmanager",
			ID:       200,
			SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckExistingPendingRequests", mock.Anything, int32(1)).
		Return([]models.CheckExistingPendingRequestsRow{}, nil).Once()

	mockDB.On("CheckUserOwnsOtherChannels", mock.Anything, int32(200)).
		Return(false, nil).Once()

	mockDB.On("CheckChannelSingleManager", mock.Anything, int32(1)).
		Return(int64(1), nil).Once()

	mockDB.On("CheckUserCooldownStatus", mock.Anything, int32(100)).
		Return(models.CheckUserCooldownStatusRow{
			PostForms:        666,
			Verificationdata: pgtype.Text{String: "verified", Valid: true},
			Email:            pgtype.Text{String: "test@example.com", Valid: true},
		}, nil).Once()

	err := validator.ValidateManagerChangeBusinessRules(
		context.Background(),
		int32(1),
		int32(100),
		"newmanager",
		"permanent",
	)

	require.Error(t, err)
	var valErr *ValidationError
	require.True(t, errors.As(err, &valErr))
	assert.Equal(t, apierrors.ErrCodeForbidden, valErr.Code)
	assert.Contains(t, valErr.Message, "locked from submitting forms")
	mockDB.AssertExpectations(t)
}

func TestValidateManagerChangeBusinessRules_DBError(t *testing.T) {
	t.Run("pending requests db error", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		validator := NewManagerChangeValidator(mockDB)

		oldTs := int32(time.Now().Add(-365 * 24 * time.Hour).Unix())

		mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
			Return(models.CheckUserChannelOwnershipRow{
				Name:         "#testchannel",
				ID:           1,
				RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
			}, nil).Once()

		mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, int32(1)).
			Return(models.CheckChannelExistsAndRegisteredRow{
				ID:           1,
				Name:         "#testchannel",
				RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
			}, nil).Once()

		mockDB.On("GetUser", mock.Anything, models.GetUserParams{Username: "newmanager"}).
			Return(models.GetUserRow{
				ID:       200,
				Username: "newmanager",
				SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
			}, nil).Once()

		mockDB.On("CheckNewManagerChannelAccess", mock.Anything, int32(1), int32(200)).
			Return(models.CheckNewManagerChannelAccessRow{
				Username: "newmanager",
				ID:       200,
				SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
			}, nil).Once()

		mockDB.On("CheckExistingPendingRequests", mock.Anything, int32(1)).
			Return([]models.CheckExistingPendingRequestsRow(nil), errors.New("connection refused")).Once()

		err := validator.ValidateManagerChangeBusinessRules(
			context.Background(),
			int32(1),
			int32(100),
			"newmanager",
			"permanent",
		)

		require.Error(t, err)
		var valErr *ValidationError
		require.True(t, errors.As(err, &valErr))
		assert.Equal(t, apierrors.ErrCodeDatabase, valErr.Code)
		mockDB.AssertExpectations(t)
	})

	t.Run("owns other channels db error", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		validator := NewManagerChangeValidator(mockDB)

		oldTs := int32(time.Now().Add(-365 * 24 * time.Hour).Unix())

		mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
			Return(models.CheckUserChannelOwnershipRow{
				Name:         "#testchannel",
				ID:           1,
				RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
			}, nil).Once()

		mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, int32(1)).
			Return(models.CheckChannelExistsAndRegisteredRow{
				ID:           1,
				Name:         "#testchannel",
				RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
			}, nil).Once()

		mockDB.On("GetUser", mock.Anything, models.GetUserParams{Username: "newmanager"}).
			Return(models.GetUserRow{
				ID:       200,
				Username: "newmanager",
				SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
			}, nil).Once()

		mockDB.On("CheckNewManagerChannelAccess", mock.Anything, int32(1), int32(200)).
			Return(models.CheckNewManagerChannelAccessRow{
				Username: "newmanager",
				ID:       200,
				SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
			}, nil).Once()

		mockDB.On("CheckExistingPendingRequests", mock.Anything, int32(1)).
			Return([]models.CheckExistingPendingRequestsRow{}, nil).Once()

		mockDB.On("CheckUserOwnsOtherChannels", mock.Anything, int32(200)).
			Return(false, errors.New("database timeout")).Once()

		err := validator.ValidateManagerChangeBusinessRules(
			context.Background(),
			int32(1),
			int32(100),
			"newmanager",
			"permanent",
		)

		require.Error(t, err)
		var valErr *ValidationError
		require.True(t, errors.As(err, &valErr))
		assert.Equal(t, apierrors.ErrCodeDatabase, valErr.Code)
		mockDB.AssertExpectations(t)
	})

	t.Run("single manager db error", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		validator := NewManagerChangeValidator(mockDB)

		oldTs := int32(time.Now().Add(-365 * 24 * time.Hour).Unix())

		mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
			Return(models.CheckUserChannelOwnershipRow{
				Name:         "#testchannel",
				ID:           1,
				RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
			}, nil).Once()

		mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, int32(1)).
			Return(models.CheckChannelExistsAndRegisteredRow{
				ID:           1,
				Name:         "#testchannel",
				RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
			}, nil).Once()

		mockDB.On("GetUser", mock.Anything, models.GetUserParams{Username: "newmanager"}).
			Return(models.GetUserRow{
				ID:       200,
				Username: "newmanager",
				SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
			}, nil).Once()

		mockDB.On("CheckNewManagerChannelAccess", mock.Anything, int32(1), int32(200)).
			Return(models.CheckNewManagerChannelAccessRow{
				Username: "newmanager",
				ID:       200,
				SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
			}, nil).Once()

		mockDB.On("CheckExistingPendingRequests", mock.Anything, int32(1)).
			Return([]models.CheckExistingPendingRequestsRow{}, nil).Once()

		mockDB.On("CheckUserOwnsOtherChannels", mock.Anything, int32(200)).
			Return(false, nil).Once()

		mockDB.On("CheckChannelSingleManager", mock.Anything, int32(1)).
			Return(int64(0), errors.New("database error")).Once()

		err := validator.ValidateManagerChangeBusinessRules(
			context.Background(),
			int32(1),
			int32(100),
			"newmanager",
			"permanent",
		)

		require.Error(t, err)
		var valErr *ValidationError
		require.True(t, errors.As(err, &valErr))
		assert.Equal(t, apierrors.ErrCodeDatabase, valErr.Code)
		mockDB.AssertExpectations(t)
	})

	t.Run("cooldown status db error", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		validator := NewManagerChangeValidator(mockDB)

		oldTs := int32(time.Now().Add(-365 * 24 * time.Hour).Unix())

		mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
			Return(models.CheckUserChannelOwnershipRow{
				Name:         "#testchannel",
				ID:           1,
				RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
			}, nil).Once()

		mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, int32(1)).
			Return(models.CheckChannelExistsAndRegisteredRow{
				ID:           1,
				Name:         "#testchannel",
				RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
			}, nil).Once()

		mockDB.On("GetUser", mock.Anything, models.GetUserParams{Username: "newmanager"}).
			Return(models.GetUserRow{
				ID:       200,
				Username: "newmanager",
				SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
			}, nil).Once()

		mockDB.On("CheckNewManagerChannelAccess", mock.Anything, int32(1), int32(200)).
			Return(models.CheckNewManagerChannelAccessRow{
				Username: "newmanager",
				ID:       200,
				SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
			}, nil).Once()

		mockDB.On("CheckExistingPendingRequests", mock.Anything, int32(1)).
			Return([]models.CheckExistingPendingRequestsRow{}, nil).Once()

		mockDB.On("CheckUserOwnsOtherChannels", mock.Anything, int32(200)).
			Return(false, nil).Once()

		mockDB.On("CheckChannelSingleManager", mock.Anything, int32(1)).
			Return(int64(1), nil).Once()

		mockDB.On("CheckUserCooldownStatus", mock.Anything, int32(100)).
			Return(models.CheckUserCooldownStatusRow{}, errors.New("database error")).Once()

		err := validator.ValidateManagerChangeBusinessRules(
			context.Background(),
			int32(1),
			int32(100),
			"newmanager",
			"permanent",
		)

		require.Error(t, err)
		var valErr *ValidationError
		require.True(t, errors.As(err, &valErr))
		assert.Equal(t, apierrors.ErrCodeDatabase, valErr.Code)
		mockDB.AssertExpectations(t)
	})
}

func TestValidateManagerChangeBusinessRules_TemporaryValid(t *testing.T) {
	mockDB := mocks.NewServiceInterface(t)
	validator := NewManagerChangeValidator(mockDB)

	oldTs := int32(time.Now().Add(-365 * 24 * time.Hour).Unix())

	mockDB.On("CheckUserChannelOwnership", mock.Anything, int32(100), int32(1)).
		Return(models.CheckUserChannelOwnershipRow{
			Name:         "#testchannel",
			ID:           1,
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckChannelExistsAndRegistered", mock.Anything, int32(1)).
		Return(models.CheckChannelExistsAndRegisteredRow{
			ID:           1,
			Name:         "#testchannel",
			RegisteredTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("GetUser", mock.Anything, models.GetUserParams{Username: "newmanager"}).
		Return(models.GetUserRow{
			ID:       200,
			Username: "newmanager",
			SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckNewManagerChannelAccess", mock.Anything, int32(1), int32(200)).
		Return(models.CheckNewManagerChannelAccessRow{
			Username: "newmanager",
			ID:       200,
			SignupTs: pgtype.Int4{Int32: oldTs, Valid: true},
		}, nil).Once()

	mockDB.On("CheckExistingPendingRequests", mock.Anything, int32(1)).
		Return([]models.CheckExistingPendingRequestsRow{}, nil).Once()

	// CheckUserOwnsOtherChannels is NOT called for temporary changes
	mockDB.On("CheckChannelSingleManager", mock.Anything, int32(1)).
		Return(int64(1), nil).Once()

	mockDB.On("CheckUserCooldownStatus", mock.Anything, int32(100)).
		Return(models.CheckUserCooldownStatusRow{
			PostForms:        0,
			Verificationdata: pgtype.Text{String: "verified", Valid: true},
			Email:            pgtype.Text{String: "test@example.com", Valid: true},
		}, nil).Once()

	err := validator.ValidateManagerChangeBusinessRules(
		context.Background(),
		int32(1),
		int32(100),
		"newmanager",
		"temporary",
	)

	assert.NoError(t, err)
	mockDB.AssertExpectations(t)
}
