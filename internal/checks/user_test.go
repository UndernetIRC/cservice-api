// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 - 2025 UnderNET

package checks

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/db/types/flags"
	"github.com/undernetirc/cservice-api/models"
)

func TestIsUsernameRegistered(t *testing.T) {
	ctx := context.Background()
	username := "test"

	tests := []struct {
		name          string
		setupMock     func(db *mocks.Querier)
		expectedError error
	}{
		{
			name: "username not found",
			setupMock: func(db *mocks.Querier) {
				db.On("CheckUsernameExists", mock.Anything, username).
					Return([]string{}, nil).Once()
			},
			expectedError: nil,
		},
		{
			name: "username exists",
			setupMock: func(db *mocks.Querier) {
				db.On("CheckUsernameExists", mock.Anything, username).
					Return([]string{username}, nil).Once()
			},
			expectedError: ErrUsernameExists,
		},
		{
			name: "database error",
			setupMock: func(db *mocks.Querier) {
				db.On("CheckUsernameExists", mock.Anything, username).
					Return(nil, errors.New("database error")).Once()
			},
			expectedError: errors.New("database error"),
		},
		{
			name: "multiple usernames returned",
			setupMock: func(db *mocks.Querier) {
				db.On("CheckUsernameExists", mock.Anything, username).
					Return([]string{username, username + "2"}, nil).Once()
			},
			expectedError: ErrUsernameExists,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := mocks.NewQuerier(t)
			tt.setupMock(db)

			InitUser(ctx, db)
			err := User.IsUsernameRegistered(username)

			if tt.expectedError == nil {
				assert.NoError(t, err)
			} else if errors.Is(tt.expectedError, ErrUsernameExists) {
				assert.True(t, errors.Is(err, ErrUsernameExists))
			} else {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			}
		})
	}
}

func TestIsEmailRegistered(t *testing.T) {
	ctx := context.Background()
	email := "test@example.com"

	tests := []struct {
		name          string
		setupMock     func(db *mocks.Querier)
		expectedError error
	}{
		{
			name: "email not found",
			setupMock: func(db *mocks.Querier) {
				db.On("CheckEmailExists", mock.Anything, email).
					Return([]pgtype.Text{}, nil).Once()
			},
			expectedError: nil,
		},
		{
			name: "email exists",
			setupMock: func(db *mocks.Querier) {
				db.On("CheckEmailExists", mock.Anything, email).
					Return([]pgtype.Text{{String: email, Valid: true}}, nil).Once()
			},
			expectedError: ErrEmailExists,
		},
		{
			name: "database error",
			setupMock: func(db *mocks.Querier) {
				db.On("CheckEmailExists", mock.Anything, email).
					Return(nil, errors.New("database error")).Once()
			},
			expectedError: errors.New("database error"),
		},
		{
			name: "multiple emails returned",
			setupMock: func(db *mocks.Querier) {
				db.On("CheckEmailExists", mock.Anything, email).
					Return([]pgtype.Text{
						{String: email, Valid: true},
						{String: "other@example.com", Valid: true},
					}, nil).Once()
			},
			expectedError: ErrEmailExists,
		},
		{
			name: "email with invalid pgtype",
			setupMock: func(db *mocks.Querier) {
				db.On("CheckEmailExists", mock.Anything, email).
					Return([]pgtype.Text{{String: email, Valid: false}}, nil).Once()
			},
			expectedError: ErrEmailExists, // Still returns error as the array length > 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := mocks.NewQuerier(t)
			tt.setupMock(db)

			InitUser(ctx, db)
			err := User.IsEmailRegistered(email)

			if tt.expectedError == nil {
				assert.NoError(t, err)
			} else if errors.Is(tt.expectedError, ErrEmailExists) {
				assert.True(t, errors.Is(err, ErrEmailExists))
			} else {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			}
		})
	}
}

func TestIsRegistered(t *testing.T) {
	ctx := context.Background()
	email := "test@example.com"
	username := "test"

	testCases := []struct {
		name          string
		dbUsername    string
		username      string
		dbEmail       pgtype.Text
		email         string
		expectErrs    []error
		usernameDbErr error // Error for username check
		emailDbErr    error // Error for email check
	}{
		{
			name:       "both username and email exist",
			dbUsername: username,
			username:   username,
			dbEmail:    pgtype.Text{String: email, Valid: true},
			email:      email,
			expectErrs: []error{ErrUsernameExists, ErrEmailExists},
		},
		{
			name:       "only username exists",
			dbUsername: username,
			username:   username,
			dbEmail:    pgtype.Text{String: "", Valid: false},
			email:      email,
			expectErrs: []error{ErrUsernameExists},
		},
		{
			name:       "only email exists",
			dbUsername: "",
			username:   username,
			dbEmail:    pgtype.Text{String: email, Valid: true},
			email:      email,
			expectErrs: []error{ErrEmailExists},
		},
		{
			name:       "neither username nor email exists",
			dbUsername: "",
			username:   username,
			dbEmail:    pgtype.Text{String: "", Valid: false},
			email:      email,
			expectErrs: nil,
		},
		{
			name:          "database error on username check",
			dbUsername:    "",
			username:      username,
			email:         email,
			dbEmail:       pgtype.Text{String: "", Valid: false},
			usernameDbErr: errors.New("username database error"),
			emailDbErr:    nil, // No error for email check
			expectErrs:    []error{errors.New("username database error")},
		},
		{
			name:          "database error on email check",
			dbUsername:    "",
			username:      username,
			email:         email,
			dbEmail:       pgtype.Text{String: "", Valid: false},
			usernameDbErr: nil, // No error for username check
			emailDbErr:    errors.New("email database error"),
			expectErrs:    []error{errors.New("email database error")},
		},
		{
			name:          "database errors on both checks",
			dbUsername:    "",
			username:      username,
			email:         email,
			dbEmail:       pgtype.Text{String: "", Valid: false},
			usernameDbErr: errors.New("username database error"),
			emailDbErr:    errors.New("email database error"),
			expectErrs:    []error{errors.New("username database error"), errors.New("email database error")},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			userList := []string{}
			if tc.dbUsername != "" {
				userList = append(userList, tc.dbUsername)
			}

			emailList := []pgtype.Text{}
			if tc.dbEmail.String != "" {
				emailList = append(emailList, tc.dbEmail)
			}

			db := mocks.NewQuerier(t)

			// Setup username check mock
			db.On("CheckUsernameExists", mock.Anything, tc.username).
				Return(func() interface{} {
					if tc.usernameDbErr != nil {
						return nil
					}
					return userList
				}(), tc.usernameDbErr).Once()

			// Setup email check mock - this will always be called in IsRegistered
			db.On("CheckEmailExists", mock.Anything, tc.email).
				Return(func() interface{} {
					if tc.emailDbErr != nil {
						return nil
					}
					return emailList
				}(), tc.emailDbErr).Once()

			InitUser(ctx, db)
			err := User.IsRegistered(tc.username, tc.email)

			if tc.expectErrs == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				for _, expectedErr := range tc.expectErrs {
					if errors.Is(expectedErr, ErrUsernameExists) || errors.Is(expectedErr, ErrEmailExists) {
						assert.True(t, errors.Is(err, expectedErr), fmt.Sprintf("Expected error to contain %v", expectedErr))
					} else {
						assert.Contains(t, err.Error(), expectedErr.Error())
					}
				}
			}
		})
	}
}

func TestIsAdmin(t *testing.T) {
	ctx := context.Background()
	userID := int32(123)
	adminLevel := int32(1000)

	tests := []struct {
		name          string
		setupMock     func(db *mocks.Querier)
		expectedLevel int32
		expectedError error
	}{
		{
			name: "valid admin with admin level",
			setupMock: func(db *mocks.Querier) {
				db.On("GetUserByID", mock.Anything, userID).
					Return(models.GetUserByIDRow{
						ID:    userID,
						Flags: flags.User(0), // No special flags
					}, nil).Once()
				db.On("GetAdminLevel", mock.Anything, userID).
					Return(models.GetAdminLevelRow{
						Access:         adminLevel,
						SuspendExpires: pgtype.Int4{Int32: 0, Valid: true}, // Not suspended
					}, nil).Once()
			},
			expectedLevel: adminLevel,
			expectedError: nil,
		},
		{
			name: "user not found",
			setupMock: func(db *mocks.Querier) {
				db.On("GetUserByID", mock.Anything, userID).
					Return(models.GetUserByIDRow{}, pgx.ErrNoRows).Once()
			},
			expectedLevel: 0,
			expectedError: pgx.ErrNoRows,
		},
		{
			name: "admin level not found",
			setupMock: func(db *mocks.Querier) {
				db.On("GetUserByID", mock.Anything, userID).
					Return(models.GetUserByIDRow{
						ID:    userID,
						Flags: flags.User(0),
					}, nil).Once()
				db.On("GetAdminLevel", mock.Anything, userID).
					Return(models.GetAdminLevelRow{}, pgx.ErrNoRows).Once()
			},
			expectedLevel: 0,
			expectedError: nil, // Not an error, just not an admin
		},
		{
			name: "admin with suspension",
			setupMock: func(db *mocks.Querier) {
				// Current time + 1 hour for suspension expiry
				suspendExpiry := int32(time.Now().Add(time.Hour).Unix())

				db.On("GetUserByID", mock.Anything, userID).
					Return(models.GetUserByIDRow{
						ID:    userID,
						Flags: flags.User(0),
					}, nil).Once()
				db.On("GetAdminLevel", mock.Anything, userID).
					Return(models.GetAdminLevelRow{
						Access:         adminLevel,
						SuspendExpires: pgtype.Int4{Int32: suspendExpiry, Valid: true},
					}, nil).Once()
			},
			expectedLevel: 0, // Suspended admins have level 0
			expectedError: nil,
		},
		{
			name: "admin with UserNoAdmin flag",
			setupMock: func(db *mocks.Querier) {
				db.On("GetUserByID", mock.Anything, userID).
					Return(models.GetUserByIDRow{
						ID:    userID,
						Flags: flags.User(flags.UserNoAdmin),
					}, nil).Once()
				db.On("GetAdminLevel", mock.Anything, userID).
					Return(models.GetAdminLevelRow{
						Access:         adminLevel,
						SuspendExpires: pgtype.Int4{Int32: 0, Valid: true},
					}, nil).Once()
			},
			expectedLevel: 0, // UserNoAdmin means not an admin
			expectedError: nil,
		},
		{
			name: "admin with UserAlumni flag",
			setupMock: func(db *mocks.Querier) {
				db.On("GetUserByID", mock.Anything, userID).
					Return(models.GetUserByIDRow{
						ID:    userID,
						Flags: flags.User(flags.UserAlumni),
					}, nil).Once()
				db.On("GetAdminLevel", mock.Anything, userID).
					Return(models.GetAdminLevelRow{
						Access:         adminLevel,
						SuspendExpires: pgtype.Int4{Int32: 0, Valid: true},
					}, nil).Once()
			},
			expectedLevel: 0, // Alumni are not admins
			expectedError: nil,
		},
		{
			name: "database error on GetAdminLevel",
			setupMock: func(db *mocks.Querier) {
				db.On("GetUserByID", mock.Anything, userID).
					Return(models.GetUserByIDRow{
						ID:    userID,
						Flags: flags.User(0),
					}, nil).Once()
				db.On("GetAdminLevel", mock.Anything, userID).
					Return(models.GetAdminLevelRow{}, errors.New("database error")).Once()
			},
			expectedLevel: 0,
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := mocks.NewQuerier(t)
			tt.setupMock(db)

			InitUser(ctx, db)
			level, err := User.IsAdmin(userID)

			assert.Equal(t, tt.expectedLevel, level)

			if tt.expectedError == nil {
				assert.NoError(t, err)
			} else if errors.Is(tt.expectedError, pgx.ErrNoRows) {
				assert.True(t, errors.Is(err, pgx.ErrNoRows))
			} else {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			}
		})
	}
}
