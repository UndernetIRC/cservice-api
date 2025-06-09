// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package errors

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockValidationError implements the ValidationError interface for testing
type MockValidationError struct {
	code    string
	message string
	details interface{}
}

func (m *MockValidationError) Error() string {
	return m.message
}

func (m *MockValidationError) GetCode() string {
	return m.code
}

func (m *MockValidationError) GetMessage() string {
	return m.message
}

func (m *MockValidationError) GetDetails() interface{} {
	return m.details
}

func TestChannelRegistrationErrorHandler_HandleValidationError(t *testing.T) {
	handler := NewChannelRegistrationErrorHandler()

	tests := []struct {
		name           string
		error          error
		expectedStatus int
		expectedCode   string
	}{
		{
			name: "invalid channel name",
			error: &MockValidationError{
				code:    ErrCodeInvalidChannelName,
				message: "Channel name is invalid",
				details: map[string]interface{}{"field": "channel_name"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedCode:   ErrCodeInvalidChannelName,
		},
		{
			name: "self support not allowed",
			error: &MockValidationError{
				code:    ErrCodeSelfSupportNotAllowed,
				message: "Cannot support your own channel",
				details: nil,
			},
			expectedStatus: http.StatusUnprocessableEntity,
			expectedCode:   ErrCodeSelfSupportNotAllowed,
		},
		{
			name: "insufficient supporters",
			error: &MockValidationError{
				code:    ErrCodeInsufficientSupporters,
				message: "Need at least one supporter",
				details: map[string]interface{}{"required": 1, "provided": 0},
			},
			expectedStatus: http.StatusBadRequest,
			expectedCode:   ErrCodeInsufficientSupporters,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/channels", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := handler.HandleValidationError(c, tt.error)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, rec.Code)

			var response ErrorResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

			assert.Equal(t, "error", response.Status)
			assert.Equal(t, tt.expectedCode, response.Error.Code)
			assert.NotEmpty(t, response.Error.Message)
		})
	}
}

func TestChannelRegistrationErrorHandler_HandleBusinessRuleError(t *testing.T) {
	handler := NewChannelRegistrationErrorHandler()

	tests := []struct {
		name           string
		error          error
		expectedStatus int
		expectedCode   string
	}{
		{
			name: "user restricted",
			error: &MockValidationError{
				code:    ErrCodeUserRestricted,
				message: "User is restricted from registering channels",
				details: map[string]interface{}{"restriction_type": "NOREG"},
			},
			expectedStatus: http.StatusForbidden,
			expectedCode:   ErrCodeUserRestricted,
		},
		{
			name: "channel limit exceeded",
			error: &MockValidationError{
				code:    ErrCodeChannelLimitExceeded,
				message: "User has reached channel limit",
				details: map[string]interface{}{"current": 5, "limit": 5},
			},
			expectedStatus: http.StatusConflict,
			expectedCode:   ErrCodeChannelLimitExceeded,
		},
		{
			name: "registrations disabled",
			error: &MockValidationError{
				code:    ErrCodeRegistrationsDisabled,
				message: "Channel registrations are temporarily disabled",
				details: nil,
			},
			expectedStatus: http.StatusServiceUnavailable,
			expectedCode:   ErrCodeRegistrationsDisabled,
		},
		{
			name: "IRC idle check failed",
			error: &MockValidationError{
				code:    ErrCodeIrcIdleCheckFailed,
				message: "User must be active on IRC",
				details: map[string]interface{}{"last_seen": "2024-01-01"},
			},
			expectedStatus: http.StatusForbidden,
			expectedCode:   ErrCodeIrcIdleCheckFailed,
		},
		{
			name: "pending registration exists",
			error: &MockValidationError{
				code:    ErrCodePendingExists,
				message: "User already has a pending registration",
				details: map[string]interface{}{"pending_id": 123},
			},
			expectedStatus: http.StatusConflict,
			expectedCode:   ErrCodePendingExists,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/channels", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := handler.HandleBusinessRuleError(c, tt.error)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, rec.Code)

			var response ErrorResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

			assert.Equal(t, "error", response.Status)
			assert.Equal(t, tt.expectedCode, response.Error.Code)
			assert.NotEmpty(t, response.Error.Message)
		})
	}
}

func TestChannelRegistrationErrorHandler_GetErrorCategory(t *testing.T) {
	handler := NewChannelRegistrationErrorHandler()

	tests := []struct {
		errorCode        string
		expectedCategory string
	}{
		{ErrCodeInvalidChannelName, "validation"},
		{ErrCodeSelfSupportNotAllowed, "validation"},
		{ErrCodeUserRestricted, "authorization"},
		{ErrCodeIrcIdleCheckFailed, "authorization"},
		{ErrCodeChannelLimitExceeded, "business_rule"},
		{ErrCodePendingExists, "business_rule"},
		{ErrCodeRegistrationsDisabled, "service_availability"},
		{ErrCodeDatabaseError, "database"},
		{"UNKNOWN_ERROR", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.errorCode, func(t *testing.T) {
			category := handler.GetErrorCategory(tt.errorCode)
			assert.Equal(t, tt.expectedCategory, category)
		})
	}
}

func TestChannelRegistrationErrorHandler_IsRetryableError(t *testing.T) {
	handler := NewChannelRegistrationErrorHandler()

	tests := []struct {
		errorCode string
		retryable bool
	}{
		{ErrCodeDatabaseError, true},
		{ErrCodeRegistrationsDisabled, true},
		{ErrCodeInvalidChannelName, false},
		{ErrCodeUserRestricted, false},
		{ErrCodeChannelLimitExceeded, false},
		{"UNKNOWN_ERROR", false},
	}

	for _, tt := range tests {
		t.Run(tt.errorCode, func(t *testing.T) {
			retryable := handler.IsRetryableError(tt.errorCode)
			assert.Equal(t, tt.retryable, retryable)
		})
	}
}

func TestChannelRegistrationErrorHandler_GetUserFriendlyMessage(t *testing.T) {
	handler := NewChannelRegistrationErrorHandler()

	tests := []struct {
		errorCode       string
		expectedMessage string
	}{
		{
			ErrCodeInvalidChannelName,
			"The channel name is invalid. Channel names must start with # and contain only valid IRC characters.",
		},
		{
			ErrCodeSelfSupportNotAllowed,
			"You cannot support your own channel registration.",
		},
		{
			ErrCodeUserRestricted,
			"Your account is restricted from registering channels. Please contact support.",
		},
		{
			ErrCodeRegistrationsDisabled,
			"Channel registrations are temporarily disabled. Please try again later.",
		},
		{
			"UNKNOWN_ERROR",
			"An error occurred while processing your channel registration.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.errorCode, func(t *testing.T) {
			message := handler.GetUserFriendlyMessage(tt.errorCode)
			assert.Equal(t, tt.expectedMessage, message)
		})
	}
}

func TestChannelRegistrationErrorHandler_HandleNonValidationError(t *testing.T) {
	handler := NewChannelRegistrationErrorHandler()

	t.Run("validation error fallback", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/channels", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Test with a regular error that doesn't implement ValidationError interface
		regularError := assert.AnError

		err := handler.HandleValidationError(c, regularError)
		require.NoError(t, err)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)

		var response ErrorResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

		assert.Equal(t, "error", response.Status)
		assert.Equal(t, ErrCodeInternal, response.Error.Code)
	})

	t.Run("business rule error fallback", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/channels", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Test with a regular error that doesn't implement ValidationError interface
		regularError := assert.AnError

		err := handler.HandleBusinessRuleError(c, regularError)
		require.NoError(t, err)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)

		var response ErrorResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

		assert.Equal(t, "error", response.Status)
		assert.Equal(t, ErrCodeInternal, response.Error.Code)
	})
}
