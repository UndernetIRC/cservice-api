// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package errors

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManagerChangeErrorHandler(t *testing.T) {
	handler := NewManagerChangeErrorHandler()
	require.NotNil(t, handler)
}

func TestManagerChangeErrorHandler_HandleBusinessRuleError(t *testing.T) {
	handler := NewManagerChangeErrorHandler()

	tests := []struct {
		name           string
		error          error
		expectedStatus int
		expectedCode   string
	}{
		{
			name: "forbidden error",
			error: &MockValidationError{
				code:    ErrCodeForbidden,
				message: "User is not channel owner",
				details: map[string]any{"error": "not owner"},
			},
			expectedStatus: http.StatusForbidden,
			expectedCode:   ErrCodeForbidden,
		},
		{
			name: "not found error",
			error: &MockValidationError{
				code:    ErrCodeNotFound,
				message: "Channel not found or not registered",
				details: nil,
			},
			expectedStatus: http.StatusNotFound,
			expectedCode:   ErrCodeNotFound,
		},
		{
			name: "conflict error",
			error: &MockValidationError{
				code:    ErrCodeConflict,
				message: "Channel already has a pending manager change request",
				details: nil,
			},
			expectedStatus: http.StatusConflict,
			expectedCode:   ErrCodeConflict,
		},
		{
			name: "bad request error",
			error: &MockValidationError{
				code:    ErrCodeBadRequest,
				message: "Cooldown period active",
				details: nil,
			},
			expectedStatus: http.StatusBadRequest,
			expectedCode:   ErrCodeBadRequest,
		},
		{
			name: "database error",
			error: &MockValidationError{
				code:    ErrCodeDatabase,
				message: "Failed to check pending requests",
				details: map[string]any{"error": "connection refused"},
			},
			expectedStatus: http.StatusInternalServerError,
			expectedCode:   ErrCodeDatabase,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/manager-change", nil)
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

	t.Run("non-validation error fallback", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/manager-change", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		regularError := errors.New("unexpected error")

		captureLogOutput(t, func() {
			err := handler.HandleBusinessRuleError(c, regularError)
			require.NoError(t, err)
		})

		assert.Equal(t, http.StatusInternalServerError, rec.Code)

		var response ErrorResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

		assert.Equal(t, "error", response.Status)
		assert.Equal(t, ErrCodeInternal, response.Error.Code)
	})
}

func TestManagerChangeErrorHandler_MapBusinessRuleErrorToHTTPStatus(t *testing.T) {
	handler := NewManagerChangeErrorHandler()

	tests := []struct {
		errorCode      string
		expectedStatus int
	}{
		{ErrCodeForbidden, http.StatusForbidden},
		{ErrCodeNotFound, http.StatusNotFound},
		{ErrCodeConflict, http.StatusConflict},
		{ErrCodeBadRequest, http.StatusBadRequest},
		{ErrCodeDatabase, http.StatusInternalServerError},
		{"UNKNOWN_ERROR", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.errorCode, func(t *testing.T) {
			status := handler.mapBusinessRuleErrorToHTTPStatus(tt.errorCode)
			assert.Equal(t, tt.expectedStatus, status)
		})
	}
}

func TestManagerChangeErrorHandler_GetErrorCategory(t *testing.T) {
	handler := NewManagerChangeErrorHandler()

	tests := []struct {
		errorCode        string
		expectedCategory string
	}{
		{ErrCodeForbidden, "authorization"},
		{ErrCodeNotFound, "not_found"},
		{ErrCodeConflict, "business_rule"},
		{ErrCodeBadRequest, "validation"},
		{ErrCodeDatabase, "database"},
		{"UNKNOWN_ERROR", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.errorCode, func(t *testing.T) {
			category := handler.GetErrorCategory(tt.errorCode)
			assert.Equal(t, tt.expectedCategory, category)
		})
	}
}

func TestManagerChangeErrorHandler_IsRetryableError(t *testing.T) {
	handler := NewManagerChangeErrorHandler()

	tests := []struct {
		errorCode string
		retryable bool
	}{
		{ErrCodeDatabase, true},
		{ErrCodeForbidden, false},
		{ErrCodeNotFound, false},
		{ErrCodeConflict, false},
		{ErrCodeBadRequest, false},
		{"UNKNOWN_ERROR", false},
	}

	for _, tt := range tests {
		t.Run(tt.errorCode, func(t *testing.T) {
			retryable := handler.IsRetryableError(tt.errorCode)
			assert.Equal(t, tt.retryable, retryable)
		})
	}
}
