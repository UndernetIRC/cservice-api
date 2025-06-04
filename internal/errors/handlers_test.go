// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package errors

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestContext creates a test echo context with proper headers
func setupTestContext(method, path string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Set request ID for logging
	c.Response().Header().Set(echo.HeaderXRequestID, "test-request-id")

	return c, rec
}

// captureLogOutput captures slog output for testing
func captureLogOutput(_ *testing.T, fn func()) string {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	fn()

	return buf.String()
}

func TestHandleValidationError(t *testing.T) {
	t.Run("validator.ValidationErrors", func(t *testing.T) {
		c, rec := setupTestContext("POST", "/test")

		// Create a mock validation error
		validate := validator.New()
		type TestStruct struct {
			Email string `validate:"required,email"`
			Name  string `validate:"required,min=2"`
		}

		test := TestStruct{Email: "invalid", Name: "a"}
		err := validate.Struct(test)
		require.Error(t, err)

		logOutput := captureLogOutput(t, func() {
			HandleValidationError(c, err)
		})

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var response ErrorResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

		assert.Equal(t, "error", response.Status)
		assert.Equal(t, ErrCodeValidation, response.Error.Code)
		assert.Equal(t, "Invalid input provided", response.Error.Message)
		assert.NotNil(t, response.Error.Details)

		// Check log output
		assert.Contains(t, logOutput, "Validation error")
		assert.Contains(t, logOutput, "test-request-id")
		assert.Contains(t, logOutput, "/test")
	})

	t.Run("generic error", func(t *testing.T) {
		c, rec := setupTestContext("POST", "/test")
		err := errors.New("generic validation error")

		logOutput := captureLogOutput(t, func() {
			HandleValidationError(c, err)
		})

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var response ErrorResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

		assert.Equal(t, "error", response.Status)
		assert.Equal(t, ErrCodeValidation, response.Error.Code)
		assert.Equal(t, "generic validation error", response.Error.Message)
		assert.Nil(t, response.Error.Details)

		// Check log output
		assert.Contains(t, logOutput, "Generic validation error")
		assert.Contains(t, logOutput, "generic validation error")
	})
}

func TestHandleDatabaseError(t *testing.T) {
	c, rec := setupTestContext("GET", "/users/123")
	err := errors.New("connection refused")

	logOutput := captureLogOutput(t, func() {
		HandleDatabaseError(c, err)
	})

	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	var response ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

	assert.Equal(t, "error", response.Status)
	assert.Equal(t, ErrCodeDatabase, response.Error.Code)
	assert.Equal(t, "An error occurred while processing your request", response.Error.Message)
	assert.Nil(t, response.Error.Details)

	// Check that actual error is logged but not exposed
	assert.Contains(t, logOutput, "Database error")
	assert.Contains(t, logOutput, "connection refused")
	assert.NotContains(t, response.Error.Message, "connection refused")
}

func TestHandleUnauthorizedError(t *testing.T) {
	t.Run("with custom message", func(t *testing.T) {
		c, rec := setupTestContext("GET", "/protected")

		logOutput := captureLogOutput(t, func() {
			HandleUnauthorizedError(c, "Invalid token")
		})

		assert.Equal(t, http.StatusUnauthorized, rec.Code)

		var response ErrorResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

		assert.Equal(t, "error", response.Status)
		assert.Equal(t, ErrCodeUnauthorized, response.Error.Code)
		assert.Equal(t, "Invalid token", response.Error.Message)

		assert.Contains(t, logOutput, "Unauthorized access attempt")
		assert.Contains(t, logOutput, "Invalid token")
	})

	t.Run("with default message", func(t *testing.T) {
		c, rec := setupTestContext("GET", "/protected")

		HandleUnauthorizedError(c, "")

		var response ErrorResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

		assert.Equal(t, "Authorization information is missing or invalid", response.Error.Message)
	})
}

func TestHandleForbiddenError(t *testing.T) {
	c, rec := setupTestContext("DELETE", "/admin/users/123")

	logOutput := captureLogOutput(t, func() {
		HandleForbiddenError(c, "Insufficient permissions")
	})

	assert.Equal(t, http.StatusForbidden, rec.Code)

	var response ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

	assert.Equal(t, "error", response.Status)
	assert.Equal(t, ErrCodeForbidden, response.Error.Code)
	assert.Equal(t, "Insufficient permissions", response.Error.Message)

	assert.Contains(t, logOutput, "Forbidden access attempt")
}

func TestHandleNotFoundError(t *testing.T) {
	t.Run("with resource name", func(t *testing.T) {
		c, rec := setupTestContext("GET", "/users/999")

		logOutput := captureLogOutput(t, func() {
			HandleNotFoundError(c, "User")
		})

		assert.Equal(t, http.StatusNotFound, rec.Code)

		var response ErrorResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

		assert.Equal(t, "User not found", response.Error.Message)
		assert.Contains(t, logOutput, "Resource not found")
	})

	t.Run("without resource name", func(t *testing.T) {
		c, rec := setupTestContext("GET", "/invalid")

		HandleNotFoundError(c, "")

		var response ErrorResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

		assert.Equal(t, "Resource not found", response.Error.Message)
	})
}

func TestHandleConflictError(t *testing.T) {
	c, rec := setupTestContext("POST", "/users")

	logOutput := captureLogOutput(t, func() {
		HandleConflictError(c, "Username already exists")
	})

	assert.Equal(t, http.StatusConflict, rec.Code)

	var response ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

	assert.Equal(t, "error", response.Status)
	assert.Equal(t, ErrCodeConflict, response.Error.Code)
	assert.Equal(t, "Username already exists", response.Error.Message)

	assert.Contains(t, logOutput, "Resource conflict")
}

func TestHandleBadRequestError(t *testing.T) {
	c, rec := setupTestContext("POST", "/test")

	logOutput := captureLogOutput(t, func() {
		HandleBadRequestError(c, "Invalid JSON")
	})

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var response ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

	assert.Equal(t, ErrCodeBadRequest, response.Error.Code)
	assert.Equal(t, "Invalid JSON", response.Error.Message)

	assert.Contains(t, logOutput, "Bad request")
}

func TestHandleUnprocessableEntityError(t *testing.T) {
	c, rec := setupTestContext("POST", "/channels/123/members")

	logOutput := captureLogOutput(t, func() {
		HandleUnprocessableEntityError(c, "Cannot add user with higher access level")
	})

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)

	var response ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

	assert.Equal(t, ErrCodeUnprocessable, response.Error.Code)
	assert.Equal(t, "Cannot add user with higher access level", response.Error.Message)

	assert.Contains(t, logOutput, "Unprocessable entity")
}

func TestHandleInternalError(t *testing.T) {
	c, rec := setupTestContext("GET", "/test")
	internalErr := errors.New("panic: something went wrong")

	logOutput := captureLogOutput(t, func() {
		HandleInternalError(c, internalErr, "Service unavailable")
	})

	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	var response ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

	assert.Equal(t, ErrCodeInternal, response.Error.Code)
	assert.Equal(t, "Service unavailable", response.Error.Message)

	// Check that internal error is logged but not exposed
	assert.Contains(t, logOutput, "Internal server error")
	assert.Contains(t, logOutput, "panic: something went wrong")
	assert.NotContains(t, response.Error.Message, "panic")
}

func TestGetValidationErrorMessage(t *testing.T) {
	// Test with actual validator to get real FieldError instances
	validate := validator.New()

	type TestStruct struct {
		Required string `validate:"required"`
		Email    string `validate:"email"`
		MinLen   string `validate:"min=5"`
		MaxLen   string `validate:"max=10"`
		Numeric  string `validate:"numeric"`
		URL      string `validate:"url"`
	}

	// Test each validation rule
	testCases := []struct {
		name     string
		input    TestStruct
		field    string
		contains string // What the error message should contain
	}{
		{
			name:     "required field missing",
			input:    TestStruct{Email: "valid@email.com", MinLen: "12345", MaxLen: "short", Numeric: "123", URL: "https://example.com"},
			field:    "Required",
			contains: "required",
		},
		{
			name:     "invalid email",
			input:    TestStruct{Required: "value", Email: "invalid-email", MinLen: "12345", MaxLen: "short", Numeric: "123", URL: "https://example.com"},
			field:    "Email",
			contains: "email",
		},
		{
			name:     "min length violation",
			input:    TestStruct{Required: "value", Email: "valid@email.com", MinLen: "123", MaxLen: "short", Numeric: "123", URL: "https://example.com"},
			field:    "MinLen",
			contains: "5",
		},
		{
			name:     "max length violation",
			input:    TestStruct{Required: "value", Email: "valid@email.com", MinLen: "12345", MaxLen: "this is too long", Numeric: "123", URL: "https://example.com"},
			field:    "MaxLen",
			contains: "10",
		},
		{
			name:     "non-numeric value",
			input:    TestStruct{Required: "value", Email: "valid@email.com", MinLen: "12345", MaxLen: "short", Numeric: "abc", URL: "https://example.com"},
			field:    "Numeric",
			contains: "numbers",
		},
		{
			name:     "invalid URL",
			input:    TestStruct{Required: "value", Email: "valid@email.com", MinLen: "12345", MaxLen: "short", Numeric: "123", URL: "not-a-url"},
			field:    "URL",
			contains: "URL",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validate.Struct(tc.input)
			require.Error(t, err)

			validationErrors := err.(validator.ValidationErrors)
			var targetError validator.FieldError

			// Find the error for the specific field we're testing
			for _, fieldError := range validationErrors {
				if fieldError.Field() == tc.field {
					targetError = fieldError
					break
				}
			}

			require.NotNil(t, targetError, "Should find validation error for field %s", tc.field)

			message := getValidationErrorMessage(targetError)
			assert.Contains(t, strings.ToLower(message), strings.ToLower(tc.contains))
		})
	}
}

func TestGetRequestID(t *testing.T) {
	t.Run("with request ID header", func(t *testing.T) {
		c, _ := setupTestContext("GET", "/test")
		c.Response().Header().Set(echo.HeaderXRequestID, "custom-request-id")

		requestID := getRequestID(c)
		assert.Equal(t, "custom-request-id", requestID)
	})

	t.Run("without request ID header", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		requestID := getRequestID(c)
		assert.Equal(t, "unknown", requestID)
	})
}
