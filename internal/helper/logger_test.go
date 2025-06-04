// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

package helper

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestGetRequestLogger(t *testing.T) {
	tests := []struct {
		name              string
		setupRequestID    bool
		requestID         string
		expectedRequestID string
	}{
		{
			name:              "with request ID header",
			setupRequestID:    true,
			requestID:         "test-request-123",
			expectedRequestID: "test-request-123",
		},
		{
			name:              "without request ID header",
			setupRequestID:    false,
			requestID:         "",
			expectedRequestID: "unknown",
		},
		{
			name:              "with empty request ID header",
			setupRequestID:    true,
			requestID:         "",
			expectedRequestID: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			if tt.setupRequestID {
				c.Response().Header().Set(echo.HeaderXRequestID, tt.requestID)
			}

			logger := GetRequestLogger(c)
			assert.NotNil(t, logger)

			// Test that GetRequestID also works correctly
			requestID := GetRequestID(c)
			assert.Equal(t, tt.expectedRequestID, requestID)
		})
	}
}

func TestGetRequestID(t *testing.T) {
	tests := []struct {
		name           string
		requestID      string
		expectedResult string
	}{
		{
			name:           "valid request ID",
			requestID:      "valid-request-id-456",
			expectedResult: "valid-request-id-456",
		},
		{
			name:           "empty request ID",
			requestID:      "",
			expectedResult: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			c.Response().Header().Set(echo.HeaderXRequestID, tt.requestID)

			result := GetRequestID(c)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}
