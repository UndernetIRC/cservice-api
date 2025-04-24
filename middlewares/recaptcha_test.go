// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package middlewares

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/undernetirc/cservice-api/internal/config"
)

// mockVerifyReCAPTCHA is a mock implementation of verifyReCAPTCHA for testing
func mockVerifyReCAPTCHA(token string, _ string) (*ReCAPTCHAResponse, error) {
	// Always return success for "test_token"
	if token == "test_token" {
		return &ReCAPTCHAResponse{
			Success: true,
			Score:   0.9,
		}, nil
	}

	// Return failure for "low_score_token"
	if token == "low_score_token" {
		return &ReCAPTCHAResponse{
			Success: true,
			Score:   0.1,
		}, nil
	}

	// Return failure with error codes for other tokens
	return &ReCAPTCHAResponse{
		Success:    false,
		ErrorCodes: []string{"invalid-input-response"},
	}, nil
}

func TestReCAPTCHA(t *testing.T) {
	// Setup
	e := echo.New()

	// Save the original function and replace with mock
	originalVerifyReCAPTCHA := verifyReCAPTCHA
	verifyReCAPTCHA = mockVerifyReCAPTCHA

	// Restore original function after tests
	defer func() {
		verifyReCAPTCHA = originalVerifyReCAPTCHA
	}()

	// Save original config values
	origEnabled := config.ServiceReCAPTCHAEnabled.GetBool()
	origSecretKey := config.ServiceReCAPTCHASecretKey.GetString()
	origMinScore := config.ServiceReCAPTCHAMinScore.GetFloat64()
	origFieldName := config.ServiceReCAPTCHAFieldName.GetString()

	// Restore original config values after tests
	defer func() {
		config.ServiceReCAPTCHAEnabled.Set(origEnabled)
		config.ServiceReCAPTCHASecretKey.Set(origSecretKey)
		config.ServiceReCAPTCHAMinScore.Set(origMinScore)
		config.ServiceReCAPTCHAFieldName.Set(origFieldName)
	}()

	// Set common config for tests
	config.ServiceReCAPTCHAFieldName.Set("recaptcha_token")
	config.ServiceReCAPTCHAMinScore.Set(0.5)

	// Test handler that reads the request body to ensure it's preserved
	handler := func(c echo.Context) error {
		// Try to read the body again - this should work now
		bodyBytes, err := io.ReadAll(c.Request().Body)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to read body in handler")
		}

		// Check that body is not empty
		if len(bodyBytes) == 0 {
			return echo.NewHTTPError(http.StatusBadRequest, "Body was empty in handler")
		}

		return c.String(http.StatusOK, "Success")
	}

	t.Run("ReCAPTCHA disabled", func(t *testing.T) {
		// Set reCAPTCHA to disabled
		config.ServiceReCAPTCHAEnabled.Set(false)

		// Create request
		reqBody := map[string]interface{}{
			"username":        "testuser",
			"password":        "testpass",
			"recaptcha_token": "invalid_token",
		}
		bodyJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bodyJSON))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Create middleware
		middleware := ReCAPTCHA()
		h := middleware(handler)

		// Test
		err := h(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "Success", rec.Body.String())
	})

	t.Run("Skip middleware", func(t *testing.T) {
		// Set reCAPTCHA to enabled
		config.ServiceReCAPTCHAEnabled.Set(true)
		config.ServiceReCAPTCHASecretKey.Set("test_secret")

		// Create request
		reqBody := map[string]interface{}{
			"username":        "testuser",
			"password":        "testpass",
			"recaptcha_token": "invalid_token", // This would normally fail, but we're skipping
		}
		bodyJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(bodyJSON))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/test") // Important: set the path to match the skipper

		// Create middleware with skipper
		middleware := ReCAPTCHAWithConfig(ReCAPTCHAConfig{
			Skipper: func(c echo.Context) bool {
				return strings.HasPrefix(c.Path(), "/test")
			},
			SecretKey: "test_secret",
			MinScore:  0.5,
			FieldName: "recaptcha_token",
		})
		h := middleware(handler)

		// Test
		err := h(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "Success", rec.Body.String())
	})

	t.Run("Valid token", func(t *testing.T) {
		// Set reCAPTCHA to enabled
		config.ServiceReCAPTCHAEnabled.Set(true)
		config.ServiceReCAPTCHASecretKey.Set("test_secret")

		// Create request with valid token
		reqBody := map[string]interface{}{
			"username":        "testuser",
			"password":        "testpass",
			"recaptcha_token": "test_token", // This will pass validation in our mock
		}
		bodyJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bodyJSON))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Create middleware
		middleware := ReCAPTCHA()
		h := middleware(handler)

		// Test
		err := h(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "Success", rec.Body.String())
	})

	t.Run("Invalid token", func(t *testing.T) {
		// Set reCAPTCHA to enabled
		config.ServiceReCAPTCHAEnabled.Set(true)
		config.ServiceReCAPTCHASecretKey.Set("test_secret")

		// Create request with invalid token
		reqBody := map[string]interface{}{
			"username":        "testuser",
			"password":        "testpass",
			"recaptcha_token": "invalid_token", // This will fail validation in our mock
		}
		bodyJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bodyJSON))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Create middleware
		middleware := ReCAPTCHA()
		h := middleware(handler)

		// Test
		err := h(c)
		if assert.Error(t, err) {
			he, ok := err.(*echo.HTTPError)
			if assert.True(t, ok, "Expected HTTPError") {
				assert.Equal(t, http.StatusBadRequest, he.Code)
				assert.Contains(t, he.Message, "reCAPTCHA verification failed")
			}
		}
	})

	t.Run("Low score token", func(t *testing.T) {
		// Set reCAPTCHA to enabled
		config.ServiceReCAPTCHAEnabled.Set(true)
		config.ServiceReCAPTCHASecretKey.Set("test_secret")

		// Ensure min score is set to a value that would reject the low score token
		config.ServiceReCAPTCHAMinScore.Set(0.5) // Our low score token has a score of 0.1

		// Create request with low score token
		reqBody := map[string]interface{}{
			"username":        "testuser",
			"password":        "testpass",
			"recaptcha_token": "low_score_token", // This will have a low score in our mock
		}
		bodyJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bodyJSON))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Create middleware with explicit min score to ensure consistency
		middleware := ReCAPTCHAWithConfig(ReCAPTCHAConfig{
			SecretKey: "test_secret",
			MinScore:  0.5, // Explicitly set min score
			FieldName: "recaptcha_token",
		})
		h := middleware(handler)

		// Test
		err := h(c)
		if assert.Error(t, err) {
			he, ok := err.(*echo.HTTPError)
			if assert.True(t, ok, "Expected HTTPError") {
				assert.Equal(t, http.StatusForbidden, he.Code)
				assert.Equal(t, "reCAPTCHA score too low", he.Message)
			}
		}
	})

	t.Run("Missing token", func(t *testing.T) {
		// Set reCAPTCHA to enabled
		config.ServiceReCAPTCHAEnabled.Set(true)
		config.ServiceReCAPTCHASecretKey.Set("test_secret")

		// Create request without token
		reqBody := map[string]interface{}{
			"username": "testuser",
			"password": "testpass",
		}
		bodyJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bodyJSON))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Create middleware
		middleware := ReCAPTCHA()
		h := middleware(handler)

		// Test
		err := h(c)
		if assert.Error(t, err) {
			he, ok := err.(*echo.HTTPError)
			if assert.True(t, ok, "Expected HTTPError") {
				assert.Equal(t, http.StatusBadRequest, he.Code)
				assert.Equal(t, "Missing recaptcha_token field", he.Message)
			}
		}
	})

	t.Run("Empty token", func(t *testing.T) {
		// Set reCAPTCHA to enabled
		config.ServiceReCAPTCHAEnabled.Set(true)
		config.ServiceReCAPTCHASecretKey.Set("test_secret")

		// Create request with empty token
		reqBody := map[string]interface{}{
			"username":        "testuser",
			"password":        "testpass",
			"recaptcha_token": "",
		}
		bodyJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bodyJSON))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Create middleware
		middleware := ReCAPTCHA()
		h := middleware(handler)

		// Test
		err := h(c)
		if assert.Error(t, err) {
			he, ok := err.(*echo.HTTPError)
			if assert.True(t, ok, "Expected HTTPError") {
				assert.Equal(t, http.StatusBadRequest, he.Code)
				assert.Equal(t, "Invalid recaptcha_token field", he.Message)
			}
		}
	})

	t.Run("Body preservation test", func(t *testing.T) {
		// This test specifically checks that the body is properly preserved for the next handler
		config.ServiceReCAPTCHAEnabled.Set(true)
		config.ServiceReCAPTCHASecretKey.Set("test_secret")

		reqBody := map[string]interface{}{
			"username":        "testuser",
			"password":        "testpass",
			"recaptcha_token": "test_token",
		}
		bodyJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bodyJSON))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Create a custom handler that fully reads the body and checks it
		bodyCheckHandler := func(c echo.Context) error {
			body, err := io.ReadAll(c.Request().Body)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "Failed to read body")
			}

			var parsed map[string]interface{}
			if err := json.Unmarshal(body, &parsed); err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, "Failed to parse body")
			}

			// Check that all fields are present
			if _, ok := parsed["username"]; !ok {
				return echo.NewHTTPError(http.StatusBadRequest, "Missing username field")
			}

			if _, ok := parsed["password"]; !ok {
				return echo.NewHTTPError(http.StatusBadRequest, "Missing password field")
			}

			return c.String(http.StatusOK, "Body preserved")
		}

		middleware := ReCAPTCHA()
		h := middleware(bodyCheckHandler)

		err := h(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "Body preserved", rec.Body.String())
	})
}

func TestApplyReCAPTCHA(t *testing.T) {
	t.Run("ApplyReCAPTCHA function", func(t *testing.T) {
		skipper := ApplyReCAPTCHA("/api/login", "/api/register")

		// Should not skip the specified paths
		c := echo.New().NewContext(nil, nil)
		c.SetPath("/api/login")
		assert.False(t, skipper(c))

		c.SetPath("/api/register")
		assert.False(t, skipper(c))

		// Should skip other paths
		c.SetPath("/api/profile")
		assert.True(t, skipper(c))
	})
}

func TestSkipReCAPTCHA(t *testing.T) {
	t.Run("SkipReCAPTCHA function", func(t *testing.T) {
		skipper := SkipReCAPTCHA("/api/profile", "/api/settings")

		// Should skip the specified paths
		c := echo.New().NewContext(nil, nil)
		c.SetPath("/api/profile")
		assert.True(t, skipper(c))

		c.SetPath("/api/settings")
		assert.True(t, skipper(c))

		// Should not skip other paths
		c.SetPath("/api/login")
		assert.False(t, skipper(c))
	})
}
