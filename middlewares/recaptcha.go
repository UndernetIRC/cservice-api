// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package middlewares

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/undernetirc/cservice-api/internal/config"
)

const recaptchaVerifyURL = "https://www.google.com/recaptcha/api/siteverify"

// ReCAPTCHAResponse represents the response from Google's reCAPTCHA API
type ReCAPTCHAResponse struct {
	Success     bool      `json:"success"`
	Score       float64   `json:"score"`
	Action      string    `json:"action"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes,omitempty"`
}

// ReCAPTCHAConfig holds configuration for the reCAPTCHA middleware
type ReCAPTCHAConfig struct {
	// Skipper defines a function to skip middleware
	Skipper func(c echo.Context) bool

	// SecretKey is the Google reCAPTCHA v3 secret key
	SecretKey string

	// MinScore is the minimum score threshold (0.0 to 1.0)
	MinScore float64

	// FieldName is the field name in the JSON payload containing the reCAPTCHA token
	FieldName string
}

// VerifyReCAPTCHAFunc defines the function signature for reCAPTCHA verification
type VerifyReCAPTCHAFunc func(token, secretKey string) (*ReCAPTCHAResponse, error)

// verifyReCAPTCHA is a variable that holds the reCAPTCHA verification function
// This can be overridden in tests
var verifyReCAPTCHA VerifyReCAPTCHAFunc = defaultVerifyReCAPTCHA

// DefaultReCAPTCHAConfig is the default configuration for the reCAPTCHA middleware
var DefaultReCAPTCHAConfig = ReCAPTCHAConfig{
	Skipper:   defaultSkipper,
	SecretKey: config.ServiceReCAPTCHASecretKey.GetString(),
	MinScore:  config.ServiceReCAPTCHAMinScore.GetFloat64(),
	FieldName: config.ServiceReCAPTCHAFieldName.GetString(),
}

// defaultSkipper returns false which processes the middleware
func defaultSkipper(_ echo.Context) bool {
	return false
}

// ReCAPTCHA returns a middleware that validates Google reCAPTCHA v3 tokens
func ReCAPTCHA() echo.MiddlewareFunc {
	// Always get fresh config values
	cfg := ReCAPTCHAConfig{
		Skipper:   defaultSkipper,
		SecretKey: config.ServiceReCAPTCHASecretKey.GetString(),
		MinScore:  config.ServiceReCAPTCHAMinScore.GetFloat64(),
		FieldName: config.ServiceReCAPTCHAFieldName.GetString(),
	}
	return ReCAPTCHAWithConfig(cfg)
}

// ReCAPTCHAWithConfig returns a middleware with config that validates Google reCAPTCHA v3 tokens
func ReCAPTCHAWithConfig(cfg ReCAPTCHAConfig) echo.MiddlewareFunc {
	// Check if reCAPTCHA is globally enabled
	if !config.ServiceReCAPTCHAEnabled.GetBool() {
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return next
		}
	}

	// Set default values
	if cfg.Skipper == nil {
		cfg.Skipper = defaultSkipper
	}
	if cfg.SecretKey == "" {
		cfg.SecretKey = config.ServiceReCAPTCHASecretKey.GetString()
	}
	if cfg.MinScore <= 0 || cfg.MinScore > 1.0 {
		cfg.MinScore = config.ServiceReCAPTCHAMinScore.GetFloat64()
	}
	if cfg.FieldName == "" {
		cfg.FieldName = config.ServiceReCAPTCHAFieldName.GetString()
		if cfg.FieldName == "" {
			cfg.FieldName = "recaptcha_token" // Fallback to default
		}
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Apply the skipper first thing, before any processing
			if cfg.Skipper(c) {
				return next(c)
			}

			// Read the request body
			var bodyBytes []byte
			if c.Request().Body != nil {
				bodyBytes, _ = io.ReadAll(c.Request().Body)
				// Reset the body for this handler
				c.Request().Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}

			// Parse the request body manually
			var reqBody map[string]interface{}
			if err := json.Unmarshal(bodyBytes, &reqBody); err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
			}

			// Extract token
			tokenVal, ok := reqBody[cfg.FieldName]
			if !ok || tokenVal == nil {
				return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Missing %s field", cfg.FieldName))
			}

			token, ok := tokenVal.(string)
			if !ok || token == "" {
				return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid %s field", cfg.FieldName))
			}

			// Verify token
			resp, err := verifyReCAPTCHA(token, cfg.SecretKey)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify reCAPTCHA token")
			}

			if !resp.Success {
				errMsg := "reCAPTCHA verification failed"
				if len(resp.ErrorCodes) > 0 {
					errMsg = fmt.Sprintf("%s: %s", errMsg, strings.Join(resp.ErrorCodes, ", "))
				}
				return echo.NewHTTPError(http.StatusBadRequest, errMsg)
			}

			// Check if the score is below the threshold
			if resp.Score < cfg.MinScore {
				return echo.NewHTTPError(http.StatusForbidden, "reCAPTCHA score too low")
			}

			// Store verification result in context if needed
			c.Set("recaptcha", resp)

			// Reset the body for next handlers
			c.Request().Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			// Log successful verification
			log.Printf(
				"RequestID(%s) - reCAPTCHA verification successful with score %.2f",
				c.Response().Header().Get(echo.HeaderXRequestID),
				resp.Score,
			)

			return next(c)
		}
	}
}

// defaultVerifyReCAPTCHA verifies the token with Google's reCAPTCHA API
func defaultVerifyReCAPTCHA(token, secretKey string) (*ReCAPTCHAResponse, error) {
	if token == "" || secretKey == "" {
		return nil, errors.New("token and secret key are required")
	}

	// Prepare form data
	form := url.Values{}
	form.Add("secret", secretKey)
	form.Add("response", token)

	// Send POST request to Google's reCAPTCHA API
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm(recaptchaVerifyURL, form)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to reCAPTCHA API: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse response
	var recaptchaResp ReCAPTCHAResponse
	if err := json.Unmarshal(body, &recaptchaResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &recaptchaResp, nil
}

// SkipReCAPTCHA returns a skipper that skips reCAPTCHA verification for specific paths
func SkipReCAPTCHA(paths ...string) func(echo.Context) bool {
	return func(c echo.Context) bool {
		for _, path := range paths {
			if path == c.Path() {
				return true
			}
		}
		return false
	}
}

// ApplyReCAPTCHA returns a skipper that applies reCAPTCHA verification only to specific paths
func ApplyReCAPTCHA(paths ...string) func(echo.Context) bool {
	return func(c echo.Context) bool {
		for _, path := range paths {
			if path == c.Path() {
				return false
			}
		}
		return true
	}
}
