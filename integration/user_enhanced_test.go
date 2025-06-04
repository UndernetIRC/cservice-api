//go:build integration

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/undernetirc/cservice-api/controllers"
	"github.com/undernetirc/cservice-api/internal/auth/oath/totp"
	"github.com/undernetirc/cservice-api/internal/checks"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/internal/mail"
	"github.com/undernetirc/cservice-api/models"
)

func setupEnhancedUserController(t *testing.T) (*controllers.UserController, *echo.Echo, string) {
	config.DefaultConfig()
	service := models.NewService(db)
	checks.InitUser(context.Background(), db)

	userController := controllers.NewUserController(service)

	e := echo.New()
	e.Validator = helper.NewValidator()

	// Get auth token for authenticated requests
	authController := controllers.NewAuthenticationController(service, rdb, nil)
	w := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"username": "Admin", "password":"temPass2020@"}`)
	r, _ := http.NewRequest("POST", "/login", body)
	r.Header.Set("Content-Type", "application/json")

	c := e.NewContext(r, w)
	err := authController.Login(c)
	require.NoError(t, err)

	resp := w.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	loginResponse := new(controllers.LoginResponse)
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(loginResponse)
	require.NoError(t, err)

	return userController, e, loginResponse.AccessToken
}

func TestUserController_GetCurrentUser(t *testing.T) {
	userController, e, token := setupEnhancedUserController(t)

	e.GET("/user", userController.GetCurrentUser)

	t.Run("successful get current user", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/user", nil)
		r.Header.Set("Authorization", "Bearer "+token)

		c := e.NewContext(r, w)
		claims := &helper.JwtClaims{
			UserID:   1,
			Username: "Admin",
		}
		c.Set("user", claims)

		err := userController.GetCurrentUser(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var userResponse controllers.UserResponse
		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&userResponse)
		assert.NoError(t, err)
		assert.Equal(t, "Admin", userResponse.Username)
		assert.GreaterOrEqual(t, len(userResponse.Channels), 0)
	})

	t.Run("unauthorized get current user", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/user", nil)

		c := e.NewContext(r, w)

		err := userController.GetCurrentUser(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestUserController_ChangePassword(t *testing.T) {
	userController, e, token := setupEnhancedUserController(t)

	e.PUT("/user/password", userController.ChangePassword)

	t.Run("successful password change", func(t *testing.T) {
		passwordData := controllers.ChangePasswordRequest{
			CurrentPassword: "temPass2020@",
			NewPassword:     "newStrongPassword123!",
			ConfirmPassword: "newStrongPassword123!",
		}

		bodyBytes, _ := json.Marshal(passwordData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("PUT", "/user/password", bytes.NewReader(bodyBytes))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)
		claims := &helper.JwtClaims{
			UserID:   1,
			Username: "Admin",
		}
		c.Set("user", claims)

		err := userController.ChangePassword(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response map[string]interface{}
		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response["message"], "Password changed successfully")

		// Verify we can log in with the new password
		authController := controllers.NewAuthenticationController(models.NewService(db), rdb, nil)
		loginData := map[string]string{
			"username": "Admin",
			"password": "newStrongPassword123!",
		}

		loginBytes, _ := json.Marshal(loginData)
		loginW := httptest.NewRecorder()
		loginR, _ := http.NewRequest("POST", "/login", bytes.NewReader(loginBytes))
		loginR.Header.Set("Content-Type", "application/json")

		loginC := e.NewContext(loginR, loginW)
		err = authController.Login(loginC)
		assert.NoError(t, err)

		loginResp := loginW.Result()
		assert.Equal(t, http.StatusOK, loginResp.StatusCode)

		// Reset password back to original for other tests
		resetPasswordData := controllers.ChangePasswordRequest{
			CurrentPassword: "newStrongPassword123!",
			NewPassword:     "temPass2020@",
			ConfirmPassword: "temPass2020@",
		}

		resetBytes, _ := json.Marshal(resetPasswordData)
		resetW := httptest.NewRecorder()
		resetR, _ := http.NewRequest("PUT", "/user/password", bytes.NewReader(resetBytes))
		resetR.Header.Set("Authorization", "Bearer "+token)
		resetR.Header.Set("Content-Type", "application/json")

		resetC := e.NewContext(resetR, resetW)
		resetC.Set("user", claims)
		userController.ChangePassword(resetC)
	})

	t.Run("invalid current password", func(t *testing.T) {
		passwordData := controllers.ChangePasswordRequest{
			CurrentPassword: "wrongpassword",
			NewPassword:     "newStrongPassword123!",
			ConfirmPassword: "newStrongPassword123!",
		}

		bodyBytes, _ := json.Marshal(passwordData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("PUT", "/user/password", bytes.NewReader(bodyBytes))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)
		claims := &helper.JwtClaims{
			UserID:   1,
			Username: "Admin",
		}
		c.Set("user", claims)

		err := userController.ChangePassword(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("password mismatch", func(t *testing.T) {
		passwordData := controllers.ChangePasswordRequest{
			CurrentPassword: "temPass2020@",
			NewPassword:     "newStrongPassword123!",
			ConfirmPassword: "differentPassword123!",
		}

		bodyBytes, _ := json.Marshal(passwordData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("PUT", "/user/password", bytes.NewReader(bodyBytes))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)
		claims := &helper.JwtClaims{
			UserID:   1,
			Username: "Admin",
		}
		c.Set("user", claims)

		err := userController.ChangePassword(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("weak new password", func(t *testing.T) {
		passwordData := controllers.ChangePasswordRequest{
			CurrentPassword: "temPass2020@",
			NewPassword:     "weak",
			ConfirmPassword: "weak",
		}

		bodyBytes, _ := json.Marshal(passwordData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("PUT", "/user/password", bytes.NewReader(bodyBytes))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)
		claims := &helper.JwtClaims{
			UserID:   1,
			Username: "Admin",
		}
		c.Set("user", claims)

		err := userController.ChangePassword(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("unauthorized password change", func(t *testing.T) {
		passwordData := controllers.ChangePasswordRequest{
			CurrentPassword: "temPass2020@",
			NewPassword:     "newStrongPassword123!",
			ConfirmPassword: "newStrongPassword123!",
		}

		bodyBytes, _ := json.Marshal(passwordData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("PUT", "/user/password", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)

		err := userController.ChangePassword(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestUserController_TOTPOperations(t *testing.T) {
	userController, e, token := setupEnhancedUserController(t)

	// Add JWT middleware for authentication
	jwtConfig := helper.GetEchoJWTConfig()
	e.Use(echojwt.WithConfig(jwtConfig))

	e.POST("/user/2fa/enroll", userController.EnrollTOTP)
	e.POST("/user/2fa/activate", userController.ActivateTOTP)
	e.POST("/user/2fa/disable", userController.DisableTOTP)

	var totpSecret string

	t.Run("successful TOTP enrollment", func(t *testing.T) {
		enrollData := controllers.EnrollTOTPRequest{
			CurrentPassword: "temPass2020@",
		}

		bodyBytes, _ := json.Marshal(enrollData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/user/2fa/enroll", bytes.NewReader(bodyBytes))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")

		// Use Echo's ServeHTTP to go through the full request pipeline
		e.ServeHTTP(w, r)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var enrollResponse controllers.EnrollTOTPResponse
		dec := json.NewDecoder(resp.Body)
		err := dec.Decode(&enrollResponse)
		assert.NoError(t, err)
		assert.NotEmpty(t, enrollResponse.Secret)
		assert.NotEmpty(t, enrollResponse.QRCodeBase64)
		assert.Regexp(t, `^[A-Za-z0-9+/]+=*$`, enrollResponse.QRCodeBase64)

		totpSecret = enrollResponse.Secret
	})

	t.Run("successful TOTP activation", func(t *testing.T) {
		require.NotEmpty(t, totpSecret, "TOTP secret should be set from enrollment test")

		// Generate a valid OTP code using the secret
		totpInstance := totp.New(totpSecret, 6, 30, 1)
		validOTP := totpInstance.Generate()

		activateData := controllers.ActivateTOTPRequest{
			OTPCode: validOTP,
		}

		bodyBytes, _ := json.Marshal(activateData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/user/2fa/activate", bytes.NewReader(bodyBytes))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")

		// Use Echo's ServeHTTP to go through the full request pipeline
		e.ServeHTTP(w, r)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response map[string]interface{}
		dec := json.NewDecoder(resp.Body)
		err := dec.Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response["message"], "2FA activated successfully")
	})

	t.Run("successful TOTP disable", func(t *testing.T) {
		require.NotEmpty(t, totpSecret, "TOTP secret should be set from enrollment test")

		// Generate a valid OTP code for disabling
		totpInstance := totp.New(totpSecret, 6, 30, 1)
		validOTP := totpInstance.Generate()

		disableData := controllers.DisableTOTPRequest{
			CurrentPassword: "temPass2020@",
			OTPCode:         validOTP,
		}

		bodyBytes, _ := json.Marshal(disableData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/user/2fa/disable", bytes.NewReader(bodyBytes))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")

		// Use Echo's ServeHTTP to go through the full request pipeline
		e.ServeHTTP(w, r)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response map[string]interface{}
		dec := json.NewDecoder(resp.Body)
		err := dec.Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response["message"], "2FA disabled successfully")
	})

	t.Run("enroll TOTP missing password", func(t *testing.T) {
		enrollData := controllers.EnrollTOTPRequest{
			CurrentPassword: "",
		}

		bodyBytes, _ := json.Marshal(enrollData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/user/2fa/enroll", bytes.NewReader(bodyBytes))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")

		// Use Echo's ServeHTTP to go through the full request pipeline
		e.ServeHTTP(w, r)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("activate TOTP missing code", func(t *testing.T) {
		activateData := controllers.ActivateTOTPRequest{
			OTPCode: "",
		}

		bodyBytes, _ := json.Marshal(activateData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/user/2fa/activate", bytes.NewReader(bodyBytes))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")

		// Use Echo's ServeHTTP to go through the full request pipeline
		e.ServeHTTP(w, r)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("disable TOTP missing fields", func(t *testing.T) {
		disableData := controllers.DisableTOTPRequest{
			CurrentPassword: "",
			OTPCode:         "",
		}

		bodyBytes, _ := json.Marshal(disableData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/user/2fa/disable", bytes.NewReader(bodyBytes))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")

		// Use Echo's ServeHTTP to go through the full request pipeline
		e.ServeHTTP(w, r)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("unauthorized TOTP operations", func(t *testing.T) {
		enrollData := controllers.EnrollTOTPRequest{
			CurrentPassword: "temPass2020@",
		}

		bodyBytes, _ := json.Marshal(enrollData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/user/2fa/enroll", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")
		// No Authorization header

		// Use Echo's ServeHTTP to go through the full request pipeline
		e.ServeHTTP(w, r)

		resp := w.Result()
		// JWT middleware can return either 400 (Bad Request) or 401 (Unauthorized) for missing tokens
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusUnauthorized}, resp.StatusCode)
	})
}

func TestPasswordResetFlow(t *testing.T) {
	// Set up Mailpit container for email testing
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "axllent/mailpit:latest",
		ExposedPorts: []string{"1025/tcp", "8025/tcp"},
		WaitingFor: wait.ForAll(
			wait.ForLog("[http] starting on"),
			wait.ForListeningPort("1025/tcp"),
			wait.ForListeningPort("8025/tcp"),
		),
		Env: map[string]string{
			"MP_SMTP_BIND_ADDR": "0.0.0.0:1025",
			"MP_UI_BIND_ADDR":   "0.0.0.0:8025",
		},
	}

	mailpitContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "failed to start mailpit container")

	defer func() {
		if err := mailpitContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate mailpit container: %s", err)
		}
	}()

	host, err := mailpitContainer.Host(ctx)
	require.NoError(t, err, "failed to get container host")

	smtpPort, err := mailpitContainer.MappedPort(ctx, "1025/tcp")
	require.NoError(t, err, "failed to get smtp port")

	apiPort, err := mailpitContainer.MappedPort(ctx, "8025/tcp")
	require.NoError(t, err, "failed to get api port")

	// Configure application for testing
	config.DefaultConfig()

	// Convert port string to uint for SMTP configuration
	smtpPortNum, err := nat.ParsePort(smtpPort.Port())
	require.NoError(t, err, "failed to parse SMTP port")

	// Configure mail settings to use Mailpit
	config.SMTPHost.Set(host)
	config.SMTPPort.Set(uint(smtpPortNum))
	config.SMTPUseTLS.Set(false)
	config.SMTPFromEmail.Set("test@cservice.undernet.org")
	config.SMTPFromName.Set("CService Test")
	config.ServiceMailEnabled.Set(true)
	config.ServiceBaseURL.Set("http://localhost:3000") // Set base URL for reset links

	// Configure email templates for testing
	config.ServiceMailTemplateDir.Set("")
	config.ServiceMailDefaultTemplate.Set("default")

	// Initialize the template engine with embedded templates
	templateEngine := mail.GetTemplateEngine()
	require.NoError(t, templateEngine.Init(), "Failed to initialize template engine")

	// Initialize mail queue
	mail.MailQueue = make(chan mail.Mail, 10)
	mailErr := make(chan error, 10)

	// Start error handler goroutine to log mail errors in tests
	go func() {
		for err := range mailErr {
			t.Logf("Mail processing error: %v", err)
		}
	}()

	// Start mail worker for processing emails
	go mail.MailWorker(mail.MailQueue, mailErr, 2)

	// Setup controllers and database
	service := models.NewService(db)
	checks.InitUser(context.Background(), db)
	authController := controllers.NewAuthenticationController(service, rdb, nil)

	e := echo.New()
	e.Validator = helper.NewValidator()

	e.POST("/auth/password-reset", authController.RequestPasswordReset)
	e.POST("/auth/reset-password", authController.ResetPassword)
	e.POST("/login", authController.Login)

	// Set up Admin user with email for password reset testing
	_, err = dbPool.Exec(context.Background(), "UPDATE users SET email = $1 WHERE user_name = $2", "admin@example.com", "Admin")
	require.NoError(t, err, "Failed to set Admin user email")

	// Helper functions for Mailpit interaction
	apiEndpoint := fmt.Sprintf("http://%s:%s", host, apiPort.Port())

	clearMailpitMessages := func() error {
		url := fmt.Sprintf("%s/api/v1/messages", apiEndpoint)
		req, err := http.NewRequest(http.MethodDelete, url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to clear messages: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
		}
		return nil
	}

	getMailpitMessages := func() ([]MailpitMessage, error) {
		url := fmt.Sprintf("%s/api/v1/messages", apiEndpoint)
		resp, err := http.Get(url)
		if err != nil {
			return nil, fmt.Errorf("failed to get messages: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
		}

		var response MailpitResponse
		if err = json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("failed to unmarshal response: %w", err)
		}
		return response.Messages, nil
	}

	getFullMessage := func(messageID string) (string, error) {
		url := fmt.Sprintf("%s/api/v1/message/%s", apiEndpoint, messageID)
		resp, err := http.Get(url)
		if err != nil {
			return "", fmt.Errorf("failed to get message: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read response body: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
		}

		var messageData map[string]interface{}
		if err = json.Unmarshal(body, &messageData); err != nil {
			return "", fmt.Errorf("failed to unmarshal message: %w", err)
		}

		if text, ok := messageData["Text"].(string); ok && text != "" {
			return text, nil
		}

		if html, ok := messageData["HTML"].(string); ok && html != "" {
			return html, nil
		}

		return "", fmt.Errorf("no text or HTML content found in message")
	}

	extractResetToken := func(emailBody string) (string, error) {
		// Look for password reset URLs in the email
		urlRegex := regexp.MustCompile(`https?://[^\s<>]+/reset-password\?token=([a-zA-Z0-9]+)`)
		matches := urlRegex.FindAllStringSubmatch(emailBody, -1)

		// Look for the cleanest match (longest token without MIME artifacts)
		var bestToken string
		maxTokenLength := 0

		for _, match := range matches {
			if len(match) > 1 {
				token := match[1]
				// Clean up any MIME artifacts
				token = strings.TrimSuffix(token, "=")
				token = strings.TrimSuffix(token, "=")

				// Handle quoted-printable encoding
				if strings.HasPrefix(token, "3D") {
					token = token[2:]
				}

				if len(token) > maxTokenLength && len(token) >= 20 {
					bestToken = token
					maxTokenLength = len(token)
				}
			}
		}

		if bestToken != "" {
			return bestToken, nil
		}

		// Fallback patterns for reset tokens
		tokenPatterns := []string{
			`\?token=([a-zA-Z0-9]+)`,                 // URL with ?token=
			`/token/([a-zA-Z0-9]+)`,                  // URL with /token/
			`reset-password\?token=([a-zA-Z0-9]+)`,   // reset-password?token= format
			`reset[_-]?password[^=]*=([a-zA-Z0-9]+)`, // Various reset password patterns
		}

		for _, pattern := range tokenPatterns {
			re := regexp.MustCompile(pattern)
			matches := re.FindAllStringSubmatch(emailBody, -1)
			for _, match := range matches {
				if len(match) > 1 && len(match[1]) >= 20 {
					token := strings.TrimSuffix(match[1], "=")
					if strings.HasPrefix(token, "3D") {
						token = token[2:]
					}
					if len(token) >= 20 {
						return token, nil
					}
				}
			}
		}

		return "", fmt.Errorf("password reset token not found in email body")
	}

	var resetToken string

	t.Run("successful password reset request", func(t *testing.T) {
		// Clear any existing emails
		err := clearMailpitMessages()
		require.NoError(t, err, "Failed to clear existing emails")

		resetRequest := map[string]string{
			"email": "admin@example.com",
		}

		bodyBytes, _ := json.Marshal(resetRequest)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/auth/password-reset", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)
		err = authController.RequestPasswordReset(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response map[string]interface{}
		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response["message"], "password reset link")

		// Wait for email to be sent
		time.Sleep(2 * time.Second)

		// Get emails from Mailpit
		messages, err := getMailpitMessages()
		require.NoError(t, err, "Failed to get emails from Mailpit")
		require.Len(t, messages, 1, "Should have received exactly one password reset email")

		message := messages[0]
		assert.Equal(t, "admin@example.com", message.To[0].Address)
		assert.Contains(t, message.Subject, "Reset")

		// Get full email content
		fullMessage, err := getFullMessage(message.ID)
		require.NoError(t, err, "Failed to get full email content")

		// Extract reset token from email
		extractedToken, err := extractResetToken(fullMessage)
		require.NoError(t, err, "Failed to extract reset token from email")
		require.NotEmpty(t, extractedToken, "Reset token should not be empty")

		resetToken = extractedToken
		t.Logf("Successfully extracted reset token from email: %s", resetToken)
	})

	t.Run("successful password reset", func(t *testing.T) {
		require.NotEmpty(t, resetToken, "Reset token should be set from previous test")

		resetPasswordRequest := map[string]string{
			"token":            resetToken,
			"new_password":     "newResetPassword123!",
			"confirm_password": "newResetPassword123!",
		}

		bodyBytes, _ := json.Marshal(resetPasswordRequest)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/auth/reset-password", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)
		err := authController.ResetPassword(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response map[string]interface{}
		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response["message"], "successfully reset")

		// Verify we can log in with the new password
		loginData := map[string]string{
			"username": "Admin",
			"password": "newResetPassword123!",
		}

		loginBytes, _ := json.Marshal(loginData)
		loginW := httptest.NewRecorder()
		loginR, _ := http.NewRequest("POST", "/login", bytes.NewReader(loginBytes))
		loginR.Header.Set("Content-Type", "application/json")

		loginC := e.NewContext(loginR, loginW)
		err = authController.Login(loginC)
		assert.NoError(t, err)

		loginResp := loginW.Result()
		assert.Equal(t, http.StatusOK, loginResp.StatusCode)

		// Reset the password back to original for other tests
		resetBackData := map[string]string{
			"username": "Admin",
			"password": "newResetPassword123!",
		}

		// Get a new token for password change
		tokenBytes, _ := json.Marshal(resetBackData)
		tokenW := httptest.NewRecorder()
		tokenR, _ := http.NewRequest("POST", "/login", bytes.NewReader(tokenBytes))
		tokenR.Header.Set("Content-Type", "application/json")

		tokenC := e.NewContext(tokenR, tokenW)
		err = authController.Login(tokenC)
		require.NoError(t, err)

		var tokenResponse controllers.LoginResponse
		dec = json.NewDecoder(tokenW.Body)
		err = dec.Decode(&tokenResponse)
		require.NoError(t, err)

		// Change password back
		userController := controllers.NewUserController(service)
		e.PUT("/user/password", userController.ChangePassword)

		passwordData := controllers.ChangePasswordRequest{
			CurrentPassword: "newResetPassword123!",
			NewPassword:     "temPass2020@",
			ConfirmPassword: "temPass2020@",
		}

		passBytes, _ := json.Marshal(passwordData)
		passW := httptest.NewRecorder()
		passR, _ := http.NewRequest("PUT", "/user/password", bytes.NewReader(passBytes))
		passR.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)
		passR.Header.Set("Content-Type", "application/json")

		passC := e.NewContext(passR, passW)
		passC.Set("user", &helper.JwtClaims{
			UserID:   1,
			Username: "Admin",
		})
		userController.ChangePassword(passC)
	})

	t.Run("password reset request for non-existent email", func(t *testing.T) {
		// Clear existing emails
		err := clearMailpitMessages()
		require.NoError(t, err)

		resetRequest := map[string]string{
			"email": "nonexistent@test.com",
		}

		bodyBytes, _ := json.Marshal(resetRequest)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/auth/password-reset", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)
		err = authController.RequestPasswordReset(c)
		assert.NoError(t, err)

		resp := w.Result()
		// Should still return 200 for security reasons (don't leak email existence)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response map[string]interface{}
		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response["message"], "password reset link")

		// Wait a bit and verify no email was actually sent
		time.Sleep(1 * time.Second)
		messages, err := getMailpitMessages()
		require.NoError(t, err)
		assert.Len(t, messages, 0, "No email should be sent for non-existent email")
	})

	t.Run("invalid reset token", func(t *testing.T) {
		resetPasswordRequest := map[string]string{
			"token":            "invalid-token",
			"new_password":     "newPassword123!",
			"confirm_password": "newPassword123!",
		}

		bodyBytes, _ := json.Marshal(resetPasswordRequest)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/auth/reset-password", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)
		err := authController.ResetPassword(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("password mismatch in reset", func(t *testing.T) {
		// Clear existing emails and create a new reset token
		err := clearMailpitMessages()
		require.NoError(t, err)

		resetRequest := map[string]string{
			"email": "admin@example.com",
		}

		bodyBytes, _ := json.Marshal(resetRequest)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/auth/password-reset", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)
		err = authController.RequestPasswordReset(c)
		assert.NoError(t, err)

		// Wait for email and extract token
		time.Sleep(2 * time.Second)
		messages, err := getMailpitMessages()
		require.NoError(t, err)
		require.Len(t, messages, 1, "Should receive password reset email")

		fullMessage, err := getFullMessage(messages[0].ID)
		require.NoError(t, err)

		newToken, err := extractResetToken(fullMessage)
		require.NoError(t, err)

		resetPasswordRequest := map[string]string{
			"token":            newToken,
			"new_password":     "newPassword123!",
			"confirm_password": "differentPassword123!",
		}

		bodyBytes, _ = json.Marshal(resetPasswordRequest)
		w = httptest.NewRecorder()
		r, _ = http.NewRequest("POST", "/auth/reset-password", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c = e.NewContext(r, w)
		err = authController.ResetPassword(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestUserController_GetUserRoles(t *testing.T) {
	userController, e, token := setupEnhancedUserController(t)

	e.GET("/users/:id/roles", userController.GetUserRoles)

	t.Run("get user roles", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/users/1/roles", nil)
		r.Header.Set("Authorization", "Bearer "+token)

		c := e.NewContext(r, w)
		c.SetParamNames("id")
		c.SetParamValues("1")

		err := userController.GetUserRoles(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var roleResponse controllers.UserRolesResponse
		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&roleResponse)
		assert.NoError(t, err)
		assert.Equal(t, int32(1), roleResponse.User.ID)
		assert.Equal(t, "Admin", roleResponse.User.Username)
		assert.GreaterOrEqual(t, len(roleResponse.User.Roles), 0)
	})

	t.Run("get roles for non-existent user", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/users/99999/roles", nil)
		r.Header.Set("Authorization", "Bearer "+token)

		c := e.NewContext(r, w)
		c.SetParamNames("id")
		c.SetParamValues("99999")

		err := userController.GetUserRoles(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Contains(t, []int{http.StatusNotFound, http.StatusInternalServerError}, resp.StatusCode)
	})

	t.Run("invalid user ID", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/users/invalid/roles", nil)
		r.Header.Set("Authorization", "Bearer "+token)

		c := e.NewContext(r, w)
		c.SetParamNames("id")
		c.SetParamValues("invalid")

		err := userController.GetUserRoles(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestUserController_GetUserChannels(t *testing.T) {
	userController, e, token := setupEnhancedUserController(t)

	e.GET("/users/:id/channels", userController.GetUserChannels)

	t.Run("get user channels", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/users/1/channels", nil)
		r.Header.Set("Authorization", "Bearer "+token)

		c := e.NewContext(r, w)
		c.SetParamNames("id")
		c.SetParamValues("1")

		err := userController.GetUserChannels(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var channels []controllers.ChannelMembership
		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&channels)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(channels), 0)
	})

	t.Run("get channels for non-existent user", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/users/99999/channels", nil)
		r.Header.Set("Authorization", "Bearer "+token)

		c := e.NewContext(r, w)
		c.SetParamNames("id")
		c.SetParamValues("99999")

		err := userController.GetUserChannels(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("invalid user ID for channels", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/users/invalid/channels", nil)
		r.Header.Set("Authorization", "Bearer "+token)

		c := e.NewContext(r, w)
		c.SetParamNames("id")
		c.SetParamValues("invalid")

		err := userController.GetUserChannels(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestUserController_Integration(t *testing.T) {
	userController, e, token := setupEnhancedUserController(t)

	// Setup routes
	e.GET("/user", userController.GetCurrentUser)
	e.GET("/users/:id", userController.GetUser)
	e.GET("/users/:id/roles", userController.GetUserRoles)
	e.GET("/users/:id/channels", userController.GetUserChannels)
	e.PUT("/user/password", userController.ChangePassword)

	t.Run("complete user management workflow", func(t *testing.T) {
		claims := &helper.JwtClaims{
			UserID:   1,
			Username: "Admin",
		}

		// Step 1: Get current user
		w1 := httptest.NewRecorder()
		r1, _ := http.NewRequest("GET", "/user", nil)
		r1.Header.Set("Authorization", "Bearer "+token)

		c1 := e.NewContext(r1, w1)
		c1.Set("user", claims)

		err := userController.GetCurrentUser(c1)
		assert.NoError(t, err)

		resp1 := w1.Result()
		assert.Equal(t, http.StatusOK, resp1.StatusCode)

		// Step 2: Get user by ID
		w2 := httptest.NewRecorder()
		r2, _ := http.NewRequest("GET", "/users/1", nil)
		r2.Header.Set("Authorization", "Bearer "+token)

		c2 := e.NewContext(r2, w2)
		c2.SetParamNames("id")
		c2.SetParamValues("1")

		err = userController.GetUser(c2)
		assert.NoError(t, err)

		resp2 := w2.Result()
		assert.Equal(t, http.StatusOK, resp2.StatusCode)

		// Step 3: Get user roles
		w3 := httptest.NewRecorder()
		r3, _ := http.NewRequest("GET", "/users/1/roles", nil)
		r3.Header.Set("Authorization", "Bearer "+token)

		c3 := e.NewContext(r3, w3)
		c3.SetParamNames("id")
		c3.SetParamValues("1")

		err = userController.GetUserRoles(c3)
		assert.NoError(t, err)

		resp3 := w3.Result()
		assert.Equal(t, http.StatusOK, resp3.StatusCode)

		// Step 4: Get user channels
		w4 := httptest.NewRecorder()
		r4, _ := http.NewRequest("GET", "/users/1/channels", nil)
		r4.Header.Set("Authorization", "Bearer "+token)

		c4 := e.NewContext(r4, w4)
		c4.SetParamNames("id")
		c4.SetParamValues("1")

		err = userController.GetUserChannels(c4)
		assert.NoError(t, err)

		resp4 := w4.Result()
		assert.Equal(t, http.StatusOK, resp4.StatusCode)

		// All operations should succeed for the Admin user
		t.Log("Complete user workflow tested successfully")
	})

	t.Run("error handling workflow", func(t *testing.T) {
		// Test various error conditions in sequence

		// Invalid user ID
		w1 := httptest.NewRecorder()
		r1, _ := http.NewRequest("GET", "/users/invalid", nil)
		r1.Header.Set("Authorization", "Bearer "+token)

		c1 := e.NewContext(r1, w1)
		c1.SetParamNames("id")
		c1.SetParamValues("invalid")

		err := userController.GetUser(c1)
		assert.NoError(t, err)

		resp1 := w1.Result()
		assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)

		// Non-existent user
		w2 := httptest.NewRecorder()
		r2, _ := http.NewRequest("GET", "/users/99999", nil)
		r2.Header.Set("Authorization", "Bearer "+token)

		c2 := e.NewContext(r2, w2)
		c2.SetParamNames("id")
		c2.SetParamValues("99999")

		err = userController.GetUser(c2)
		assert.NoError(t, err)

		resp2 := w2.Result()
		assert.Equal(t, http.StatusNotFound, resp2.StatusCode)

		t.Log("Error handling workflow tested successfully")
	})
}
