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
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/undernetirc/cservice-api/controllers"
	"github.com/undernetirc/cservice-api/internal/checks"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/internal/mail"
	"github.com/undernetirc/cservice-api/models"
)

type userRegisterTest struct {
	mailpitContainer testcontainers.Container
	host             string
	smtpPort         string
	apiPort          string
	controller       *controllers.UserRegisterController
	echo             *echo.Echo
	ctx              context.Context
	cancel           context.CancelFunc
	mailQueue        chan mail.Mail
	mailErr          chan error
}

func setupUserRegisterWithMailpit(t *testing.T) *userRegisterTest {
	ctx := context.Background()

	// Setup Mailpit container - modern replacement for abandoned MailHog
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

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "failed to start mailpit container")

	host, err := container.Host(ctx)
	require.NoError(t, err, "failed to get container host")

	smtpPort, err := container.MappedPort(ctx, "1025/tcp")
	require.NoError(t, err, "failed to get smtp port")

	apiPort, err := container.MappedPort(ctx, "8025/tcp")
	require.NoError(t, err, "failed to get api port")

	t.Logf("Mailpit SMTP: %s:%s", host, smtpPort.Port())
	t.Logf("Mailpit API: http://%s:%s", host, apiPort.Port())

	// Configure application for testing
	config.DefaultConfig()

	// Convert port string to uint for SMTP configuration
	smtpPortNum, err := nat.ParsePort(smtpPort.Port())
	require.NoError(t, err, "failed to parse SMTP port")

	// Configure mail settings
	config.SMTPHost.Set(host)
	config.SMTPPort.Set(uint(smtpPortNum))
	config.SMTPUseTLS.Set(false)
	config.SMTPFromEmail.Set("test@cservice.undernet.org")
	config.SMTPFromName.Set("CService Test")
	config.ServiceMailEnabled.Set(true)

	// Configure email templates for testing
	config.ServiceMailTemplateDir.Set("")
	config.ServiceMailDefaultTemplate.Set("default")

	// Initialize the template engine with embedded templates
	templateEngine := mail.GetTemplateEngine()
	require.NoError(t, templateEngine.Init(), "Failed to initialize template engine")

	// Create context for cancellation
	testCtx, cancel := context.WithCancel(context.Background())

	// Initialize mail queue
	mailQueue := make(chan mail.Mail, 10)
	mailErr := make(chan error, 10)

	// Set global mail queue for the mail package
	mail.MailQueue = mailQueue

	// Start error handler goroutine to log mail errors in tests
	go func() {
		defer close(mailErr)
		for {
			select {
			case err, ok := <-mailErr:
				if !ok {
					return
				}
				if err != nil {
					t.Logf("Mail processing error: %v", err)
				}
			case <-testCtx.Done():
				return
			}
		}
	}()

	// Start mail worker for processing registration emails
	go func() {
		// Use a custom mail worker implementation that can be cancelled
		for i := 0; i < 2; i++ {
			go func(workerID int) {
				for {
					select {
					case m, ok := <-mailQueue:
						if !ok {
							return
						}
						err := mail.ProcessMail(m)
						if err != nil {
							select {
							case mailErr <- err:
							case <-testCtx.Done():
								return
							}
						}
					case <-testCtx.Done():
						return
					}
				}
			}(i)
		}
	}()

	// Setup controller
	service := models.NewService(db)
	checks.InitUser(context.Background(), db)

	userRegisterController := controllers.NewUserRegisterController(service, dbPool)

	e := echo.New()
	e.Validator = helper.NewValidator()

	return &userRegisterTest{
		mailpitContainer: container,
		host:             host,
		smtpPort:         smtpPort.Port(),
		apiPort:          apiPort.Port(),
		controller:       userRegisterController,
		echo:             e,
		ctx:              testCtx,
		cancel:           cancel,
		mailQueue:        mailQueue,
		mailErr:          mailErr,
	}
}

func (urt *userRegisterTest) getAPIEndpoint() string {
	return fmt.Sprintf("http://%s:%s", urt.host, urt.apiPort)
}

func (urt *userRegisterTest) clearMailpitMessages() error {
	url := fmt.Sprintf("%s/api/v1/messages", urt.getAPIEndpoint())
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to clear messages: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (urt *userRegisterTest) getMailpitMessages() ([]MailpitMessage, error) {
	url := fmt.Sprintf("%s/api/v1/messages", urt.getAPIEndpoint())
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

func (urt *userRegisterTest) extractActivationToken(emailBody string) (string, error) {
	// First, let's try to find complete URLs in the email body
	urlRegex := regexp.MustCompile(`https?://[^\s<>]+/activate\?token=([a-zA-Z0-9]+)`)
	matches := urlRegex.FindAllStringSubmatch(emailBody, -1)

	// Look for the cleanest match (longest token without MIME artifacts)
	var bestToken string
	maxTokenLength := 0

	for _, match := range matches {
		if len(match) > 1 {
			token := match[1]
			// Clean up any MIME artifacts (= characters at end)
			token = strings.TrimSuffix(token, "=")
			token = strings.TrimSuffix(token, "=")

			// Handle quoted-printable encoding where 3D represents =
			if strings.HasPrefix(token, "3D") {
				token = token[2:] // Remove the 3D prefix
			}

			// Prefer longer tokens as they're more likely to be complete
			if len(token) > maxTokenLength && len(token) >= 20 {
				bestToken = token
				maxTokenLength = len(token)
			}
		}
	}

	if bestToken != "" {
		return bestToken, nil
	}

	// Fallback: Look for any token pattern after ?token= or /token/
	tokenPatterns := []string{
		`\?token=([a-zA-Z0-9]+)`,         // URL with ?token=
		`/token/([a-zA-Z0-9]+)`,          // URL with /token/
		`activate\?token=([a-zA-Z0-9]+)`, // activate?token= format
	}

	for _, pattern := range tokenPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(emailBody, -1)
		for _, match := range matches {
			if len(match) > 1 && len(match[1]) >= 20 { // Ensure token is reasonably long
				token := strings.TrimSuffix(match[1], "=")
				// Handle quoted-printable encoding where 3D represents =
				if strings.HasPrefix(token, "3D") {
					token = token[2:] // Remove the 3D prefix
				}
				if len(token) >= 20 {
					return token, nil
				}
			}
		}
	}

	return "", fmt.Errorf("activation token not found in email body")
}

func (urt *userRegisterTest) terminate() error {
	// Cancel context to stop background goroutines
	urt.cancel()

	// Close channels to signal shutdown
	close(urt.mailQueue)

	// Give some time for goroutines to finish
	time.Sleep(100 * time.Millisecond)

	// Terminate container
	return urt.mailpitContainer.Terminate(context.Background())
}

func setupUserRegisterController(t *testing.T) (*controllers.UserRegisterController, *echo.Echo) {
	config.DefaultConfig()

	// Disable mail service for tests that don't need it to prevent channel issues
	config.ServiceMailEnabled.Set(false)

	// Set up a dummy mail queue to prevent nil pointer issues
	mail.MailQueue = make(chan mail.Mail, 1)

	service := models.NewService(db)
	checks.InitUser(context.Background(), db)

	userRegisterController := controllers.NewUserRegisterController(service, dbPool)

	e := echo.New()
	e.Validator = helper.NewValidator()

	return userRegisterController, e
}

func TestUserRegisterController_CompleteRegistrationFlow(t *testing.T) {
	urt := setupUserRegisterWithMailpit(t)
	defer func() {
		if err := urt.terminate(); err != nil {
			t.Logf("failed to terminate mailpit container: %s", err)
		}
	}()

	urt.echo.POST("/register", urt.controller.UserRegister)
	urt.echo.POST("/activate", urt.controller.UserActivateAccount)

	t.Run("complete registration and activation flow", func(t *testing.T) {
		// Clear any existing emails
		err := urt.clearMailpitMessages()
		require.NoError(t, err, "failed to clear existing emails")

		// Generate unique user data with shorter username (max 12 chars)
		username := "test" + helper.GenerateSecureToken(4) // "test" + 4 chars = 8 chars total
		email := username + "@example.com"

		// Step 1: Register a new user
		registrationData := controllers.UserRegisterRequest{
			Username:        username,
			Password:        "strongPassword123!",
			ConfirmPassword: "strongPassword123!",
			Email:           email,
			AUP:             true,
			COPPA:           true,
		}

		bodyBytes, _ := json.Marshal(registrationData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/register", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := urt.echo.NewContext(r, w)

		err = urt.controller.UserRegister(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusCreated, resp.StatusCode, "Registration should succeed")

		// Step 2: Wait for email to be sent and retrieve it
		time.Sleep(2 * time.Second) // Give some time for email processing

		messages, err := urt.getMailpitMessages()
		require.NoError(t, err, "failed to get emails")
		require.Len(t, messages, 1, "should have received exactly one email")

		message := messages[0]
		assert.Contains(t, message.From.Address, "@cservice.undernet.org", "Email should be from CService domain")
		assert.Len(t, message.To, 1)
		assert.Equal(t, email, message.To[0].Address)

		t.Logf("Email subject: %s", message.Subject)

		// Step 3: Get the full email content to extract activation token
		// Mailpit requires a separate API call to get the full message content
		fullMessage, err := urt.getFullMessage(message.ID)
		require.NoError(t, err, "failed to get full message content")

		activationToken, err := urt.extractActivationToken(fullMessage)
		require.NoError(t, err, "failed to extract activation token from email")
		require.NotEmpty(t, activationToken, "activation token should not be empty")

		t.Logf("Extracted activation token: %s", activationToken)

		// Step 4: Activate the account using the token
		activationData := controllers.UserRegisterActivateRequest{
			Token: activationToken,
		}

		bodyBytes2, _ := json.Marshal(activationData)
		w2 := httptest.NewRecorder()
		r2, _ := http.NewRequest("POST", "/activate", bytes.NewReader(bodyBytes2))
		r2.Header.Set("Content-Type", "application/json")

		c2 := urt.echo.NewContext(r2, w2)

		err = urt.controller.UserActivateAccount(c2)
		assert.NoError(t, err)

		resp2 := w2.Result()
		assert.Equal(t, http.StatusOK, resp2.StatusCode, "Account activation should succeed")

		t.Logf("✓ Complete registration flow tested successfully for user: %s", username)
	})

	t.Run("activation with invalid token", func(t *testing.T) {
		// Clear emails
		err := urt.clearMailpitMessages()
		require.NoError(t, err)

		activationData := controllers.UserRegisterActivateRequest{
			Token: "invalid_token_12345",
		}

		bodyBytes, _ := json.Marshal(activationData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/activate", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := urt.echo.NewContext(r, w)

		err = urt.controller.UserActivateAccount(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "Invalid token should return 404")
	})

	t.Run("multiple registration attempts with same email", func(t *testing.T) {
		// Clear emails
		err := urt.clearMailpitMessages()
		require.NoError(t, err)

		username := "dup" + helper.GenerateSecureToken(3) // "dup" + 3 chars = 6 chars total
		email := username + "@example.com"

		registrationData := controllers.UserRegisterRequest{
			Username:        username,
			Password:        "strongPassword123!",
			ConfirmPassword: "strongPassword123!",
			Email:           email,
			AUP:             true,
			COPPA:           true,
		}

		// First registration
		bodyBytes, _ := json.Marshal(registrationData)
		w1 := httptest.NewRecorder()
		r1, _ := http.NewRequest("POST", "/register", bytes.NewReader(bodyBytes))
		r1.Header.Set("Content-Type", "application/json")

		c1 := urt.echo.NewContext(r1, w1)
		err = urt.controller.UserRegister(c1)
		assert.NoError(t, err)

		resp1 := w1.Result()
		assert.Equal(t, http.StatusCreated, resp1.StatusCode)

		// Second registration with same username should fail
		registrationData.Username = username // Same username
		registrationData.Email = "different@example.com"

		bodyBytes2, _ := json.Marshal(registrationData)
		w2 := httptest.NewRecorder()
		r2, _ := http.NewRequest("POST", "/register", bytes.NewReader(bodyBytes2))
		r2.Header.Set("Content-Type", "application/json")

		c2 := urt.echo.NewContext(r2, w2)
		err = urt.controller.UserRegister(c2)
		assert.NoError(t, err)

		resp2 := w2.Result()
		assert.Equal(t, http.StatusConflict, resp2.StatusCode, "Duplicate username should return conflict")
	})
}

func TestUserRegisterController_Register(t *testing.T) {
	userRegisterController, e := setupUserRegisterController(t)

	e.POST("/register", userRegisterController.UserRegister)

	t.Run("successful registration", func(t *testing.T) {
		registrationData := controllers.UserRegisterRequest{
			Username:        "testuser123",
			Password:        "strongPassword123!",
			ConfirmPassword: "strongPassword123!",
			Email:           "testuser123@example.com",
			AUP:             true,
			COPPA:           true,
		}

		bodyBytes, _ := json.Marshal(registrationData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/register", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)

		err := userRegisterController.UserRegister(c)
		assert.NoError(t, err)

		resp := w.Result()
		// Should succeed or fail depending on database state
		assert.Contains(t, []int{http.StatusCreated, http.StatusConflict}, resp.StatusCode)

		if resp.StatusCode == http.StatusCreated {
			// For 201 Created, there's no response body (NoContent)
			// ContentLength might be -1 if not explicitly set, so check body content instead
			body, _ := io.ReadAll(resp.Body)
			assert.Equal(t, 0, len(body))
		}
	})

	t.Run("password mismatch", func(t *testing.T) {
		registrationData := controllers.UserRegisterRequest{
			Username:        "testuser456",
			Password:        "strongPassword123!",
			ConfirmPassword: "differentPassword123!",
			Email:           "testuser456@example.com",
			AUP:             true,
			COPPA:           true,
		}

		bodyBytes, _ := json.Marshal(registrationData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/register", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)

		err := userRegisterController.UserRegister(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("missing required fields", func(t *testing.T) {
		registrationData := controllers.UserRegisterRequest{
			Username: "testuser789",
			// Missing password, email, AUP, COPPA
		}

		bodyBytes, _ := json.Marshal(registrationData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/register", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)

		err := userRegisterController.UserRegister(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("invalid email format", func(t *testing.T) {
		registrationData := controllers.UserRegisterRequest{
			Username:        "testuser101",
			Password:        "strongPassword123!",
			ConfirmPassword: "strongPassword123!",
			Email:           "invalid-email",
			AUP:             true,
			COPPA:           true,
		}

		bodyBytes, _ := json.Marshal(registrationData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/register", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)

		err := userRegisterController.UserRegister(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("weak password", func(t *testing.T) {
		registrationData := controllers.UserRegisterRequest{
			Username:        "testuser202",
			Password:        "weak",
			ConfirmPassword: "weak",
			Email:           "testuser202@example.com",
			AUP:             true,
			COPPA:           true,
		}

		bodyBytes, _ := json.Marshal(registrationData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/register", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)

		err := userRegisterController.UserRegister(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("username too long", func(t *testing.T) {
		registrationData := controllers.UserRegisterRequest{
			Username:        "verylongusernamethatexceedslimits",
			Password:        "strongPassword123!",
			ConfirmPassword: "strongPassword123!",
			Email:           "testuser303@example.com",
			AUP:             true,
			COPPA:           true,
		}

		bodyBytes, _ := json.Marshal(registrationData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/register", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)

		err := userRegisterController.UserRegister(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/register", bytes.NewReader([]byte("invalid json")))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)

		err := userRegisterController.UserRegister(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestUserRegisterController_UserActivateAccount(t *testing.T) {
	userRegisterController, e := setupUserRegisterController(t)

	e.POST("/activate", userRegisterController.UserActivateAccount)

	t.Run("missing token", func(t *testing.T) {
		activationData := controllers.UserRegisterActivateRequest{
			Token: "",
		}

		bodyBytes, _ := json.Marshal(activationData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/activate", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)

		err := userRegisterController.UserActivateAccount(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("invalid token", func(t *testing.T) {
		activationData := controllers.UserRegisterActivateRequest{
			Token: "invalid-token-12345",
		}

		bodyBytes, _ := json.Marshal(activationData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/activate", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)

		err := userRegisterController.UserActivateAccount(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("invalid JSON format", func(t *testing.T) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/activate", bytes.NewReader([]byte("invalid json")))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)

		err := userRegisterController.UserActivateAccount(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestUserRegisterController_Integration(t *testing.T) {
	userRegisterController, e := setupUserRegisterController(t)

	// Setup routes
	e.POST("/register", userRegisterController.UserRegister)
	e.POST("/activate", userRegisterController.UserActivateAccount)

	t.Run("complete registration flow", func(t *testing.T) {
		// Generate unique username to avoid conflicts
		username := "int" + helper.GenerateSecureToken(4) // "int" + 4 chars = 7 chars total
		email := username + "@example.com"

		// Step 1: Register a new user
		registrationData := controllers.UserRegisterRequest{
			Username:        username,
			Password:        "strongPassword123!",
			ConfirmPassword: "strongPassword123!",
			Email:           email,
			AUP:             true,
			COPPA:           true,
		}

		bodyBytes, _ := json.Marshal(registrationData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/register", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)

		err := userRegisterController.UserRegister(c)
		assert.NoError(t, err)

		resp := w.Result()
		if resp.StatusCode == http.StatusCreated {
			// For 201 Created, there's no response body (NoContent)
			// ContentLength might be -1 if not explicitly set, so check body content instead
			body, _ := io.ReadAll(resp.Body)
			assert.Equal(t, 0, len(body))

			// Step 2: Try to activate with an invalid token
			activationData := controllers.UserRegisterActivateRequest{
				Token: "invalid-token-" + helper.GenerateSecureToken(16),
			}

			bodyBytes2, _ := json.Marshal(activationData)
			w2 := httptest.NewRecorder()
			r2, _ := http.NewRequest("POST", "/activate", bytes.NewReader(bodyBytes2))
			r2.Header.Set("Content-Type", "application/json")

			c2 := e.NewContext(r2, w2)

			err = userRegisterController.UserActivateAccount(c2)
			assert.NoError(t, err)

			resp2 := w2.Result()
			assert.Equal(t, http.StatusNotFound, resp2.StatusCode)
		}
	})

	t.Run("duplicate registration attempt", func(t *testing.T) {
		// Try to register the same user twice (using Admin which exists)
		registrationData := controllers.UserRegisterRequest{
			Username:        "Admin", // This should already exist
			Password:        "strongPassword123!",
			ConfirmPassword: "strongPassword123!",
			Email:           "admin@example.com",
			AUP:             true,
			COPPA:           true,
		}

		bodyBytes, _ := json.Marshal(registrationData)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "/register", bytes.NewReader(bodyBytes))
		r.Header.Set("Content-Type", "application/json")

		c := e.NewContext(r, w)

		err := userRegisterController.UserRegister(c)
		assert.NoError(t, err)

		resp := w.Result()
		assert.Equal(t, http.StatusConflict, resp.StatusCode)
	})
}

func TestUserRegisterController_RegistrationValidation(t *testing.T) {
	userRegisterController, e := setupUserRegisterController(t)

	e.POST("/register", userRegisterController.UserRegister)

	tests := []struct {
		name           string
		requestData    controllers.UserRegisterRequest
		expectedStatus int
		description    string
	}{
		{
			name: "valid registration",
			requestData: controllers.UserRegisterRequest{
				Username:        "validuser123",
				Password:        "ValidPassword123!",
				ConfirmPassword: "ValidPassword123!",
				Email:           "validuser123@example.com",
				AUP:             true,
				COPPA:           true,
			},
			expectedStatus: http.StatusCreated, // Or conflict if user exists
			description:    "Should accept valid registration data",
		},
		{
			name: "username too short",
			requestData: controllers.UserRegisterRequest{
				Username:        "a",
				Password:        "ValidPassword123!",
				ConfirmPassword: "ValidPassword123!",
				Email:           "shortuser@example.com",
				AUP:             true,
				COPPA:           true,
			},
			expectedStatus: http.StatusBadRequest,
			description:    "Should reject username that's too short",
		},
		{
			name: "password too long",
			requestData: controllers.UserRegisterRequest{
				Username:        "testuser999",
				Password:        "ThisPasswordIsWayTooLongAndShouldBeRejectedByTheValidationSystemBecauseItExceedsTheMaximumAllowedLength",
				ConfirmPassword: "ThisPasswordIsWayTooLongAndShouldBeRejectedByTheValidationSystemBecauseItExceedsTheMaximumAllowedLength",
				Email:           "testuser999@example.com",
				AUP:             true,
				COPPA:           true,
			},
			expectedStatus: http.StatusBadRequest,
			description:    "Should reject password that's too long",
		},
		{
			name: "missing AUP acceptance",
			requestData: controllers.UserRegisterRequest{
				Username:        "testuser888",
				Password:        "ValidPassword123!",
				ConfirmPassword: "ValidPassword123!",
				Email:           "testuser888@example.com",
				AUP:             false,
				COPPA:           true,
			},
			expectedStatus: http.StatusBadRequest,
			description:    "Should reject if AUP is not accepted",
		},
		{
			name: "missing COPPA acknowledgment",
			requestData: controllers.UserRegisterRequest{
				Username:        "testuser777",
				Password:        "ValidPassword123!",
				ConfirmPassword: "ValidPassword123!",
				Email:           "testuser777@example.com",
				AUP:             true,
				COPPA:           false,
			},
			expectedStatus: http.StatusBadRequest,
			description:    "Should reject if COPPA is not acknowledged",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(tt.requestData)
			w := httptest.NewRecorder()
			r, _ := http.NewRequest("POST", "/register", bytes.NewReader(bodyBytes))
			r.Header.Set("Content-Type", "application/json")

			c := e.NewContext(r, w)

			err := userRegisterController.UserRegister(c)
			assert.NoError(t, err, tt.description)

			resp := w.Result()
			// For valid registration, accept either success or conflict
			if tt.expectedStatus == http.StatusCreated {
				assert.Contains(t, []int{http.StatusCreated, http.StatusConflict}, resp.StatusCode, tt.description)
			} else {
				assert.Equal(t, tt.expectedStatus, resp.StatusCode, tt.description)
			}
		})
	}
}

func (urt *userRegisterTest) getFullMessage(messageID string) (string, error) {
	url := fmt.Sprintf("%s/api/v1/message/%s", urt.getAPIEndpoint(), messageID)
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

	// Parse the full message response
	var messageData map[string]interface{}
	if err = json.Unmarshal(body, &messageData); err != nil {
		return "", fmt.Errorf("failed to unmarshal message: %w", err)
	}

	// Extract text content from the message
	if text, ok := messageData["Text"].(string); ok && text != "" {
		return text, nil
	}

	// Fallback to HTML content if text is not available
	if html, ok := messageData["HTML"].(string); ok && html != "" {
		return html, nil
	}

	return "", fmt.Errorf("no text or HTML content found in message")
}
