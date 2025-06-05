//go:build integration

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/mail"
)

type mailTest struct {
	container testcontainers.Container
	host      string
	smtpPort  string
	apiPort   string
}

// MailpitResponse represents Mailpit's API response structure
type MailpitResponse struct {
	Total          int              `json:"total"`
	Unread         int              `json:"unread"`
	Count          int              `json:"count"`
	MessagesCount  int              `json:"messages_count"`
	MessagesUnread int              `json:"messages_unread"`
	Start          int              `json:"start"`
	Tags           []string         `json:"tags"`
	Messages       []MailpitMessage `json:"messages"`
}

// MailpitMessage represents the structure of a message in Mailpit's API
type MailpitMessage struct {
	ID        string `json:"ID"`
	MessageID string `json:"MessageID"`
	Read      bool   `json:"Read"`
	From      struct {
		Name    string `json:"Name"`
		Address string `json:"Address"`
	} `json:"From"`
	To []struct {
		Name    string `json:"Name"`
		Address string `json:"Address"`
	} `json:"To"`
	Cc          []interface{} `json:"Cc"`
	Bcc         []interface{} `json:"Bcc"`
	ReplyTo     []interface{} `json:"ReplyTo"`
	Subject     string        `json:"Subject"`
	Created     string        `json:"Created"`
	Tags        []string      `json:"Tags"`
	Size        int           `json:"Size"`
	Attachments int           `json:"Attachments"`
	Snippet     string        `json:"Snippet"`
}

func setupMailpit(t *testing.T) *mailTest {
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

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start mailpit container: %s", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("failed to get container host: %s", err)
	}

	smtpPort, err := container.MappedPort(ctx, "1025/tcp")
	if err != nil {
		t.Fatalf("failed to get smtp port: %s", err)
	}

	apiPort, err := container.MappedPort(ctx, "8025/tcp")
	if err != nil {
		t.Fatalf("failed to get api port: %s", err)
	}

	t.Logf("Container host: %s", host)
	t.Logf("SMTP port: %s", smtpPort.Port())
	t.Logf("API endpoint: http://%s:%s", host, apiPort.Port())

	// For integration tests, we'll use the embedded templates
	// Clear any existing template directory setting to ensure embedded templates are used
	config.ServiceMailTemplateDir.Set("")
	config.ServiceMailDefaultTemplate.Set("default")

	// Initialize the template engine with embedded templates
	templateEngine := mail.GetTemplateEngine()
	if err := templateEngine.Init(); err != nil {
		t.Fatalf("Failed to initialize template engine: %v", err)
	}

	return &mailTest{
		container: container,
		host:      host,
		smtpPort:  smtpPort.Port(),
		apiPort:   apiPort.Port(),
	}
}

func clearMailpitMessages(apiEndpoint string) error {
	// Use v1 API compatible with MailHog
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

	// Read and log the response body for debugging
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}
	return nil
}

func getMailpitMessages(apiEndpoint string) ([]MailpitMessage, error) {
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

func TestMailIntegration(t *testing.T) {
	mt := setupMailpit(t)
	defer func() {
		if err := mt.container.Terminate(context.Background()); err != nil {
			t.Logf("failed to terminate container: %s", err)
		}
	}()

	// Convert port string to uint
	smtpPort, err := nat.ParsePort(mt.smtpPort)
	if err != nil {
		t.Fatalf("failed to parse SMTP port: %s", err)
	}

	// Configure mail settings
	config.SMTPHost.Set(mt.host)
	config.SMTPPort.Set(uint(smtpPort))
	config.SMTPUseTLS.Set(false)
	config.SMTPFromEmail.Set("test@cservice.undernet.org")
	config.SMTPFromName.Set("CService Test")
	config.ServiceMailEnabled.Set(true)

	apiEndpoint := fmt.Sprintf("http://%s:%s", mt.host, mt.apiPort)
	t.Logf("Using API endpoint: %s", apiEndpoint)

	// Create context for cancellation
	testCtx, cancel := context.WithCancel(context.Background())

	// Initialize mail queue
	mailQueue := make(chan mail.Mail, 10)
	mailErr := make(chan error, 10)
	mail.MailQueue = mailQueue

	// Set up cleanup after variables are defined
	defer func() {
		cancel()
		// Close channels to signal shutdown
		close(mailQueue)
		// Give time for goroutines to finish
		time.Sleep(100 * time.Millisecond)
	}()

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

	// Start mail worker
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

	// Test cases
	tests := []struct {
		name     string
		mail     mail.Mail
		wantErr  bool
		expected struct {
			subject      string
			to           string
			from         string
			bodyContains string
		}
	}{
		{
			name: "Basic email",
			mail: mail.Mail{
				FromName:  "Test Sender",
				FromEmail: "sender@test.com",
				To:        "recipient@test.com",
				Subject:   "Test Subject",
				Body:      "Test Body",
			},
			wantErr: false,
			expected: struct {
				subject      string
				to           string
				from         string
				bodyContains string
			}{
				subject:      "Test Subject",
				to:           "recipient@test.com",
				from:         "sender@test.com",
				bodyContains: "Test Body",
			},
		},
		{
			name: "Custom from",
			mail: mail.Mail{
				FromName:  "Custom Sender",
				FromEmail: "custom@cservice.undernet.org",
				To:        "another@example.com",
				Subject:   "Custom From Test",
				Body:      "Email with custom from address",
			},
			wantErr: false,
			expected: struct {
				subject      string
				to           string
				from         string
				bodyContains string
			}{
				subject:      "Custom From Test",
				to:           "another@example.com",
				from:         "custom@cservice.undernet.org",
				bodyContains: "Email with custom from address",
			},
		},
		{
			name: "HTML email",
			mail: mail.Mail{
				FromName:  "HTML Sender",
				FromEmail: "html@cservice.undernet.org",
				To:        "html-recipient@example.com",
				Subject:   "HTML Email Test",
				Body:      "Plain text version",
				HTMLBody:  "<html><body><h1>HTML Email</h1><p>This is an HTML email test.</p></body></html>",
			},
			wantErr: false,
			expected: struct {
				subject      string
				to           string
				from         string
				bodyContains string
			}{
				subject:      "HTML Email Test",
				to:           "html-recipient@example.com",
				from:         "html@cservice.undernet.org",
				bodyContains: "HTML Email",
			},
		},
		{
			name: "Template-based email",
			mail: mail.Mail{
				FromName:  "Template Sender",
				FromEmail: "template@cservice.undernet.org",
				To:        "template-recipient@example.com",
				Subject:   "Template Email Test",
				// Use default template which will be created in setup
				Template: "default",
				TemplateData: map[string]interface{}{
					"Body": "This is a templated email content.",
					"Year": 2024,
				},
			},
			wantErr: false,
			expected: struct {
				subject      string
				to           string
				from         string
				bodyContains string
			}{
				subject:      "Template Email Test",
				to:           "template-recipient@example.com",
				from:         "template@cservice.undernet.org",
				bodyContains: "This is a templated email content.",
			},
		},
		{
			name: "Disabled mail service",
			mail: mail.Mail{
				FromName:  "Test Sender",
				FromEmail: "sender@test.com",
				To:        "recipient@test.com",
				Subject:   "Test Subject",
				Body:      "Test Body",
			},
			wantErr: false,
			expected: struct {
				subject      string
				to           string
				from         string
				bodyContains string
			}{
				subject:      "Test Subject",
				to:           "recipient@test.com",
				from:         "sender@test.com",
				bodyContains: "Test Body",
			},
		},
	}

	// Add a separate test for disabled mail service
	t.Run("Disabled mail service", func(t *testing.T) {
		// Save original state
		originalEnabled := config.ServiceMailEnabled.GetBool()
		defer config.ServiceMailEnabled.Set(originalEnabled)

		// Disable mail service
		config.ServiceMailEnabled.Set(false)

		// Clear existing messages
		err := clearMailpitMessages(apiEndpoint)
		assert.NoError(t, err)

		// Try to send mail while disabled
		m := mail.Mail{
			FromName:  "Test Sender",
			FromEmail: "sender@test.com",
			To:        "recipient@test.com",
			Subject:   "Test Subject",
			Body:      "Test Body",
		}
		err = m.Send()
		assert.NoError(t, err, "Send should succeed when mail service is disabled")

		// Verify no messages were sent
		messages, err := getMailpitMessages(apiEndpoint)
		assert.NoError(t, err)
		assert.Len(t, messages, 0, "No messages should be sent when mail service is disabled")
	})

	// Run the original test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear existing messages before each test
			err := clearMailpitMessages(apiEndpoint)
			assert.NoError(t, err)

			// Send the test email
			t.Logf("Sending test email to %s for test case %s", tt.mail.To, tt.name)
			err = tt.mail.Send()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			t.Logf("Mail sent successfully for test case %s", tt.name)

			// Wait for message to be processed - give more time
			t.Logf("Waiting for message to be processed for test case %s", tt.name)
			time.Sleep(2 * time.Second)

			// Get messages from Mailpit
			messages, err := getMailpitMessages(apiEndpoint)
			assert.NoError(t, err)

			// Debug output
			t.Logf("Retrieved %d messages for test case %s", len(messages), tt.name)

			// If no messages were found but expected, log and fail
			if len(messages) == 0 {
				t.Errorf("No messages found in Mailpit for test case %s, but expected one", tt.name)
				// Skip rest of the verification to avoid panic
				return
			}

			assert.Len(t, messages, 1)

			// Verify message content
			message := messages[0]

			// Check basic message properties
			assert.Equal(t, tt.expected.subject, message.Subject, "Subject mismatch for test case: %s", tt.name)
			assert.Equal(t, tt.expected.to, message.To[0].Address, "To address mismatch for test case: %s", tt.name)
			assert.Equal(t, tt.expected.from, message.From.Address, "From address mismatch for test case: %s", tt.name)

			// For content verification, we'd need to get the full message
			// For now, we'll check that the snippet contains some expected content
			if tt.expected.bodyContains != "" {
				assert.Contains(t, message.Snippet, tt.expected.bodyContains, "Body content mismatch for test case: %s", tt.name)
			}
		})
	}
}

func TestMailQueueNotInitialized(t *testing.T) {
	// Ensure MailQueue is nil
	mail.MailQueue = nil

	testMail := mail.Mail{
		To:      "test@example.com",
		Subject: "Test Email",
		Body:    "This is a test email",
	}

	err := testMail.Send()
	assert.Error(t, err)
	assert.Equal(t, "mail queue is not initialized", err.Error())
}
