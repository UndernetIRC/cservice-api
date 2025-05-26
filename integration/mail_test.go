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

// MailHogMessage represents the structure of a message in MailHog's API
type MailHogMessage struct {
	ID   string `json:"ID"`
	From struct {
		Relays  []string `json:"Relays"`
		Mailbox string   `json:"Mailbox"`
		Domain  string   `json:"Domain"`
		Params  string   `json:"Params"`
	} `json:"From"`
	To []struct {
		Relays  []string `json:"Relays"`
		Mailbox string   `json:"Mailbox"`
		Domain  string   `json:"Domain"`
		Params  string   `json:"Params"`
	} `json:"To"`
	Content struct {
		Headers map[string][]string `json:"Headers"`
		Body    string              `json:"Body"`
		Size    int                 `json:"Size"`
		MIME    string              `json:"MIME"`
	} `json:"Content"`
	Created time.Time `json:"Created"`
	Raw     struct {
		From string   `json:"From"`
		To   []string `json:"To"`
	} `json:"Raw"`
}

func setupMailHog(t *testing.T) *mailTest {
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "mailhog/mailhog:latest",
		ExposedPorts: []string{"1025/tcp", "8025/tcp"},
		WaitingFor: wait.ForAll(
			wait.ForLog("Creating API v1 with WebPath:"),
			wait.ForListeningPort("1025/tcp"),
			wait.ForListeningPort("8025/tcp"),
		),
		Env: map[string]string{
			"MH_API_BIND_ADDR":    "0.0.0.0:8025",
			"MH_UI_BIND_ADDR":     "0.0.0.0:8025",
			"MH_SMTP_BIND_ADDR":   "0.0.0.0:1025",
			"MH_STORAGE":          "memory",
			"MH_CORS_ORIGIN":      "*",
			"MH_API_READ_TIMEOUT": "10s",
		},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start mailhog container: %s", err)
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

func clearMailHogMessages(apiEndpoint string) error {
	// Fix: Use v1 API instead of v2
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

func getMailHogMessages(apiEndpoint string) ([]MailHogMessage, error) {
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

	var messages []MailHogMessage
	if err = json.Unmarshal(body, &messages); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return messages, nil
}

func TestMailIntegration(t *testing.T) {
	mt := setupMailHog(t)
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

	// Initialize mail queue
	mail.MailQueue = make(chan mail.Mail, 10)
	mailErr := make(chan error, 10)

	// Start error handler goroutine to log mail errors in tests
	go func() {
		for err := range mailErr {
			t.Logf("Mail processing error: %v", err)
		}
	}()

	// Start mail worker
	go mail.MailWorker(mail.MailQueue, mailErr, 2)

	// Test cases
	tests := []struct {
		name    string
		mail    mail.Mail
		wantErr bool
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
		err := clearMailHogMessages(apiEndpoint)
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
		messages, err := getMailHogMessages(apiEndpoint)
		assert.NoError(t, err)
		assert.Len(t, messages, 0, "No messages should be sent when mail service is disabled")
	})

	// Run the original test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear existing messages before each test
			err := clearMailHogMessages(apiEndpoint)
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

			// Get messages from MailHog
			messages, err := getMailHogMessages(apiEndpoint)
			assert.NoError(t, err)

			// Debug output
			t.Logf("Retrieved %d messages for test case %s", len(messages), tt.name)

			// If no messages were found but expected, log and fail
			if len(messages) == 0 {
				t.Errorf("No messages found in MailHog for test case %s, but expected one", tt.name)
				// Skip rest of the verification to avoid panic
				return
			}

			assert.Len(t, messages, 1)

			// Verify message content
			msg := messages[0]
			assert.Equal(t, fmt.Sprintf("<%s>", tt.mail.To), msg.Content.Headers["To"][0])
			assert.Equal(t, tt.mail.Subject, msg.Content.Headers["Subject"][0])

			// Different verification based on email type
			if tt.name == "HTML email" || tt.name == "Template-based email" {
				// For HTML or template emails, just check that the content contains expected text
				if tt.name == "HTML email" {
					assert.Contains(t, msg.Content.Body, "Plain text version")
					assert.Contains(t, msg.Content.Body, "HTML Email")
					assert.Contains(t, msg.Content.Body, "This is an HTML email test.")
				} else if tt.name == "Template-based email" {
					assert.Contains(t, msg.Content.Body, "This is a templated email content.")
					assert.Contains(t, msg.Content.Body, "UnderNET. All rights reserved.")
				}

				// Verify that Content-Type headers exist for multipart emails
				assert.Contains(t, msg.Content.Headers["Content-Type"][0], "multipart/alternative")
			} else {
				// For plain text emails, directly compare body
				assert.Equal(t, tt.mail.Body, msg.Content.Body)
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
