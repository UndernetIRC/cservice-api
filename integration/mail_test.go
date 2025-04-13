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

	apiEndpoint := fmt.Sprintf("http://%s:%s", mt.host, mt.apiPort)
	t.Logf("Using API endpoint: %s", apiEndpoint)

	// Initialize mail queue
	mail.MailQueue = make(chan mail.Mail, 10)
	mailErr := make(chan error, 10)

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
				To:      "user@example.com",
				Subject: "Test Email",
				Body:    "This is a test email",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear messages before each test
			err := clearMailHogMessages(apiEndpoint)
			assert.NoError(t, err, "Failed to clear MailHog messages")

			// Ensure messages are cleared before proceeding
			time.Sleep(time.Second)

			// Send email
			err = tt.mail.Send()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			// Wait for email processing
			time.Sleep(time.Second * 2)

			// Check MailHog for the message
			messages, err := getMailHogMessages(apiEndpoint)
			assert.NoError(t, err, "Failed to get MailHog messages")

			// Verify message count
			if !assert.Equal(t, 1, len(messages), "Expected exactly one message") {
				t.Logf("Unexpected message count. Messages in mailbox: %d", len(messages))
				return
			}

			if len(messages) > 0 {
				msg := messages[0]
				assert.Contains(t, msg.Raw.To[0], tt.mail.To, "Recipient email doesn't match")
				assert.Contains(t, msg.Content.Body, tt.mail.Body, "Email body doesn't match")

				// Additional logging for debugging
				t.Logf("Received message - To: %v, From: %s, Body: %s",
					msg.Raw.To, msg.Raw.From, msg.Content.Body)
			}

			// Check for any worker errors
			select {
			case err := <-mailErr:
				t.Errorf("Unexpected mail worker error: %v", err)
			default:
				// No errors - good!
			}
		})
	}

	// Clean up
	close(mail.MailQueue)
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
