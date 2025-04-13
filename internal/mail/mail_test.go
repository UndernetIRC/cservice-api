package mail

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/undernetirc/cservice-api/internal/config"
)

func TestMailSend_DisabledService(t *testing.T) {
	// Save the original value
	originalValue := config.ServiceMailEnabled.GetBool()
	// Restore the original value after the test
	defer config.ServiceMailEnabled.Set(originalValue)

	// Disable mail service
	config.ServiceMailEnabled.Set(false)

	m := &Mail{
		FromName:  "Test",
		FromEmail: "test@example.com",
		To:        "recipient@example.com",
		Subject:   "Test Subject",
		Body:      "Test Body",
	}

	// Test that Send() returns nil when mail service is disabled
	err := m.Send()
	assert.NoError(t, err, "Send should return nil when mail service is disabled")

	// Enable mail service but keep queue uninitialized
	config.ServiceMailEnabled.Set(true)
	MailQueue = nil

	// Test that Send() returns error when queue is not initialized
	err = m.Send()
	assert.Error(t, err, "Send should return error when mail queue is not initialized")
	assert.Contains(t, err.Error(), "mail queue is not initialized")
}
