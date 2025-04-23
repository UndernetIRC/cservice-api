package mail

import (
	"html/template"
	"os"
	"path/filepath"
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

func TestTemplateEngine(t *testing.T) {
	// Create a temporary directory for test templates
	tempDir, err := os.MkdirTemp("", "mail_templates")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Save original config values and restore them after the test
	origTemplateDir := config.ServiceMailTemplateDir.GetString()
	origDefaultTemplate := config.ServiceMailDefaultTemplate.GetString()
	defer func() {
		config.ServiceMailTemplateDir.Set(origTemplateDir)
		config.ServiceMailDefaultTemplate.Set(origDefaultTemplate)
	}()

	// Set the temp directory as the template directory to test filesystem loading
	config.ServiceMailTemplateDir.Set(tempDir)
	config.ServiceMailDefaultTemplate.Set("test_template")

	// Create a test template
	testTemplateDir := filepath.Join(tempDir, "test_template")
	err = os.Mkdir(testTemplateDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create template directory: %v", err)
	}

	// Create HTML template
	htmlContent := `<html><body><h1>Hello {{.Name}}</h1><p>{{.Message}}</p></body></html>`
	err = os.WriteFile(filepath.Join(testTemplateDir, "html.tmpl"), []byte(htmlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create HTML template: %v", err)
	}

	// Create text template
	textContent := `Hello {{.Name}}\n\n{{.Message}}`
	err = os.WriteFile(filepath.Join(testTemplateDir, "text.tmpl"), []byte(textContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create text template: %v", err)
	}

	// Test filesystem-based template engine
	t.Run("Filesystem templates", func(t *testing.T) {
		te := &TemplateEngine{
			templateDir:  tempDir,
			templates:    make(map[string]*template.Template),
			defaultEmail: "test_template",
			useEmbedded:  false,
		}

		// Initialize the engine
		err = te.Init()
		assert.NoError(t, err, "Template engine initialization should not error")
		assert.True(t, te.initialized, "Template engine should be initialized")

		// Test rendering a template
		htmlOutput, textOutput, err := te.Render("test_template", map[string]interface{}{
			"Name":    "John",
			"Message": "Welcome to the service!",
		})
		assert.NoError(t, err, "Template rendering should not error")
		assert.Contains(t, htmlOutput, "<h1>Hello John</h1>")
		assert.Contains(t, htmlOutput, "<p>Welcome to the service!</p>")
		assert.Contains(t, textOutput, "Hello John")
		assert.Contains(t, textOutput, "Welcome to the service!")

		// Test fallback to default template when template not found
		htmlOutput, textOutput, err = te.Render("non_existent", map[string]interface{}{
			"Name":    "Jane",
			"Message": "Another welcome message!",
		})
		assert.NoError(t, err, "Should not error when falling back to default template")
		assert.Contains(t, htmlOutput, "<h1>Hello Jane</h1>")
		assert.Contains(t, htmlOutput, "<p>Another welcome message!</p>")
		assert.Contains(t, textOutput, "Hello Jane")
		assert.Contains(t, textOutput, "Another welcome message!")
	})

	// Test embedded template engine
	t.Run("Embedded templates", func(t *testing.T) {
		// Set empty directory to force embedded usage
		config.ServiceMailTemplateDir.Set("")
		config.ServiceMailDefaultTemplate.Set("default")

		te := GetTemplateEngine()
		assert.True(t, te.useEmbedded, "Template engine should use embedded templates")
		assert.True(t, te.initialized, "Template engine should be initialized")

		// Test rendering the default template from embedded FS
		htmlOutput, textOutput, err := te.Render("default", map[string]interface{}{
			"Subject": "Test Email",
			"Body":    "This is a test email body",
			"Year":    "2025",
		})
		assert.NoError(t, err, "Template rendering should not error")
		assert.Contains(t, htmlOutput, "Test Email")
		assert.Contains(t, htmlOutput, "This is a test email body")
		assert.Contains(t, textOutput, "Test Email")
		assert.Contains(t, textOutput, "This is a test email body")
	})
}

func TestEmbeddedImages(t *testing.T) {
	// Create a temporary image file
	tempFile, err := os.CreateTemp("", "test_image_*.png")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Write some dummy data to the file
	_, err = tempFile.Write([]byte("dummy image data"))
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	// Test creating embedded images
	images := []EmbeddedImage{
		{
			ContentID: "test_image",
			Path:      tempFile.Name(),
		},
		{
			ContentID: "data_image",
			Data:      []byte("test data"),
		},
	}

	// Check images are created correctly
	assert.Equal(t, "test_image", images[0].ContentID)
	assert.Equal(t, tempFile.Name(), images[0].Path)
	assert.Equal(t, "data_image", images[1].ContentID)
	assert.Equal(t, []byte("test data"), images[1].Data)
}
