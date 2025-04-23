// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2025 UnderNET

// Package mail provides a mail service
package mail

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/wneessen/go-mail"
)

var (
	MailQueue            chan Mail
	GlobalTemplateEngine *TemplateEngine
	templateEngineOnce   sync.Once
)

// TemplateEngine handles email template rendering
type TemplateEngine struct {
	templateDir  string
	templates    map[string]*template.Template
	templatesMu  sync.RWMutex
	initialized  bool
	defaultEmail string
	useEmbedded  bool
}

// GetTemplateEngine returns the global template engine instance
func GetTemplateEngine() *TemplateEngine {
	templateEngineOnce.Do(func() {
		templateDir := config.ServiceMailTemplateDir.GetString()
		useEmbedded := templateDir == ""

		GlobalTemplateEngine = &TemplateEngine{
			templateDir:  templateDir,
			templates:    make(map[string]*template.Template),
			defaultEmail: config.ServiceMailDefaultTemplate.GetString(),
			useEmbedded:  useEmbedded,
		}
		if err := GlobalTemplateEngine.Init(); err != nil {
			log.Printf("Failed to initialize template engine: %v", err)
		}
	})
	return GlobalTemplateEngine
}

// Init initializes the template engine by loading all templates
func (te *TemplateEngine) Init() error {
	if te.initialized {
		return nil
	}

	if te.useEmbedded {
		return te.initFromEmbedded()
	}

	return te.initFromFS()
}

// initFromEmbedded loads templates from the embedded filesystem
func (te *TemplateEngine) initFromEmbedded() error {
	entries, err := fs.ReadDir(templatesFS, "templates")
	if err != nil {
		return fmt.Errorf("failed to read embedded template directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "assets" {
			continue
		}

		templateName := entry.Name()
		htmlPath := fmt.Sprintf("templates/%s/html.tmpl", templateName)
		textPath := fmt.Sprintf("templates/%s/text.tmpl", templateName)

		// Check if both HTML and text templates exist
		htmlData, err := templatesFS.ReadFile(htmlPath)
		if err != nil {
			log.Printf("HTML template does not exist for %s, skipping: %v", templateName, err)
			continue
		}

		textData, err := templatesFS.ReadFile(textPath)
		if err != nil {
			log.Printf("Text template does not exist for %s, skipping: %v", templateName, err)
			continue
		}

		// Create and parse both templates
		tmpl := template.New(templateName)

		// Parse HTML template
		_, err = tmpl.New("html.tmpl").Parse(string(htmlData))
		if err != nil {
			log.Printf("Failed to parse HTML template for %s: %v", templateName, err)
			continue
		}

		// Parse text template
		_, err = tmpl.New("text.tmpl").Parse(string(textData))
		if err != nil {
			log.Printf("Failed to parse text template for %s: %v", templateName, err)
			continue
		}

		te.templatesMu.Lock()
		te.templates[templateName] = tmpl
		te.templatesMu.Unlock()

		log.Printf("Loaded embedded template: %s", templateName)
	}

	te.initialized = true
	return nil
}

// initFromFS loads templates from the filesystem
func (te *TemplateEngine) initFromFS() error {
	if _, err := os.Stat(te.templateDir); os.IsNotExist(err) {
		return fmt.Errorf("template directory does not exist: %s", te.templateDir)
	}

	// Load all template directories
	entries, err := os.ReadDir(te.templateDir)
	if err != nil {
		return fmt.Errorf("failed to read template directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "assets" {
			continue
		}

		templateName := entry.Name()
		htmlPath := filepath.Join(te.templateDir, templateName, "html.tmpl")
		textPath := filepath.Join(te.templateDir, templateName, "text.tmpl")

		// Check if both HTML and text templates exist
		if _, err := os.Stat(htmlPath); os.IsNotExist(err) {
			log.Printf("HTML template does not exist for %s, skipping", templateName)
			continue
		}
		if _, err := os.Stat(textPath); os.IsNotExist(err) {
			log.Printf("Text template does not exist for %s, skipping", templateName)
			continue
		}

		// Parse both templates
		tmpl, err := template.New(templateName).ParseFiles(htmlPath, textPath)
		if err != nil {
			log.Printf("Failed to parse templates for %s: %v", templateName, err)
			continue
		}

		te.templatesMu.Lock()
		te.templates[templateName] = tmpl
		te.templatesMu.Unlock()

		log.Printf("Loaded filesystem template: %s", templateName)
	}

	te.initialized = true
	return nil
}

// Render renders a template with the given data
func (te *TemplateEngine) Render(templateName string, data interface{}) (string, string, error) {
	te.templatesMu.RLock()
	tmpl, ok := te.templates[templateName]
	te.templatesMu.RUnlock()

	if !ok {
		if templateName != te.defaultEmail {
			log.Printf("Template %s not found, falling back to default", templateName)
			return te.Render(te.defaultEmail, data)
		}
		return "", "", fmt.Errorf("template not found: %s", templateName)
	}

	var htmlBuf, textBuf bytes.Buffer

	// Render HTML template
	if err := tmpl.ExecuteTemplate(&htmlBuf, "html.tmpl", data); err != nil {
		return "", "", fmt.Errorf("failed to render HTML template: %w", err)
	}

	// Render text template
	if err := tmpl.ExecuteTemplate(&textBuf, "text.tmpl", data); err != nil {
		return "", "", fmt.Errorf("failed to render text template: %w", err)
	}

	return htmlBuf.String(), textBuf.String(), nil
}

// EmbeddedImage represents an image to be embedded in an email
type EmbeddedImage struct {
	ContentID string // ContentID to be referenced in HTML, e.g., <img src="cid:image1">
	Path      string // Path to the image file
	Data      []byte // Raw image data (optional, used if Path is empty)
}

// Mail is a struct that holds the data for a mail
type Mail struct {
	FromName     string
	FromEmail    string
	To           string
	Subject      string
	Body         string          // Plain text body (used only if Template is empty)
	HTMLBody     string          // HTML body (used only if Template is empty)
	Template     string          // Template name to use
	TemplateData interface{}     // Data to pass to the template
	Attachments  []string        // Paths to files to attach
	Images       []EmbeddedImage // Images to embed in the email
	MetaData     interface{}     // Additional metadata
}

func NewMail(to string, subject string, template string, templateData interface{}) *Mail {
	// Find logo path for embedding in email
	var logoData []byte
	var logoFilename string

	// Check if we have a external template directory configured
	if externalDir := config.ServiceMailTemplateDir.GetString(); externalDir != "" {
		// Use filesystem logo if available
		logoPath := filepath.Join(externalDir, "assets", "logo.png")
		if _, err := os.Stat(logoPath); err == nil {
			logoFilename = logoPath
		}
	} else {
		// Try to load logo from embedded filesystem
		var err error
		logoData, err = templatesFS.ReadFile("templates/assets/logo.png")
		if err != nil {
			// Logo not found in embedded FS, continue without logo
			log.Printf("Logo not found in embedded filesystem: %v", err)
		}
	}

	// Create embedded images list
	images := []EmbeddedImage{}

	// Add logo if available
	if logoFilename != "" {
		images = append(images, EmbeddedImage{
			ContentID: "logo",
			Path:      logoFilename,
		})
	} else if len(logoData) > 0 {
		images = append(images, EmbeddedImage{
			ContentID: "logo",
			Data:      logoData,
		})
	}

	return &Mail{
		FromName:     config.SMTPFromName.GetString(),
		FromEmail:    config.SMTPFromEmail.GetString(),
		To:           to,
		Subject:      subject,
		Template:     template,
		TemplateData: templateData,
		Attachments:  make([]string, 0),
		Images:       images,
	}
}

// AttachFile adds a file to the email attachments
func (m *Mail) AttachFile(filepath string) error {
	// Check if file exists and is readable
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		return fmt.Errorf("attachment file does not exist: %s", filepath)
	}

	m.Attachments = append(m.Attachments, filepath)
	return nil
}

// Send queues a mail for sending
func (m *Mail) Send() error {
	// Silently succeed if mail service is disabled
	if !config.ServiceMailEnabled.GetBool() {
		return nil
	}

	if MailQueue == nil {
		return fmt.Errorf("mail queue is not initialized")
	}
	MailQueue <- *m
	return nil
}

// ProcessMail handles the actual sending of an email
func ProcessMail(mailData Mail) error {
	var rn int32
	err := binary.Read(rand.Reader, binary.LittleEndian, &rn)
	if err != nil {
		return fmt.Errorf("failed to generate random number: %w", err)
	}

	m := mail.NewMsg()

	// Use configured or default from email/name
	fromEmail := mailData.FromEmail
	if fromEmail == "" {
		fromEmail = config.SMTPFromEmail.GetString()
	}
	fromName := mailData.FromName
	if fromName == "" {
		fromName = config.SMTPFromName.GetString()
	}

	if err := m.EnvelopeFrom(fmt.Sprintf("noreply+%d@cservice.undernet.org", rn)); err != nil {
		return fmt.Errorf("failed to set envelope from: %s", err)
	}
	if err := m.FromFormat(fromName, fromEmail); err != nil {
		return fmt.Errorf("failed to set from: %s", err)
	}
	if err := m.AddTo(mailData.To); err != nil {
		return fmt.Errorf("failed to set to: %s", err)
	}

	m.SetMessageID()
	m.SetDate()
	m.SetBulk()
	m.Subject(mailData.Subject)

	// Process template if specified
	if mailData.Template != "" {
		te := GetTemplateEngine()
		if !te.initialized {
			if err := te.Init(); err != nil {
				return fmt.Errorf("failed to initialize template engine: %w", err)
			}
		}

		htmlBody, textBody, err := te.Render(mailData.Template, mailData.TemplateData)
		if err != nil {
			return fmt.Errorf("failed to render template: %w", err)
		}

		// Set both HTML and plain text bodies
		m.SetBodyString(mail.TypeTextHTML, htmlBody)
		m.AddAlternativeString(mail.TypeTextPlain, textBody)
	} else if mailData.HTMLBody != "" {
		// Use provided HTML and plain text bodies
		m.SetBodyString(mail.TypeTextHTML, mailData.HTMLBody)
		if mailData.Body != "" {
			m.AddAlternativeString(mail.TypeTextPlain, mailData.Body)
		}
	} else {
		// Fall back to plain text only
		m.SetBodyString(mail.TypeTextPlain, mailData.Body)
	}

	// Embed images
	for _, img := range mailData.Images {
		var err error
		if img.Data != nil {
			err = m.EmbedReader(img.ContentID, bytes.NewReader(img.Data), mail.WithFileName(img.ContentID))
		} else if img.Path != "" {
			imgFile, err := os.Open(img.Path)
			if err != nil {
				log.Printf("Failed to open image %s: %v", img.Path, err)
				continue
			}
			defer imgFile.Close()

			imgData, err := io.ReadAll(imgFile)
			if err != nil {
				log.Printf("Failed to read image %s: %v", img.Path, err)
				continue
			}

			err = m.EmbedReader(img.ContentID, bytes.NewReader(imgData), mail.WithFileName(filepath.Base(img.Path)))
			if err != nil {
				log.Printf("Failed to embed image %s: %v", img.Path, err)
			}
		}

		if err != nil {
			log.Printf("Failed to embed image %s: %v", img.ContentID, err)
		}
	}

	// Add attachments
	for _, attachment := range mailData.Attachments {
		m.AttachFile(attachment)
		log.Printf("Attached file: %s", attachment)
	}

	// Configure client based on settings
	port := config.SMTPPort.GetUint()
	if port > uint(^uint16(0)) {
		return fmt.Errorf("SMTP port %d exceeds maximum allowed value %d", port, ^uint16(0))
	}

	opts := []mail.Option{
		mail.WithPort(int(port)),
	}

	if !config.SMTPUseTLS.GetBool() {
		opts = append(opts, mail.WithTLSPortPolicy(mail.NoTLS))
	}

	// Add authentication if credentials are provided
	if config.SMTPUsername.GetString() != "" {
		opts = append(opts, mail.WithUsername(config.SMTPUsername.GetString()))
		opts = append(opts, mail.WithPassword(config.SMTPPassword.GetString()))
	}

	c, err := mail.NewClient(config.SMTPHost.GetString(), opts...)
	if err != nil {
		return fmt.Errorf("failed to create client: %s", err)
	}

	if err := c.DialAndSend(m); err != nil {
		return fmt.Errorf("failed to send mail: %s", err)
	}
	log.Printf("mail sent to %s", mailData.To)

	return nil
}

// Worker processes emails from the mail queue
// nolint:revive // Keeping original name for backward compatibility
func MailWorker(mailQueue chan Mail, mailErr chan error, worker int) {
	done := make(chan bool, worker)

	for x := 0; x < worker; x++ {
		go func() {
			defer func() {
				done <- true
			}()

			for m := range mailQueue {
				err := ProcessMail(m)
				if err != nil {
					mailErr <- err
				}
			}
		}()
	}

	for x := 0; x < worker; x++ {
		<-done
	}
}
