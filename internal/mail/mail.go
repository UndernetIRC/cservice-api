// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2025 UnderNET

// Package mail provides a mail service
package mail

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/wneessen/go-mail"
)

var MailQueue chan Mail

// Mail is a struct that holds the data for a mail
type Mail struct {
	FromName  string
	FromEmail string
	To        string
	Subject   string
	Body      string
	MetaData  interface{}
}

// Send queues a mail for sending
func (m *Mail) Send() error {
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
	m.SetBodyString("text/plain", mailData.Body)

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
