// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

package helper

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/yeqown/go-qrcode/v2"
	"github.com/yeqown/go-qrcode/writer/standard"
)

// GenerateTOTPQRCode generates a QR code for TOTP setup with the UnderNET logo
func GenerateTOTPQRCode(username, secret string) (string, error) {
	// Build the TOTP URL according to RFC 6238
	u := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   fmt.Sprintf("/UnderNET CService:%s", username),
	}

	q := u.Query()
	q.Set("secret", secret)
	q.Set("issuer", "UnderNET CService")
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	u.RawQuery = q.Encode()

	// Create QR code
	qrc, err := qrcode.New(u.String())
	if err != nil {
		return "", fmt.Errorf("failed to create QR code: %w", err)
	}

	// Create a temporary file for the QR code
	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("qrcode_%d.png", time.Now().UnixNano()))
	defer os.Remove(tempFile) // Clean up

	// Create writer with logo
	w, err := standard.New(tempFile,
		standard.WithLogoImageFilePNG("internal/mail/templates/assets/logo.png"),
		standard.WithBorderWidth(10),
		standard.WithQRWidth(21), // Standard width for better logo visibility
	)
	if err != nil {
		return "", fmt.Errorf("failed to create QR writer: %w", err)
	}

	// Generate the QR code
	if err = qrc.Save(w); err != nil {
		return "", fmt.Errorf("failed to save QR code: %w", err)
	}

	// Read the file back
	data, err := os.ReadFile(tempFile)
	if err != nil {
		return "", fmt.Errorf("failed to read QR code file: %w", err)
	}

	// Convert to base64
	encoded := base64.StdEncoding.EncodeToString(data)
	return encoded, nil
}
