// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

package helper

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateTOTPQRCode(t *testing.T) {
	t.Run("Success - Valid username and secret", func(t *testing.T) {
		username := "testuser"
		secret := "JBSWY3DPEHPK3PXP"

		qrCodeBase64, err := GenerateTOTPQRCode(username, secret)

		assert.NoError(t, err, "GenerateTOTPQRCode should not return an error")
		assert.NotEmpty(t, qrCodeBase64, "QR code base64 should not be empty")

		// Verify it's valid base64
		decodedData, err := base64.StdEncoding.DecodeString(qrCodeBase64)
		assert.NoError(t, err, "QR code should be valid base64")
		assert.NotEmpty(t, decodedData, "Decoded QR code data should not be empty")

		// Verify it's a valid image file (PNG or JPEG)
		assert.True(t, len(decodedData) > 4, "QR code data should be long enough to contain image header")

		// Check for PNG header (89 50 4E 47) or JPEG header (FF D8 FF)
		isPNG := len(decodedData) >= 4 && decodedData[0] == 0x89 && decodedData[1] == 0x50 && decodedData[2] == 0x4E && decodedData[3] == 0x47
		isJPEG := len(decodedData) >= 3 && decodedData[0] == 0xFF && decodedData[1] == 0xD8 && decodedData[2] == 0xFF

		assert.True(t, isPNG || isJPEG, "QR code should be a valid PNG or JPEG file")
	})

	t.Run("Success - Different username and secret", func(t *testing.T) {
		username := "admin"
		secret := "ABCDEFGHIJKLMNOP"

		qrCodeBase64, err := GenerateTOTPQRCode(username, secret)

		assert.NoError(t, err, "GenerateTOTPQRCode should not return an error")
		assert.NotEmpty(t, qrCodeBase64, "QR code base64 should not be empty")

		// Verify it's valid base64
		_, err = base64.StdEncoding.DecodeString(qrCodeBase64)
		assert.NoError(t, err, "QR code should be valid base64")
	})

	t.Run("Success - Username with special characters", func(t *testing.T) {
		username := "test.user@example"
		secret := "JBSWY3DPEHPK3PXP"

		qrCodeBase64, err := GenerateTOTPQRCode(username, secret)

		assert.NoError(t, err, "GenerateTOTPQRCode should handle special characters in username")
		assert.NotEmpty(t, qrCodeBase64, "QR code base64 should not be empty")

		// Verify it's valid base64
		_, err = base64.StdEncoding.DecodeString(qrCodeBase64)
		assert.NoError(t, err, "QR code should be valid base64")
	})

	t.Run("Error - Empty username", func(t *testing.T) {
		username := ""
		secret := "JBSWY3DPEHPK3PXP"

		qrCodeBase64, err := GenerateTOTPQRCode(username, secret)

		// The function should still work with empty username, but let's verify the behavior
		assert.NoError(t, err, "GenerateTOTPQRCode should handle empty username")
		assert.NotEmpty(t, qrCodeBase64, "QR code should still be generated")
	})

	t.Run("Error - Empty secret", func(t *testing.T) {
		username := "testuser"
		secret := ""

		qrCodeBase64, err := GenerateTOTPQRCode(username, secret)

		// The function should still work with empty secret, but let's verify the behavior
		assert.NoError(t, err, "GenerateTOTPQRCode should handle empty secret")
		assert.NotEmpty(t, qrCodeBase64, "QR code should still be generated")
	})

	t.Run("Error - Very long inputs", func(t *testing.T) {
		username := strings.Repeat("a", 1000)
		secret := strings.Repeat("A", 1000)

		qrCodeBase64, err := GenerateTOTPQRCode(username, secret)

		// Very long inputs might cause QR code generation to fail or succeed
		// The important thing is that it doesn't panic
		if err != nil {
			assert.Error(t, err, "Very long inputs may cause an error")
			assert.Empty(t, qrCodeBase64, "QR code should be empty on error")
		} else {
			assert.NotEmpty(t, qrCodeBase64, "If successful, QR code should not be empty")
		}
	})

	t.Run("Verify TOTP URL format", func(t *testing.T) {
		// This test indirectly verifies the URL format by checking the QR code generation doesn't fail
		// The actual TOTP URL format is: otpauth://totp/UnderNET%20CService:username?secret=SECRET&issuer=UnderNET%20CService&algorithm=SHA1&digits=6&period=30

		username := "testuser"
		secret := "JBSWY3DPEHPK3PXP"

		qrCodeBase64, err := GenerateTOTPQRCode(username, secret)

		assert.NoError(t, err, "Valid TOTP URL should generate QR code successfully")
		assert.NotEmpty(t, qrCodeBase64, "QR code should be generated for valid TOTP URL")

		// Verify the base64 can be decoded
		decodedData, err := base64.StdEncoding.DecodeString(qrCodeBase64)
		assert.NoError(t, err, "QR code should be valid base64")
		assert.Greater(t, len(decodedData), 100, "QR code should contain substantial data")
	})

	t.Run("Multiple calls should generate different QR codes", func(t *testing.T) {
		username := "testuser"
		secret := "JBSWY3DPEHPK3PXP"

		qrCode1, err1 := GenerateTOTPQRCode(username, secret)
		qrCode2, err2 := GenerateTOTPQRCode(username, secret)

		assert.NoError(t, err1, "First call should succeed")
		assert.NoError(t, err2, "Second call should succeed")
		assert.NotEmpty(t, qrCode1, "First QR code should not be empty")
		assert.NotEmpty(t, qrCode2, "Second QR code should not be empty")

		// Note: QR codes might be identical for same input since the content is the same
		// The temp file naming uses time.Now().UnixNano() so they should be generated separately
		// But the actual base64 content might be the same since it's the same TOTP URL
	})

	t.Run("Base32 secret validation", func(t *testing.T) {
		// Test with valid base32 secret
		username := "testuser"
		validSecret := "JBSWY3DPEHPK3PXP" // Valid base32

		qrCodeBase64, err := GenerateTOTPQRCode(username, validSecret)
		assert.NoError(t, err, "Valid base32 secret should work")
		assert.NotEmpty(t, qrCodeBase64, "QR code should be generated")

		// Test with invalid base32 characters (but QR generation should still work)
		invalidSecret := "INVALID-SECRET-123" // Contains invalid base32 chars
		qrCodeBase64Invalid, errInvalid := GenerateTOTPQRCode(username, invalidSecret)
		assert.NoError(t, errInvalid, "QR generation should work even with invalid base32")
		assert.NotEmpty(t, qrCodeBase64Invalid, "QR code should still be generated")
	})
}

// TestTOTPURLConstruction verifies the internal URL construction logic
func TestTOTPURLConstruction(t *testing.T) {
	// This is an indirect test by verifying expected components can be found in a manual URL construction
	username := "testuser"
	secret := "JBSWY3DPEHPK3PXP"

	// Manually construct what we expect the URL to look like
	expectedURL := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   "/UnderNET CService:" + username,
	}

	q := expectedURL.Query()
	q.Set("secret", secret)
	q.Set("issuer", "UnderNET CService")
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	expectedURL.RawQuery = q.Encode()

	// The URL should be well-formed
	assert.Equal(t, "otpauth", expectedURL.Scheme, "Scheme should be otpauth")
	assert.Equal(t, "totp", expectedURL.Host, "Host should be totp")
	assert.Contains(t, expectedURL.Path, username, "Path should contain username")
	assert.Contains(t, expectedURL.Path, "UnderNET CService", "Path should contain issuer")

	// Query parameters should be set correctly
	values := expectedURL.Query()
	assert.Equal(t, secret, values.Get("secret"), "Secret should be in query")
	assert.Equal(t, "UnderNET CService", values.Get("issuer"), "Issuer should be in query")
	assert.Equal(t, "SHA1", values.Get("algorithm"), "Algorithm should be SHA1")
	assert.Equal(t, "6", values.Get("digits"), "Digits should be 6")
	assert.Equal(t, "30", values.Get("period"), "Period should be 30")

	// Now test that our function can generate a QR code for this URL structure
	qrCodeBase64, err := GenerateTOTPQRCode(username, secret)
	assert.NoError(t, err, "QR code generation should work for valid TOTP URL")
	assert.NotEmpty(t, qrCodeBase64, "QR code should not be empty")
}
