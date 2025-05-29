// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

package helper

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"net/url"

	"github.com/skip2/go-qrcode"
	"github.com/undernetirc/cservice-api/internal/mail"
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

	// Generate QR code using skip2/go-qrcode (in-memory)
	qrBytes, err := qrcode.Encode(u.String(), qrcode.Medium, 256)
	if err != nil {
		return "", fmt.Errorf("failed to generate QR code: %w", err)
	}

	// Try to load and overlay logo from embedded filesystem
	if logoBytes, err := mail.TemplatesFS.ReadFile("templates/assets/logo.png"); err == nil {
		// Decode the QR code PNG
		qrImg, err := png.Decode(bytes.NewReader(qrBytes))
		if err == nil {
			// Load logo
			if logoImg, err := png.Decode(bytes.NewReader(logoBytes)); err == nil {
				// Overlay logo on QR code
				qrWithLogo := overlayLogoOnQR(qrImg, logoImg)

				// Re-encode to PNG
				var buf bytes.Buffer
				if err := png.Encode(&buf, qrWithLogo); err == nil {
					qrBytes = buf.Bytes()
				}
				// If any step fails, continue with original QR code
			}
		}
	}
	// If logo loading/overlay fails, continue with original QR code

	// Convert to base64
	encoded := base64.StdEncoding.EncodeToString(qrBytes)
	return encoded, nil
}

// overlayLogoOnQR overlays a logo image on the center of a QR code
func overlayLogoOnQR(qrImg, logoImg image.Image) image.Image {
	qrBounds := qrImg.Bounds()
	qrWidth := qrBounds.Dx()
	qrHeight := qrBounds.Dy()

	// Create a new RGBA image based on the QR code
	result := image.NewRGBA(qrBounds)
	draw.Draw(result, qrBounds, qrImg, qrBounds.Min, draw.Src)

	// Calculate logo size (about 1/5 of QR code size)
	logoSize := qrWidth / 5
	if logoSize < 20 {
		logoSize = 20 // Minimum logo size
	}

	// Calculate logo position (center)
	logoX := (qrWidth - logoSize) / 2
	logoY := (qrHeight - logoSize) / 2

	// Create a resized version of the logo
	logoResized := resizeImage(logoImg, logoSize, logoSize)

	// Create a white background for the logo (for better visibility)
	bgPadding := 4
	bgRect := image.Rect(
		logoX-bgPadding,
		logoY-bgPadding,
		logoX+logoSize+bgPadding,
		logoY+logoSize+bgPadding,
	)
	draw.Draw(result, bgRect, &image.Uniform{color.White}, image.Point{}, draw.Src)

	// Draw the logo
	logoRect := image.Rect(logoX, logoY, logoX+logoSize, logoY+logoSize)
	draw.Draw(result, logoRect, logoResized, image.Point{}, draw.Over)

	return result
}

// resizeImage resizes an image to the specified width and height using simple scaling
func resizeImage(src image.Image, width, height int) image.Image {
	srcBounds := src.Bounds()
	srcWidth := srcBounds.Dx()
	srcHeight := srcBounds.Dy()

	dst := image.NewRGBA(image.Rect(0, 0, width, height))

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			// Calculate source coordinates
			srcX := x * srcWidth / width
			srcY := y * srcHeight / height

			// Get color from source
			srcColor := src.At(srcBounds.Min.X+srcX, srcBounds.Min.Y+srcY)
			dst.Set(x, y, srcColor)
		}
	}

	return dst
}
