// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package helper

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/labstack/echo/v4"
)

const (
	// APIKeyPrefix is the prefix for all API keys
	APIKeyPrefix = "cserv_"
	// APIKeyRandomBytes is the number of random bytes to generate (32 bytes = 256 bits)
	APIKeyRandomBytes = 32
)

// APIKeyContext holds API key authentication context
type APIKeyContext struct {
	ID       int32    // API key ID from database
	Name     string   // API key name
	Scopes   []string // Permission scopes
	IsAPIKey bool     // Always true to identify as API key auth
}

// GenerateAPIKey generates a new API key with the standard prefix
func GenerateAPIKey() (string, error) {
	randomBytes := make([]byte, APIKeyRandomBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base64 and add prefix
	encoded := base64.RawURLEncoding.EncodeToString(randomBytes)
	return APIKeyPrefix + encoded, nil
}

// HashAPIKey hashes an API key using SHA-256 for database lookup
// Note: Since API keys are cryptographically random with high entropy,
// SHA-256 is sufficient and allows for efficient database lookups.
func HashAPIKey(key string) (string, error) {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	hashBytes := hasher.Sum(nil)
	return hex.EncodeToString(hashBytes), nil
}

// ValidateAPIKey compares a plain-text API key to a SHA-256 hash
func ValidateAPIKey(plain, hash string) bool {
	computed, err := HashAPIKey(plain)
	if err != nil {
		return false
	}
	return computed == hash
}

// ExtractAPIKey extracts the API key from the X-API-Key header
func ExtractAPIKey(c echo.Context) string {
	return c.Request().Header.Get("X-API-Key")
}

// GetAPIKeyFromContext extracts API key context from echo context
func GetAPIKeyFromContext(c echo.Context) *APIKeyContext {
	user := c.Get("user")
	if apiKey, ok := user.(*APIKeyContext); ok {
		return apiKey
	}
	return nil
}
