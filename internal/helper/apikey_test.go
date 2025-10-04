// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package helper

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateAPIKey(t *testing.T) {
	key, err := GenerateAPIKey()
	require.NoError(t, err)
	require.NotEmpty(t, key)

	// Check prefix
	assert.True(t, strings.HasPrefix(key, APIKeyPrefix), "API key should have correct prefix")

	// Check length (prefix + base64 encoded 32 bytes)
	// 32 bytes = 43 characters in base64 (without padding)
	expectedLen := len(APIKeyPrefix) + 43
	assert.Equal(t, expectedLen, len(key), "API key should have correct length")
}

func TestGenerateAPIKey_Uniqueness(t *testing.T) {
	key1, err1 := GenerateAPIKey()
	key2, err2 := GenerateAPIKey()

	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.NotEqual(t, key1, key2, "Generated keys should be unique")
}

func TestHashAPIKey(t *testing.T) {
	key := "cserv_test123456789"

	hash, err := HashAPIKey(key)
	require.NoError(t, err)
	require.NotEmpty(t, hash)

	// SHA-256 produces 64 character hex string
	assert.Len(t, hash, 64, "SHA-256 hash should be 64 characters")
	// Check it's valid hex
	assert.Regexp(t, "^[a-f0-9]{64}$", hash, "Hash should be valid hex format")
}

func TestHashAPIKey_Deterministic(t *testing.T) {
	key := "cserv_test123456789"

	hash1, err1 := HashAPIKey(key)
	hash2, err2 := HashAPIKey(key)

	require.NoError(t, err1)
	require.NoError(t, err2)

	// SHA-256 should produce identical hashes for the same input
	assert.Equal(t, hash1, hash2, "SHA-256 hashes should be deterministic")
}

func TestValidateAPIKey(t *testing.T) {
	key := "cserv_test123456789"
	hash, err := HashAPIKey(key)
	require.NoError(t, err)

	tests := []struct {
		name      string
		plainKey  string
		hash      string
		wantValid bool
	}{
		{
			name:      "valid key",
			plainKey:  key,
			hash:      hash,
			wantValid: true,
		},
		{
			name:      "invalid key",
			plainKey:  "cserv_wrongkey",
			hash:      hash,
			wantValid: false,
		},
		{
			name:      "empty key",
			plainKey:  "",
			hash:      hash,
			wantValid: false,
		},
		{
			name:      "invalid hash format",
			plainKey:  key,
			hash:      "invalid_hash",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := ValidateAPIKey(tt.plainKey, tt.hash)
			assert.Equal(t, tt.wantValid, valid)
		})
	}
}

func TestExtractAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		want        string
	}{
		{
			name:        "valid key in header",
			headerValue: "cserv_abc123def456",
			want:        "cserv_abc123def456",
		},
		{
			name:        "empty header",
			headerValue: "",
			want:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.headerValue != "" {
				req.Header.Set("X-API-Key", tt.headerValue)
			}
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			got := ExtractAPIKey(c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetAPIKeyFromContext(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	t.Run("api key present", func(t *testing.T) {
		expected := &APIKeyContext{
			ID:       123,
			Name:     "test-key",
			Scopes:   []string{"channels:read"},
			IsAPIKey: true,
		}
		c.Set("user", expected)

		got := GetAPIKeyFromContext(c)
		require.NotNil(t, got)
		assert.Equal(t, expected.ID, got.ID)
		assert.Equal(t, expected.Name, got.Name)
		assert.Equal(t, expected.Scopes, got.Scopes)
		assert.True(t, got.IsAPIKey)
	})

	t.Run("no api key", func(t *testing.T) {
		c.Set("user", nil)
		got := GetAPIKeyFromContext(c)
		assert.Nil(t, got)
	})

	t.Run("wrong type in context", func(t *testing.T) {
		c.Set("user", "not an api key")
		got := GetAPIKeyFromContext(c)
		assert.Nil(t, got)
	})
}
