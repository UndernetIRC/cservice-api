// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 - 2025 UnderNET

package helper

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/testutils"
	"github.com/undernetirc/cservice-api/models"
)

func TestJwtClaimsHasScope(t *testing.T) {
	tests := []struct {
		name     string
		scope    string
		search   string
		expected bool
	}{
		{
			name:     "empty scope",
			scope:    "",
			search:   "admin",
			expected: false,
		},
		{
			name:     "single scope match",
			scope:    "admin",
			search:   "admin",
			expected: true,
		},
		{
			name:     "single scope no match",
			scope:    "user",
			search:   "admin",
			expected: false,
		},
		{
			name:     "multiple scopes with match",
			scope:    "user admin moderator",
			search:   "admin",
			expected: true,
		},
		{
			name:     "multiple scopes with match at beginning",
			scope:    "admin user moderator",
			search:   "admin",
			expected: true,
		},
		{
			name:     "multiple scopes with match at end",
			scope:    "user moderator admin",
			search:   "admin",
			expected: true,
		},
		{
			name:     "multiple scopes without match",
			scope:    "user moderator editor",
			search:   "admin",
			expected: false,
		},
		{
			name:     "partial match should not match",
			scope:    "administrator user",
			search:   "admin",
			expected: false,
		},
		{
			name:     "case sensitivity check",
			scope:    "Admin",
			search:   "admin",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &JwtClaims{
				Scope: tt.scope,
			}
			result := claims.HasScope(tt.search)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateToken(t *testing.T) {
	// Setup
	config.DefaultConfig()

	t.Run("valid token generation", func(t *testing.T) {
		user := new(models.User)
		user.ID = 1000
		user.Username = "test"
		user.TotpKey.String = ""

		claims := &JwtClaims{
			UserID:   user.ID,
			Username: user.Username,
			Scope:    "admin",
		}

		// Fixed time for deterministic tests
		fixedTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
		token, err := GenerateToken(claims, fixedTime)

		// Verify token was generated correctly
		require.NoError(t, err)
		require.NotEmpty(t, token.AccessToken)
		require.NotEmpty(t, token.RefreshToken)
		require.NotEmpty(t, token.RefreshUUID)

		// Verify access token expiry
		assert.Equal(t, jwt.NewNumericDate(fixedTime.Add(time.Minute*5)), token.AtExpires)

		// Verify refresh token expiry
		assert.Equal(t, jwt.NewNumericDate(fixedTime.Add(time.Hour*24*7)), token.RtExpires)

		// Decode and verify the access token payload
		segments := strings.Split(token.AccessToken, ".")
		require.Equal(t, 3, len(segments), "JWT should have 3 segments")

		// Padding for base64 decoding if needed
		if l := len(segments[1]) % 4; l > 0 {
			segments[1] += strings.Repeat("=", 4-l)
		}

		payload, err := base64.URLEncoding.DecodeString(segments[1])
		require.NoError(t, err, "Failed to decode token payload")

		var tokenData map[string]interface{}
		err = json.Unmarshal(payload, &tokenData)
		require.NoError(t, err, "Failed to unmarshal token payload")

		// Verify token contents
		assert.Equal(t, float64(1000), tokenData["user_id"])
		assert.Equal(t, "test", tokenData["username"])
		assert.Equal(t, "admin", tokenData["scope"])
		assert.Equal(t, token.RefreshUUID, tokenData["refresh_uuid"])

		// Verify token headers
		headers := strings.Split(token.AccessToken, ".")[0]
		if l := len(headers) % 4; l > 0 {
			headers += strings.Repeat("=", 4-l)
		}

		headerBytes, err := base64.URLEncoding.DecodeString(headers)
		require.NoError(t, err)

		var headerData map[string]interface{}
		err = json.Unmarshal(headerBytes, &headerData)
		require.NoError(t, err)

		assert.Equal(t, "at", headerData["kid"])
	})

	t.Run("token with admin level", func(t *testing.T) {
		claims := &JwtClaims{
			UserID:   1000,
			Username: "admin",
			Scope:    "admin",
			Adm:      1000, // Admin level
		}

		token, err := GenerateToken(claims, time.Now())
		require.NoError(t, err)

		// Decode token to verify admin level
		segments := strings.Split(token.AccessToken, ".")
		if l := len(segments[1]) % 4; l > 0 {
			segments[1] += strings.Repeat("=", 4-l)
		}

		payload, _ := base64.URLEncoding.DecodeString(segments[1])
		var tokenData map[string]interface{}
		_ = json.Unmarshal(payload, &tokenData)

		assert.Equal(t, float64(1000), tokenData["adm"])
	})
}

func TestGetClaimsFromContext(t *testing.T) {
	// Setup
	config.DefaultConfig()

	t.Run("retrieving claims from context", func(t *testing.T) {
		claims := &JwtClaims{
			UserID:   1,
			Username: "Admin",
			Scope:    "admin",
			Adm:      1000,
		}

		tokens, err := GenerateToken(claims, time.Now())
		require.NoError(t, err)

		token, err := jwt.ParseWithClaims(tokens.AccessToken, &JwtClaims{}, func(_ *jwt.Token) (interface{}, error) {
			return GetJWTPublicKey(), nil
		})
		require.NoError(t, err)

		e := echo.New()
		ctx := e.NewContext(nil, nil)
		ctx.Set("user", token)

		// Test
		resultClaims := GetClaimsFromContext(ctx)

		// Verify
		assert.Equal(t, claims.UserID, resultClaims.UserID)
		assert.Equal(t, claims.Username, resultClaims.Username)
		assert.Equal(t, claims.Scope, resultClaims.Scope)
		assert.Equal(t, claims.Adm, resultClaims.Adm)
	})
}

func TestGetJWTSigningAndPublicKeys(t *testing.T) {
	t.Run("HMAC keys with default config", func(t *testing.T) {
		// Setup with HMAC
		config.DefaultConfig()
		config.ServiceJWTSigningMethod.Set("HS256")
		config.ServiceJWTSigningSecret.Set("test-secret")
		config.ServiceJWTRefreshSigningSecret.Set("test-refresh-secret")

		// Test
		signingKey := GetJWTSigningKey()
		refreshSigningKey := GetJWTRefreshSigningKey()
		publicKey := GetJWTPublicKey()

		// Verify
		assert.Equal(t, []byte("test-secret"), signingKey)
		assert.Equal(t, []byte("test-refresh-secret"), refreshSigningKey)
		assert.Equal(t, []byte("test-secret"), publicKey)
	})
}

func TestJWTWithRSAKeys(t *testing.T) {
	// Setup
	keyFile, publicKeyFile, err := testutils.GenerateRSAKeyPair()
	require.NoError(t, err)

	defer func() {
		_ = os.Remove(keyFile.Name())
		_ = os.Remove(publicKeyFile.Name())
	}()

	t.Run("RSA signing and verification", func(t *testing.T) {
		config.DefaultConfig()
		config.ServiceJWTSigningMethod.Set("RS256")
		config.ServiceJWTSigningKey.Set(keyFile.Name())
		config.ServiceJWTPublicKey.Set(publicKeyFile.Name())
		config.ServiceJWTRefreshSigningKey.Set(keyFile.Name())
		config.ServiceJWTRefreshPublicKey.Set(publicKeyFile.Name())

		claims := &JwtClaims{
			UserID:   1,
			Username: "Admin",
			Scope:    "admin",
		}

		tokens, err := GenerateToken(claims, time.Now())
		require.NoError(t, err)

		token, err := jwt.ParseWithClaims(tokens.AccessToken, &JwtClaims{}, func(_ *jwt.Token) (interface{}, error) {
			return GetJWTPublicKey(), nil
		})
		require.NoError(t, err)
		assert.True(t, token.Valid)

		parsedClaims, ok := token.Claims.(*JwtClaims)
		require.True(t, ok)
		assert.Equal(t, int32(1), parsedClaims.UserID)
		assert.Equal(t, "Admin", parsedClaims.Username)
	})

	t.Run("GetEchoJWTConfig returns valid config", func(t *testing.T) {
		config.ServiceJWTSigningMethod.Set("RS256")

		config := GetEchoJWTConfig()

		assert.Equal(t, "RS256", config.SigningMethod)
		assert.NotNil(t, config.SigningKey)
		assert.NotNil(t, config.NewClaimsFunc)

		// Test the NewClaimsFunc
		e := echo.New()
		ctx := e.NewContext(nil, nil)
		claims := config.NewClaimsFunc(ctx)

		_, ok := claims.(*JwtClaims)
		assert.True(t, ok)
	})
}

func TestGetClaimsFromRefreshToken(t *testing.T) {
	// Setup with HMAC
	config.DefaultConfig()
	config.ServiceJWTSigningMethod.Set("HS256")
	config.ServiceJWTSigningSecret.Set("test-secret")
	config.ServiceJWTRefreshSigningSecret.Set("test-refresh-secret")

	t.Run("valid refresh token with HMAC", func(t *testing.T) {
		claims := &JwtClaims{
			UserID:   123,
			Username: "testuser",
		}

		tokens, err := GenerateToken(claims, time.Now())
		require.NoError(t, err)

		// Test
		tokenClaims, err := GetClaimsFromRefreshToken(tokens.RefreshToken)

		// Verify
		require.NoError(t, err)
		assert.Equal(t, float64(123), tokenClaims["user_id"])
		assert.Equal(t, tokens.RefreshUUID, tokenClaims["refresh_uuid"])
	})

	t.Run("invalid refresh token", func(t *testing.T) {
		_, err := GetClaimsFromRefreshToken("invalid.token.here")
		assert.Error(t, err)
	})

	t.Run("altered signing method", func(t *testing.T) {
		// Generate a valid token first
		claims := &JwtClaims{
			UserID:   123,
			Username: "testuser",
		}

		tokens, err := GenerateToken(claims, time.Now())
		require.NoError(t, err)

		// Alter the token header to change the signing method
		parts := strings.Split(tokens.RefreshToken, ".")
		require.Equal(t, 3, len(parts))

		// Decode header
		if l := len(parts[0]) % 4; l > 0 {
			parts[0] += strings.Repeat("=", 4-l)
		}

		headerBytes, err := base64.URLEncoding.DecodeString(parts[0])
		require.NoError(t, err)

		var header map[string]interface{}
		err = json.Unmarshal(headerBytes, &header)
		require.NoError(t, err)

		// Change algorithm
		header["alg"] = "RS256" // Different from our configured HS256

		// Encode back
		newHeaderBytes, err := json.Marshal(header)
		require.NoError(t, err)

		newHeader := base64.URLEncoding.EncodeToString(newHeaderBytes)
		newHeader = strings.TrimRight(newHeader, "=")

		// Rebuild token
		alteredToken := newHeader + "." + parts[1] + "." + parts[2]

		// Test
		_, err = GetClaimsFromRefreshToken(alteredToken)

		// Verify
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected signing method")
	})

	// Setup with RSA
	keyFile, publicKeyFile, err := testutils.GenerateRSAKeyPair()
	require.NoError(t, err)

	defer func() {
		_ = os.Remove(keyFile.Name())
		_ = os.Remove(publicKeyFile.Name())
	}()

	t.Run("valid refresh token with RSA", func(t *testing.T) {
		config.ServiceJWTSigningMethod.Set("RS256")
		config.ServiceJWTSigningKey.Set(keyFile.Name())
		config.ServiceJWTPublicKey.Set(publicKeyFile.Name())
		config.ServiceJWTRefreshSigningKey.Set(keyFile.Name())
		config.ServiceJWTRefreshPublicKey.Set(publicKeyFile.Name())

		claims := &JwtClaims{
			UserID:   123,
			Username: "testuser",
		}

		tokens, err := GenerateToken(claims, time.Now())
		require.NoError(t, err)

		// Test
		tokenClaims, err := GetClaimsFromRefreshToken(tokens.RefreshToken)

		// Verify
		require.NoError(t, err)
		assert.Equal(t, float64(123), tokenClaims["user_id"])
		assert.Equal(t, tokens.RefreshUUID, tokenClaims["refresh_uuid"])
	})

	t.Run("expired token", func(t *testing.T) {
		// Create token that's already expired
		token := jwt.New(jwt.GetSigningMethod(config.ServiceJWTSigningMethod.GetString()))
		token.Header["kid"] = "rt"
		claims := token.Claims.(jwt.MapClaims)
		claims["refresh_uuid"] = "test-uuid"
		claims["user_id"] = 123
		claims["exp"] = time.Now().Add(-time.Hour).Unix() // Expired 1 hour ago

		signedToken, err := token.SignedString(GetJWTRefreshSigningKey())
		require.NoError(t, err)

		// Test
		_, err = GetClaimsFromRefreshToken(signedToken)

		// Verify
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})
}
