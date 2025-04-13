// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/undernetirc/cservice-api/internal/helper"
)

func TestHasAuthorization(t *testing.T) {
	tests := []struct {
		name           string
		adminLevel     int32
		userAdminLevel int32
		scopes         []string
		userScopes     string
		wantStatus     int
		wantMessage    string
	}{
		{
			name:           "Admin level sufficient",
			adminLevel:     500,
			userAdminLevel: 600,
			scopes:         []string{},
			userScopes:     "",
			wantStatus:     http.StatusOK,
		},
		{
			name:           "Admin level insufficient",
			adminLevel:     500,
			userAdminLevel: 400,
			scopes:         []string{},
			userScopes:     "",
			wantStatus:     http.StatusForbidden,
			wantMessage:    "level [500] or scope(s) [] is required to access this resource",
		},
		{
			name:           "Scope sufficient",
			adminLevel:     0,
			userAdminLevel: 0,
			scopes:         []string{"user.read"},
			userScopes:     "user.read user.write",
			wantStatus:     http.StatusOK,
		},
		{
			name:           "Scope insufficient",
			adminLevel:     0,
			userAdminLevel: 0,
			scopes:         []string{"user.delete"},
			userScopes:     "user.read user.write",
			wantStatus:     http.StatusForbidden,
			wantMessage:    "level [0] or scope(s) [user.delete] is required to access this resource",
		},
		{
			name:           "Admin level overrides missing scope",
			adminLevel:     500,
			userAdminLevel: 600,
			scopes:         []string{"user.delete"},
			userScopes:     "user.read user.write",
			wantStatus:     http.StatusOK,
		},
		{
			name:           "Multiple scopes - one match",
			adminLevel:     0,
			userAdminLevel: 0,
			scopes:         []string{"user.delete", "user.read"},
			userScopes:     "user.read",
			wantStatus:     http.StatusOK,
		},
		{
			name:           "Multiple scopes - no match",
			adminLevel:     0,
			userAdminLevel: 0,
			scopes:         []string{"user.delete", "user.admin"},
			userScopes:     "user.read user.write",
			wantStatus:     http.StatusForbidden,
			wantMessage:    "level [0] or scope(s) [user.delete, user.admin] is required to access this resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new echo instance
			e := echo.New()

			// Create a test request
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// Create a mock JWT token with claims
			claims := &helper.JwtClaims{
				Adm:   tt.userAdminLevel,
				Scope: tt.userScopes,
			}
			token := &jwt.Token{
				Claims: claims,
			}

			// Set the token in context
			c.Set(DefaultHasAuthorizationConfig.JWTContextKey, token)

			// Create test handler
			handler := func(c echo.Context) error {
				return c.String(http.StatusOK, "success")
			}

			// Create middleware
			middleware := HasAuthorization(tt.adminLevel, tt.scopes...)

			// Execute middleware
			err := middleware(handler)(c)

			// Check results
			if tt.wantStatus == http.StatusOK {
				assert.NoError(t, err)
				assert.Equal(t, http.StatusOK, rec.Code)
			} else {
				httpError, ok := err.(*echo.HTTPError)
				assert.True(t, ok)
				assert.Equal(t, tt.wantStatus, httpError.Code)
				assert.Equal(t, tt.wantMessage, httpError.Message)
			}
		})
	}
}

func TestHasAuthorizationWithConfig(t *testing.T) {
	// Test with custom config
	customConfig := HasAuthorizationConfig{
		JWTContextKey:   "custom_user",
		AdminLevelClaim: "custom_adm",
	}

	// Create a new echo instance
	e := echo.New()

	// Create a test request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Create a mock JWT token with claims
	claims := &helper.JwtClaims{
		Adm:   600,
		Scope: "user.read",
	}
	token := &jwt.Token{
		Claims: claims,
	}

	// Set the token in context with custom key
	c.Set(customConfig.JWTContextKey, token)

	// Create test handler
	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	}

	// Create middleware with custom config
	middleware := HasAuthorizationWithConfig(customConfig, 500)

	// Execute middleware
	err := middleware(handler)(c)

	// Check results
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHasAuthorizationNoToken(t *testing.T) {
	tests := []struct {
		name      string
		tokenVal  interface{}
		wantError error
	}{
		{
			name:      "No token in context",
			tokenVal:  nil,
			wantError: echo.ErrUnauthorized,
		},
		{
			name:      "Invalid token type",
			tokenVal:  "not a token",
			wantError: echo.ErrUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new echo instance
			e := echo.New()

			// Create a test request
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// Set token value in context (might be nil)
			if tt.tokenVal != nil {
				c.Set(DefaultHasAuthorizationConfig.JWTContextKey, tt.tokenVal)
			}

			// Create test handler
			handler := func(c echo.Context) error {
				return c.String(http.StatusOK, "success")
			}

			// Create middleware
			middleware := HasAuthorization(500)

			// Execute middleware
			err := middleware(handler)(c)

			// Check results
			assert.Equal(t, tt.wantError, err)
		})
	}
}

func TestHasAuthorizationInvalidToken(t *testing.T) {
	// Create a new echo instance
	e := echo.New()

	// Create a test request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Set invalid token in context
	c.Set(DefaultHasAuthorizationConfig.JWTContextKey, nil)

	// Create test handler
	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	}

	// Create middleware
	middleware := HasAuthorization(500)

	// Execute middleware
	err := middleware(handler)(c)

	// Check results
	assert.Equal(t, echo.ErrUnauthorized, err)
}
