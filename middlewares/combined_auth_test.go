// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package middlewares

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

func TestDefaultCombinedAuthConfig(t *testing.T) {
	mockService := mocks.NewServiceInterface(t)
	cfg := DefaultCombinedAuthConfig(mockService)

	assert.True(t, cfg.AllowJWT, "AllowJWT should default to true")
	assert.True(t, cfg.AllowAPIKey, "AllowAPIKey should default to true")
	assert.True(t, cfg.Required, "Required should default to true")
	assert.Equal(t, mockService, cfg.Service, "Service should be set")
}

// newTestCombinedAuthConfig creates a CombinedAuthConfig for testing with API key support only.
// JWT is disabled to avoid needing real RSA keys in unit tests.
func newTestCombinedAuthConfig(service models.ServiceInterface, allowJWT, allowAPIKey, required bool) CombinedAuthConfig {
	return CombinedAuthConfig{
		AllowJWT:    allowJWT,
		AllowAPIKey: allowAPIKey,
		Required:    required,
		JWTConfig: echojwt.Config{
			SigningKey: []byte("test-secret-key-for-unit-tests"),
		},
		Service: service,
	}
}

// validAPIKey returns a test API key and its SHA-256 hash for use in tests.
func validAPIKey() string {
	return "test-api-key-12345"
}

// newValidAPIKeyRow returns a models.ApiKey representing a valid, non-expired key.
func newValidAPIKeyRow(scopes []byte, ipRestrictions []byte) models.ApiKey {
	return models.ApiKey{
		ID:             1,
		Name:           "test-key",
		KeyHash:        "hashed",
		Scopes:         scopes,
		CreatedBy:      1,
		CreatedAt:      int32(time.Now().Unix()),
		ExpiresAt:      pgtype.Int4{Int32: 0, Valid: false},
		Deleted:        pgtype.Int2{Int16: 0, Valid: true},
		IpRestrictions: ipRestrictions,
	}
}

func TestCombinedAuth_JWTOnly(t *testing.T) {
	t.Run("no auth header with required=true returns 401", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)
		cfg := newTestCombinedAuthConfig(mockService, true, false, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		assert.Equal(t, echo.ErrUnauthorized, err)
	})

	t.Run("no auth header with required=false continues", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)
		cfg := newTestCombinedAuthConfig(mockService, true, false, false)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestCombinedAuth_APIKeyOnly(t *testing.T) {
	t.Run("valid API key authenticates successfully", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)

		scopesJSON, _ := json.Marshal([]string{"channels:read", "users:write"})
		apiKeyRow := newValidAPIKeyRow(scopesJSON, nil)

		mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(apiKeyRow, nil).Once()
		mockService.On("UpdateAPIKeyLastUsed", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Maybe()

		cfg := newTestCombinedAuthConfig(mockService, false, true, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", validAPIKey())
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		var capturedUser any
		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			capturedUser = c.Get("user")
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		apiKeyCtx, ok := capturedUser.(*helper.APIKeyContext)
		require.True(t, ok, "user context should be *helper.APIKeyContext")
		assert.Equal(t, int32(1), apiKeyCtx.ID)
		assert.Equal(t, "test-key", apiKeyCtx.Name)
		assert.Equal(t, []string{"channels:read", "users:write"}, apiKeyCtx.Scopes)
		assert.True(t, apiKeyCtx.IsAPIKey)
	})

	t.Run("no API key with required=true returns 401", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)
		cfg := newTestCombinedAuthConfig(mockService, false, true, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		assert.Equal(t, echo.ErrUnauthorized, err)
	})
}

func TestCombinedAuth_BothPresent(t *testing.T) {
	t.Run("JWT fails, falls back to valid API key", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)

		scopesJSON, _ := json.Marshal([]string{"read"})
		apiKeyRow := newValidAPIKeyRow(scopesJSON, nil)

		mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(apiKeyRow, nil).Once()
		mockService.On("UpdateAPIKeyLastUsed", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Maybe()

		cfg := newTestCombinedAuthConfig(mockService, true, true, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		// Set both headers - JWT will fail (no valid signing key configured), API key should succeed
		req.Header.Set("Authorization", "Bearer invalid-jwt-token")
		req.Header.Set("X-API-Key", validAPIKey())
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		var capturedUser any
		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			capturedUser = c.Get("user")
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		apiKeyCtx, ok := capturedUser.(*helper.APIKeyContext)
		require.True(t, ok, "should fall back to API key auth")
		assert.Equal(t, int32(1), apiKeyCtx.ID)
	})
}

func TestCombinedAuth_InvalidAPIKey(t *testing.T) {
	t.Run("key not found in database returns 401", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)
		mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(models.ApiKey{}, errors.New("no rows")).Once()

		cfg := newTestCombinedAuthConfig(mockService, false, true, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", "nonexistent-key")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		assert.Equal(t, echo.ErrUnauthorized, err)
	})
}

func TestCombinedAuth_ExpiredKey(t *testing.T) {
	t.Run("expired API key returns 401", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)

		pastTime := int32(time.Now().Add(-1 * time.Hour).Unix())
		apiKeyRow := newValidAPIKeyRow(nil, nil)
		apiKeyRow.ExpiresAt = pgtype.Int4{Int32: pastTime, Valid: true}

		mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(apiKeyRow, nil).Once()

		cfg := newTestCombinedAuthConfig(mockService, false, true, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", validAPIKey())
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		assert.Equal(t, echo.ErrUnauthorized, err)
	})
}

func TestCombinedAuth_ScopeValidation(t *testing.T) {
	t.Run("scopes are correctly parsed and set on context", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)

		scopes := []string{"channels:read", "users:write", "admin:manage"}
		scopesJSON, _ := json.Marshal(scopes)
		apiKeyRow := newValidAPIKeyRow(scopesJSON, nil)

		mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(apiKeyRow, nil).Once()
		mockService.On("UpdateAPIKeyLastUsed", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Maybe()

		cfg := newTestCombinedAuthConfig(mockService, false, true, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", validAPIKey())
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		var capturedUser any
		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			capturedUser = c.Get("user")
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		require.NoError(t, err)

		apiKeyCtx, ok := capturedUser.(*helper.APIKeyContext)
		require.True(t, ok)
		assert.Equal(t, scopes, apiKeyCtx.Scopes)
	})

	t.Run("empty scopes results in nil scopes slice", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)

		apiKeyRow := newValidAPIKeyRow(nil, nil)

		mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(apiKeyRow, nil).Once()
		mockService.On("UpdateAPIKeyLastUsed", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Maybe()

		cfg := newTestCombinedAuthConfig(mockService, false, true, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", validAPIKey())
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		var capturedUser any
		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			capturedUser = c.Get("user")
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		require.NoError(t, err)

		apiKeyCtx, ok := capturedUser.(*helper.APIKeyContext)
		require.True(t, ok)
		assert.Nil(t, apiKeyCtx.Scopes)
	})
}

func TestCombinedAuth_IPRestriction(t *testing.T) {
	t.Run("allowed IP passes", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)

		ipRestrictionsJSON, _ := json.Marshal([]string{"192.168.1.0/24"})
		scopesJSON, _ := json.Marshal([]string{"read"})
		apiKeyRow := newValidAPIKeyRow(scopesJSON, ipRestrictionsJSON)

		mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(apiKeyRow, nil).Once()
		mockService.On("UpdateAPIKeyLastUsed", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Maybe()

		cfg := newTestCombinedAuthConfig(mockService, false, true, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", validAPIKey())
		req.Header.Set("X-Real-IP", "192.168.1.50")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("denied IP returns 401", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)

		ipRestrictionsJSON, _ := json.Marshal([]string{"192.168.1.0/24"})
		apiKeyRow := newValidAPIKeyRow(nil, ipRestrictionsJSON)

		mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(apiKeyRow, nil).Once()

		cfg := newTestCombinedAuthConfig(mockService, false, true, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", validAPIKey())
		req.Header.Set("X-Real-IP", "10.0.0.1")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		assert.Equal(t, echo.ErrUnauthorized, err)
	})
}

func TestAuthenticateAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(m *mocks.ServiceInterface)
		clientIP    string
		wantAuth    bool
		wantContext bool
		wantErr     bool
	}{
		{
			name: "valid key returns authenticated context",
			setupMock: func(m *mocks.ServiceInterface) {
				scopesJSON, _ := json.Marshal([]string{"read", "write"})
				m.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
					Return(newValidAPIKeyRow(scopesJSON, nil), nil).Once()
				m.On("UpdateAPIKeyLastUsed", mock.Anything, mock.Anything, mock.Anything).
					Return(nil).Maybe()
			},
			wantAuth:    true,
			wantContext: true,
			wantErr:     false,
		},
		{
			name: "database error returns error",
			setupMock: func(m *mocks.ServiceInterface) {
				m.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
					Return(models.ApiKey{}, errors.New("connection refused")).Once()
			},
			wantAuth:    false,
			wantContext: false,
			wantErr:     true,
		},
		{
			name: "expired key returns false with no error",
			setupMock: func(m *mocks.ServiceInterface) {
				row := newValidAPIKeyRow(nil, nil)
				row.ExpiresAt = pgtype.Int4{Int32: int32(time.Now().Add(-1 * time.Hour).Unix()), Valid: true}
				m.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
					Return(row, nil).Once()
			},
			wantAuth:    false,
			wantContext: false,
			wantErr:     false,
		},
		{
			name: "IP allowed passes restriction check",
			setupMock: func(m *mocks.ServiceInterface) {
				ipJSON, _ := json.Marshal([]string{"10.0.0.0/8"})
				m.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
					Return(newValidAPIKeyRow(nil, ipJSON), nil).Once()
				m.On("UpdateAPIKeyLastUsed", mock.Anything, mock.Anything, mock.Anything).
					Return(nil).Maybe()
			},
			clientIP:    "10.0.0.5",
			wantAuth:    true,
			wantContext: true,
			wantErr:     false,
		},
		{
			name: "IP denied fails restriction check",
			setupMock: func(m *mocks.ServiceInterface) {
				ipJSON, _ := json.Marshal([]string{"10.0.0.0/8"})
				m.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
					Return(newValidAPIKeyRow(nil, ipJSON), nil).Once()
			},
			clientIP:    "172.16.0.1",
			wantAuth:    false,
			wantContext: false,
			wantErr:     false,
		},
		{
			name: "invalid scope JSON returns error",
			setupMock: func(m *mocks.ServiceInterface) {
				row := newValidAPIKeyRow([]byte(`not valid json`), nil)
				m.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
					Return(row, nil).Once()
			},
			wantAuth:    false,
			wantContext: false,
			wantErr:     true,
		},
		{
			name: "empty scopes returns context with nil scopes",
			setupMock: func(m *mocks.ServiceInterface) {
				m.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
					Return(newValidAPIKeyRow(nil, nil), nil).Once()
				m.On("UpdateAPIKeyLastUsed", mock.Anything, mock.Anything, mock.Anything).
					Return(nil).Maybe()
			},
			wantAuth:    true,
			wantContext: true,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := mocks.NewServiceInterface(t)
			tt.setupMock(mockService)

			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.clientIP != "" {
				req.Header.Set("X-Real-IP", tt.clientIP)
			}
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			authenticated, keyCtx, err := authenticateAPIKey(c, mockService, validAPIKey())

			assert.Equal(t, tt.wantAuth, authenticated)
			if tt.wantContext {
				assert.NotNil(t, keyCtx)
				assert.True(t, keyCtx.IsAPIKey)
			} else {
				assert.Nil(t, keyCtx)
			}
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCombinedAuth_DatabaseError(t *testing.T) {
	t.Run("database error with required=true returns 401", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)
		mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(models.ApiKey{}, errors.New("database unavailable")).Once()

		cfg := newTestCombinedAuthConfig(mockService, false, true, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", validAPIKey())
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		assert.Equal(t, echo.ErrUnauthorized, err)
	})

	t.Run("database error with required=false continues", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)
		mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(models.ApiKey{}, errors.New("database unavailable")).Once()

		cfg := newTestCombinedAuthConfig(mockService, false, true, false)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", validAPIKey())
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
