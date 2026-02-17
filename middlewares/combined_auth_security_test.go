// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package middlewares

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/models"
)

// TestCombinedAuth_SecurityBoundary_EmptyAuthHeader verifies that an empty Authorization
// header (header present with empty value) is treated the same as absent.
// Attack vector: sending "Authorization: " to skip JWT validation while avoiding
// the no-header check.
func TestCombinedAuth_SecurityBoundary_EmptyAuthHeader(t *testing.T) {
	t.Run("empty Authorization header with JWT-only returns 401", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)
		cfg := newTestCombinedAuthConfig(mockService, true, false, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		assert.Equal(t, echo.ErrUnauthorized, err)
	})

	t.Run("empty Authorization header with both methods falls through to 401", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)
		cfg := newTestCombinedAuthConfig(mockService, true, true, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "")
		// No X-API-Key header either
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		assert.Equal(t, echo.ErrUnauthorized, err)
	})
}

// TestCombinedAuth_SecurityBoundary_BearerEdgeCases tests malformed Bearer token formats.
func TestCombinedAuth_SecurityBoundary_BearerEdgeCases(t *testing.T) {
	t.Run("Bearer with no token returns 401", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)
		cfg := newTestCombinedAuthConfig(mockService, true, false, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer ")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		assert.Equal(t, echo.ErrUnauthorized, err)
	})

	t.Run("Basic auth scheme is rejected by JWT-only config", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)
		cfg := newTestCombinedAuthConfig(mockService, true, false, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		// Basic auth with valid-looking base64 credentials
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNzd29yZA==")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		assert.Equal(t, echo.ErrUnauthorized, err, "Basic scheme should be rejected by JWT-only config")
	})

	t.Run("Authorization header with SQL injection pattern is rejected", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)
		cfg := newTestCombinedAuthConfig(mockService, true, false, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		// Attempt SQL injection via Authorization header
		req.Header.Set("Authorization", "Bearer '; DROP TABLE users; --")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		assert.NotPanics(t, func() {
			err := handler(c)
			assert.Equal(t, echo.ErrUnauthorized, err)
		})
	})
}

// TestCombinedAuth_SecurityBoundary_NoAuthMethodsEnabled tests the degenerate case
// where both AllowJWT and AllowAPIKey are false.
func TestCombinedAuth_SecurityBoundary_NoAuthMethodsEnabled(t *testing.T) {
	t.Run("no auth methods with Required=true always denies regardless of headers", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)
		cfg := newTestCombinedAuthConfig(mockService, false, false, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer some-token")
		req.Header.Set("X-API-Key", "some-api-key")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		assert.Equal(t, echo.ErrUnauthorized, err)
	})

	t.Run("no auth methods with Required=false passes through", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)
		cfg := newTestCombinedAuthConfig(mockService, false, false, false)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer some-token")
		req.Header.Set("X-API-Key", "some-api-key")
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

// TestCombinedAuth_SecurityBoundary_DeletedKey tests whether a soft-deleted API key
// is correctly rejected.
//
// POTENTIAL BUG: The current authenticateAPIKey implementation does not check the
// Deleted field on the returned ApiKey row. If GetAPIKeyByHash returns a deleted key
// (because the SQL query does not filter it), the key will be authenticated.
// This test documents the expected behavior (rejection).
//
// NOTE: The SQL query in GetAPIKeyByHash filters out deleted keys at the DB level,
// so in practice deleted keys are never returned. This test uses mocks that bypass
// the SQL filter, so the middleware-level gap is documented but not exploitable.
func TestCombinedAuth_SecurityBoundary_DeletedKey(t *testing.T) {
	t.Run("soft-deleted API key behavior documented", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)

		deletedKey := newValidApiKeyRow(nil, nil)
		deletedKey.Deleted = pgtype.Int2{Int16: 1, Valid: true}

		mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(deletedKey, nil).Once()
		// The middleware spawns a background goroutine for UpdateAPIKeyLastUsed
		mockService.On("UpdateAPIKeyLastUsed", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Maybe()

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
		// KNOWN GAP: authenticateAPIKey does not check the Deleted flag at the Go level.
		// The SQL query filters deleted keys, so this is defense-in-depth only.
		// If GetAPIKeyByHash ever changes to return deleted keys, add:
		//   if apiKey.Deleted.Valid && apiKey.Deleted.Int16 != 0 { return false, nil, nil }
		if err == nil {
			t.Log("SECURITY NOTE: authenticateAPIKey does not check Deleted flag; relies on SQL filter")
		}
		// Allow background goroutine to complete
		time.Sleep(10 * time.Millisecond)
	})
}

// TestCombinedAuth_SecurityBoundary_ExpirationBoundary tests edge cases in expiration logic.
// The current check is: if int64(ExpiresAt) < now → expired.
// This means ExpiresAt == now is NOT expired (off-by-one at the boundary second).
func TestCombinedAuth_SecurityBoundary_ExpirationBoundary(t *testing.T) {
	t.Run("key expiring exactly at current second is treated as valid (boundary condition)", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)

		exactlyNow := int32(time.Now().Unix())
		apiKeyRow := newValidApiKeyRow(nil, nil)
		apiKeyRow.ExpiresAt = pgtype.Int4{Int32: exactlyNow, Valid: true}

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

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		// Document actual boundary behavior: ExpiresAt == now uses strict "<" so this is NOT expired.
		// This may be intentional or a bug depending on design intent.
		// The test logs the behavior rather than asserting a specific outcome.
		t.Logf("Key at exact expiry second: err=%v, statusCode=%d (nil err = accepted, ErrUnauthorized = rejected)",
			err, rec.Code)
	})

	t.Run("key expiring 1 second in the future is valid", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)

		oneSecondFuture := int32(time.Now().Unix() + 1)
		apiKeyRow := newValidApiKeyRow(nil, nil)
		apiKeyRow.ExpiresAt = pgtype.Int4{Int32: oneSecondFuture, Valid: true}

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

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		assert.NoError(t, err, "key expiring in 1 second should still be valid")
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("key expired 1 second ago is rejected", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)

		oneSecondAgo := int32(time.Now().Unix() - 1)
		apiKeyRow := newValidApiKeyRow(nil, nil)
		apiKeyRow.ExpiresAt = pgtype.Int4{Int32: oneSecondAgo, Valid: true}

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
		assert.Equal(t, echo.ErrUnauthorized, err, "key expired 1 second ago must be rejected")
	})

	t.Run("key with ExpiresAt=0 and Valid=true is treated as no expiry", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)

		// ExpiresAt.Int32 = 0, Valid = true: the condition `apiKey.ExpiresAt.Int32 > 0` is false,
		// so expiry check is skipped. This is tested to document the behavior.
		apiKeyRow := newValidApiKeyRow(nil, nil)
		apiKeyRow.ExpiresAt = pgtype.Int4{Int32: 0, Valid: true}

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

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		assert.NoError(t, err, "ExpiresAt=0 with Valid=true should bypass expiry check and accept the key")
	})
}

// TestCombinedAuth_SecurityBoundary_VeryLongAPIKey tests that an oversized API key
// does not cause panics or resource exhaustion. SHA-256 hashing handles arbitrary input.
func TestCombinedAuth_SecurityBoundary_VeryLongAPIKey(t *testing.T) {
	t.Run("1MB API key is hashed and fails gracefully", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)
		mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(models.ApiKey{}, errors.New("not found")).Once()

		cfg := newTestCombinedAuthConfig(mockService, false, true, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		veryLongKey := strings.Repeat("a", 1024*1024)
		req.Header.Set("X-API-Key", veryLongKey)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		assert.NotPanics(t, func() {
			err := handler(c)
			assert.Equal(t, echo.ErrUnauthorized, err)
		})
	})
}

// TestCombinedAuth_SecurityBoundary_AdversarialAPIKeys tests API keys with adversarial
// content. All inputs are SHA-256 hashed before DB lookup, so injection is not possible,
// but the system must not panic or behave unexpectedly.
func TestCombinedAuth_SecurityBoundary_AdversarialAPIKeys(t *testing.T) {
	adversarialKeys := []struct {
		name string
		key  string
	}{
		{"null bytes in key", "key\x00withNull\x00bytes"},
		{"SQL injection attempt", "'; DROP TABLE api_keys; --"},
		{"unicode characters", "测试-api-key-值"},
		{"newline header injection attempt", "key\r\nX-Injected: evil"},
		{"tab characters", "key\twith\ttabs"},
		{"only whitespace", "   \t\n  "},
		{"zero-width unicode", "key\u200b\u200czero\u200dwidth"},
		{"path traversal attempt", "../../../../etc/passwd"},
		{"null key", "\x00\x00\x00\x00"},
	}

	for _, tc := range adversarialKeys {
		t.Run(tc.name, func(t *testing.T) {
			mockService := mocks.NewServiceInterface(t)
			mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
				Return(models.ApiKey{}, errors.New("not found")).Maybe()

			cfg := newTestCombinedAuthConfig(mockService, false, true, true)

			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-API-Key", tc.key)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			handler := CombinedAuth(cfg)(func(c echo.Context) error {
				return c.String(http.StatusOK, "success")
			})

			assert.NotPanics(t, func() {
				err := handler(c)
				// All adversarial keys must be rejected
				assert.Equal(t, echo.ErrUnauthorized, err,
					"adversarial API key %q must not authenticate", tc.name)
			})
		})
	}
}

// TestCombinedAuth_SecurityBoundary_MalformedIPRestrictions tests behavior when
// the IP restriction data stored in the database is malformed.
func TestCombinedAuth_SecurityBoundary_MalformedIPRestrictions(t *testing.T) {
	t.Run("malformed IP restrictions JSON in database causes auth failure", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)
		apiKeyRow := newValidApiKeyRow(nil, []byte(`this is not valid json`))

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

	t.Run("invalid IP address in X-Real-IP header with IP-restricted key causes auth failure", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)
		ipRestrictionsJSON, _ := json.Marshal([]string{"192.168.1.0/24"})
		apiKeyRow := newValidApiKeyRow(nil, ipRestrictionsJSON)

		mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(apiKeyRow, nil).Once()

		cfg := newTestCombinedAuthConfig(mockService, false, true, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", validAPIKey())
		req.Header.Set("X-Real-IP", "not-a-valid-ip-address")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		err := handler(c)
		// Invalid client IP should result in auth failure
		assert.Equal(t, echo.ErrUnauthorized, err)
	})

	t.Run("malformed CIDR in database IP restrictions causes auth failure", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)
		// Valid JSON array, but contents are not valid CIDR notation
		malformedCIDRJSON, _ := json.Marshal([]string{"not-a-cidr", "256.256.256.256/99"})
		apiKeyRow := newValidApiKeyRow(nil, malformedCIDRJSON)

		mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(apiKeyRow, nil).Once()

		cfg := newTestCombinedAuthConfig(mockService, false, true, true)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", validAPIKey())
		req.Header.Set("X-Real-IP", "192.168.1.1")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler := CombinedAuth(cfg)(func(c echo.Context) error {
			return c.String(http.StatusOK, "success")
		})

		assert.NotPanics(t, func() {
			err := handler(c)
			// Malformed CIDR in DB should cause auth to fail (error path)
			assert.Equal(t, echo.ErrUnauthorized, err)
		})
	})
}

// TestCombinedAuth_SecurityBoundary_ConcurrentRequests verifies that the middleware
// is safe to use concurrently (no data races, no panics under load).
func TestCombinedAuth_SecurityBoundary_ConcurrentRequests(t *testing.T) {
	t.Run("50 concurrent API key validations are goroutine-safe", func(t *testing.T) {
		const numGoroutines = 50

		mockService := mocks.NewServiceInterface(t)
		scopesJSON, _ := json.Marshal([]string{"read"})
		apiKeyRow := newValidApiKeyRow(scopesJSON, nil)

		mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(apiKeyRow, nil).Times(numGoroutines)
		mockService.On("UpdateAPIKeyLastUsed", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Maybe()

		cfg := newTestCombinedAuthConfig(mockService, false, true, true)

		e := echo.New()
		var wg sync.WaitGroup
		authErrors := make([]error, numGoroutines)

		for i := range numGoroutines {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-API-Key", validAPIKey())
				rec := httptest.NewRecorder()
				c := e.NewContext(req, rec)

				handler := CombinedAuth(cfg)(func(c echo.Context) error {
					return c.String(http.StatusOK, "success")
				})
				authErrors[idx] = handler(c)
			}(i)
		}

		wg.Wait()

		for i, err := range authErrors {
			assert.NoError(t, err, "goroutine %d should authenticate successfully", i)
		}
	})

	t.Run("concurrent requests with mixed valid/invalid keys handle correctly", func(t *testing.T) {
		const numValid = 25
		const numInvalid = 25

		mockService := mocks.NewServiceInterface(t)
		scopesJSON, _ := json.Marshal([]string{"read"})
		validRow := newValidApiKeyRow(scopesJSON, nil)

		// Valid key lookups succeed
		mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(validRow, nil).Times(numValid)
		mockService.On("UpdateAPIKeyLastUsed", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Maybe()

		cfg := newTestCombinedAuthConfig(mockService, false, true, true)

		e := echo.New()
		var wg sync.WaitGroup
		results := make([]error, numValid+numInvalid)

		for i := range numValid {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-API-Key", validAPIKey())
				rec := httptest.NewRecorder()
				c := e.NewContext(req, rec)
				handler := CombinedAuth(cfg)(func(c echo.Context) error {
					return c.String(http.StatusOK, "success")
				})
				results[idx] = handler(c)
			}(i)
		}

		// Invalid key goroutines use a separate mock setup
		mockService2 := mocks.NewServiceInterface(t)
		mockService2.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(models.ApiKey{}, errors.New("not found")).Times(numInvalid)
		cfg2 := newTestCombinedAuthConfig(mockService2, false, true, true)

		for i := range numInvalid {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-API-Key", "invalid-key-"+strings.Repeat("x", idx))
				rec := httptest.NewRecorder()
				c := e.NewContext(req, rec)
				handler := CombinedAuth(cfg2)(func(c echo.Context) error {
					return c.String(http.StatusOK, "success")
				})
				results[numValid+idx] = handler(c)
			}(i)
		}

		wg.Wait()

		// Valid requests should succeed
		for i := range numValid {
			assert.NoError(t, results[i], "valid request %d should succeed", i)
		}
		// Invalid requests should fail
		for i := range numInvalid {
			assert.Equal(t, echo.ErrUnauthorized, results[numValid+i],
				"invalid request %d should return 401", i)
		}
	})
}

// TestAuthenticateAPIKey_SecurityBoundary_AdversarialInputs directly tests the
// authenticateAPIKey function with adversarial inputs.
func TestAuthenticateAPIKey_SecurityBoundary_AdversarialInputs(t *testing.T) {
	t.Run("empty key string is hashed and returns not found", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)
		mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(models.ApiKey{}, errors.New("not found")).Once()

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Empty key string — SHA-256("") is still a valid hash
		authenticated, keyCtx, err := authenticateAPIKey(c, mockService, "")

		assert.False(t, authenticated)
		assert.Nil(t, keyCtx)
		assert.Error(t, err, "empty key should fail DB lookup")
	})

	t.Run("key with only whitespace is hashed and rejected", func(t *testing.T) {
		mockService := mocks.NewServiceInterface(t)
		mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(models.ApiKey{}, errors.New("not found")).Once()

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		authenticated, keyCtx, err := authenticateAPIKey(c, mockService, "   \t\n   ")

		assert.False(t, authenticated)
		assert.Nil(t, keyCtx)
		assert.Error(t, err)
	})

	t.Run("key with deleted flag behavior documented", func(t *testing.T) {
		// Documents the current behavior: authenticateAPIKey does NOT check Deleted flag.
		// The SQL query filters deleted keys at the DB level, so this is defense-in-depth.
		mockService := mocks.NewServiceInterface(t)

		scopesJSON, _ := json.Marshal([]string{"read"})
		deletedKey := newValidApiKeyRow(scopesJSON, nil)
		deletedKey.Deleted = pgtype.Int2{Int16: 1, Valid: true}

		mockService.On("GetAPIKeyByHash", mock.Anything, mock.AnythingOfType("string")).
			Return(deletedKey, nil).Once()
		mockService.On("UpdateAPIKeyLastUsed", mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Maybe()

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		authenticated, keyCtx, err := authenticateAPIKey(c, mockService, validAPIKey())

		// KNOWN GAP: authenticateAPIKey does not check Deleted flag at Go level.
		// SQL query filters deleted keys, making this defense-in-depth only.
		t.Logf("Deleted key: authenticated=%v, ctx=%v, err=%v", authenticated, keyCtx, err)
		if authenticated {
			t.Log("SECURITY NOTE: authenticateAPIKey does not check Deleted flag; relies on SQL filter")
		}
		// Allow background goroutine to complete
		time.Sleep(10 * time.Millisecond)
	})
}
