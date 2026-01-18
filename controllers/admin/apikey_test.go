// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/internal/checks"
	"github.com/undernetirc/cservice-api/internal/config"
	apierrors "github.com/undernetirc/cservice-api/internal/errors"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

func TestAPIKeyController(t *testing.T) {
	config.DefaultConfig()

	jwtConfig := echojwt.Config{
		SigningMethod: config.ServiceJWTSigningMethod.GetString(),
		SigningKey:    helper.GetJWTPublicKey(),
		NewClaimsFunc: func(_ echo.Context) jwt.Claims {
			return new(helper.JwtClaims)
		},
	}

	claims := new(helper.JwtClaims)
	claims.UserID = 1
	claims.Username = "Admin"
	claims.Adm = 1000
	tokens, _ := helper.GenerateToken(claims, time.Now())

	t.Parallel()

	t.Run("CreateAPIKey_Success", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		// Mock successful API key creation
		db.On("CreateAPIKey", mock.Anything, mock.Anything).
			Return(models.ApiKey{
				ID:          1,
				Name:        "Test API Key",
				Description: pgtype.Text{String: "Test description", Valid: true},
				CreatedBy:   1,
				CreatedAt:   int32(time.Now().Unix()),
				LastUpdated: int32(time.Now().Unix()),
				Deleted:     pgtype.Int2{Int16: 0, Valid: true},
			}, nil)

		checks.InitUser(context.Background(), db)
		c := NewAPIKeyController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("", c.CreateAPIKey, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(`{
			"name": "Test API Key",
			"description": "Test description",
			"scopes": ["channels:read", "users:read"]
		}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPost, "/", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var response CreateAPIKeyResponse
		dec := json.NewDecoder(resp.Body)
		err := dec.Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, int32(1), response.ID)
		assert.Equal(t, "Test API Key", response.Name)
		assert.NotEmpty(t, response.Key) // Plain key should be returned
		assert.Contains(t, response.Key, "cserv_")
		assert.Equal(t, "This key will only be shown once. Store it securely.", response.Warning)
	})

	t.Run("CreateAPIKey_ValidationError_MissingName", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		checks.InitUser(context.Background(), db)
		c := NewAPIKeyController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("", c.CreateAPIKey, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(`{
			"scopes": ["channels:read"]
		}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPost, "/", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("CreateAPIKey_ValidationError_InvalidScope", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		checks.InitUser(context.Background(), db)
		c := NewAPIKeyController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("", c.CreateAPIKey, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(`{
			"name": "Test Key",
			"scopes": ["invalid:scope"]
		}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPost, "/", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("CreateAPIKey_Unauthorized", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		checks.InitUser(context.Background(), db)
		c := NewAPIKeyController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("", c.CreateAPIKey, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(`{
			"name": "Test Key",
			"scopes": ["channels:read"]
		}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPost, "/", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		// No Authorization header

		e.ServeHTTP(w, r)
		resp := w.Result()
		// JWT middleware returns 400 for missing token, not 401
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("ListAPIKeys_Success", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		scopesJSON1 := []byte(`["channels:read", "users:read"]`)
		scopesJSON2 := []byte(`["channels:write"]`)

		db.On("ListAPIKeys", mock.Anything).
			Return([]models.ApiKey{
				{
					ID:          1,
					Name:        "Key 1",
					Description: pgtype.Text{String: "Description 1", Valid: true},
					Scopes:      scopesJSON1,
					CreatedBy:   1,
					CreatedAt:   int32(time.Now().Unix()),
					LastUpdated: int32(time.Now().Unix()),
					Deleted:     pgtype.Int2{Int16: 0, Valid: true},
				},
				{
					ID:          2,
					Name:        "Key 2",
					Description: pgtype.Text{String: "Description 2", Valid: true},
					Scopes:      scopesJSON2,
					CreatedBy:   1,
					CreatedAt:   int32(time.Now().Unix()),
					LastUpdated: int32(time.Now().Unix()),
					Deleted:     pgtype.Int2{Int16: 0, Valid: true},
				},
			}, nil)

		checks.InitUser(context.Background(), db)
		c := NewAPIKeyController(db)

		e := echo.New()
		e.GET("", c.ListAPIKeys, echojwt.WithConfig(jwtConfig))

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response []APIKeyResponse
		dec := json.NewDecoder(resp.Body)
		err := dec.Decode(&response)
		assert.NoError(t, err)
		assert.Len(t, response, 2)
		assert.Equal(t, "Key 1", response[0].Name)
		assert.Equal(t, "Key 2", response[1].Name)
	})

	t.Run("ListAPIKeys_DatabaseError", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		db.On("ListAPIKeys", mock.Anything).
			Return([]models.ApiKey{}, pgx.ErrNoRows)

		checks.InitUser(context.Background(), db)
		c := NewAPIKeyController(db)

		e := echo.New()
		e.GET("", c.ListAPIKeys, echojwt.WithConfig(jwtConfig))

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("GetAvailableScopes_Success", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		checks.InitUser(context.Background(), db)
		c := NewAPIKeyController(db)

		e := echo.New()
		e.GET("/scopes", c.GetAvailableScopes, echojwt.WithConfig(jwtConfig))

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/scopes", nil)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var scopes []ScopeInfo
		dec := json.NewDecoder(resp.Body)
		err := dec.Decode(&scopes)
		assert.NoError(t, err)
		assert.NotEmpty(t, scopes)
		assert.GreaterOrEqual(t, len(scopes), 8) // Should have at least 8 predefined scopes

		// Verify structure
		for _, scope := range scopes {
			assert.NotEmpty(t, scope.Scope)
			assert.NotEmpty(t, scope.Resource)
			assert.NotEmpty(t, scope.Action)
			assert.NotEmpty(t, scope.Description)
			assert.Contains(t, scope.Scope, ":")
		}
	})

	t.Run("GetAPIKey_Success", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		scopesJSON := []byte(`["channels:read", "users:read"]`)

		db.On("GetAPIKey", mock.Anything, int32(1)).
			Return(models.ApiKey{
				ID:          1,
				Name:        "Test Key",
				Description: pgtype.Text{String: "Test description", Valid: true},
				Scopes:      scopesJSON,
				CreatedBy:   1,
				CreatedAt:   int32(time.Now().Unix()),
				LastUpdated: int32(time.Now().Unix()),
				Deleted:     pgtype.Int2{Int16: 0, Valid: true},
			}, nil)

		checks.InitUser(context.Background(), db)
		c := NewAPIKeyController(db)

		e := echo.New()
		e.GET("/:id", c.GetAPIKey, echojwt.WithConfig(jwtConfig))

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/1", nil)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response APIKeyResponse
		dec := json.NewDecoder(resp.Body)
		err := dec.Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, int32(1), response.ID)
		assert.Equal(t, "Test Key", response.Name)
		assert.Equal(t, "Test description", response.Description)
		assert.Len(t, response.Scopes, 2)
	})

	t.Run("GetAPIKey_NotFound", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		db.On("GetAPIKey", mock.Anything, int32(999)).
			Return(models.ApiKey{}, pgx.ErrNoRows)

		checks.InitUser(context.Background(), db)
		c := NewAPIKeyController(db)

		e := echo.New()
		e.GET("/:id", c.GetAPIKey, echojwt.WithConfig(jwtConfig))

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/999", nil)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("GetAPIKey_InvalidID", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		checks.InitUser(context.Background(), db)
		c := NewAPIKeyController(db)

		e := echo.New()
		e.GET("/:id", c.GetAPIKey, echojwt.WithConfig(jwtConfig))

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodGet, "/invalid", nil)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("UpdateAPIKeyScopes_Success", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		scopesJSON := []byte(`["channels:write", "users:write"]`)

		db.On("UpdateAPIKeyScopes", mock.Anything, mock.Anything).
			Return(nil)

		db.On("GetAPIKey", mock.Anything, int32(1)).
			Return(models.ApiKey{
				ID:          1,
				Name:        "Test Key",
				Description: pgtype.Text{String: "Test description", Valid: true},
				Scopes:      scopesJSON,
				CreatedBy:   1,
				CreatedAt:   int32(time.Now().Unix()),
				LastUpdated: int32(time.Now().Unix()),
				Deleted:     pgtype.Int2{Int16: 0, Valid: true},
			}, nil)

		checks.InitUser(context.Background(), db)
		c := NewAPIKeyController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.PUT("/:id/scopes", c.UpdateAPIKeyScopes, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(`{
			"scopes": ["channels:write", "users:write"]
		}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPut, "/1/scopes", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response APIKeyResponse
		dec := json.NewDecoder(resp.Body)
		err := dec.Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, int32(1), response.ID)
		assert.Len(t, response.Scopes, 2)
	})

	t.Run("UpdateAPIKeyScopes_InvalidScope", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		checks.InitUser(context.Background(), db)
		c := NewAPIKeyController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.PUT("/:id/scopes", c.UpdateAPIKeyScopes, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(`{
			"scopes": ["invalid:scope"]
		}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPut, "/1/scopes", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		errResp := new(apierrors.ErrorResponse)
		dec := json.NewDecoder(resp.Body)
		err := dec.Decode(&errResp)
		assert.NoError(t, err)
		assert.Contains(t, errResp.Error.Message, "scopes must contain only valid API scopes")
	})

	t.Run("UpdateAPIKeyScopes_EmptyScopes", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		checks.InitUser(context.Background(), db)
		c := NewAPIKeyController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.PUT("/:id/scopes", c.UpdateAPIKeyScopes, echojwt.WithConfig(jwtConfig))

		body := bytes.NewBufferString(`{
			"scopes": []
		}`)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPut, "/1/scopes", body)
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("DeleteAPIKey_Success", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		db.On("DeleteAPIKey", mock.Anything, int32(1), mock.AnythingOfType("int32")).
			Return(nil)

		checks.InitUser(context.Background(), db)
		c := NewAPIKeyController(db)

		e := echo.New()
		e.DELETE("/:id", c.DeleteAPIKey, echojwt.WithConfig(jwtConfig))

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodDelete, "/1", nil)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})

	t.Run("DeleteAPIKey_InvalidID", func(t *testing.T) {
		db := mocks.NewQuerier(t)
		checks.InitUser(context.Background(), db)
		c := NewAPIKeyController(db)

		e := echo.New()
		e.DELETE("/:id", c.DeleteAPIKey, echojwt.WithConfig(jwtConfig))

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodDelete, "/invalid", nil)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("DeleteAPIKey_NotFound", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		db.On("DeleteAPIKey", mock.Anything, int32(999), mock.AnythingOfType("int32")).
			Return(pgx.ErrNoRows)

		checks.InitUser(context.Background(), db)
		c := NewAPIKeyController(db)

		e := echo.New()
		e.DELETE("/:id", c.DeleteAPIKey, echojwt.WithConfig(jwtConfig))

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodDelete, "/999", nil)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("CreateAPIKey_InvalidCIDR", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		checks.InitUser(context.Background(), db)
		c := NewAPIKeyController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.POST("/", c.CreateAPIKey, echojwt.WithConfig(jwtConfig))

		// Create request with invalid CIDR notation
		reqBody := map[string]interface{}{
			"name":            "Test Key",
			"scopes":          []string{"users:read"},
			"ip_restrictions": []string{"not-a-valid-cidr"},
		}
		body, _ := json.Marshal(reqBody)

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var errorResp apierrors.ErrorResponse
		err := json.NewDecoder(resp.Body).Decode(&errorResp)
		assert.NoError(t, err)
		assert.Contains(t, errorResp.Error.Message, "ip_restrictions")
		assert.Contains(t, errorResp.Error.Message, "CIDR")
	})

	t.Run("UpdateAPIKeyIPRestrictions_InvalidCIDR", func(t *testing.T) {
		db := mocks.NewQuerier(t)

		checks.InitUser(context.Background(), db)
		c := NewAPIKeyController(db)

		e := echo.New()
		e.Validator = helper.NewValidator()
		e.PUT("/:id/ip-restrictions", c.UpdateAPIKeyIPRestrictions, echojwt.WithConfig(jwtConfig))

		// Create request with invalid CIDR notation
		reqBody := map[string]interface{}{
			"ip_restrictions": []string{"192.168.1.0", "invalid"}, // Missing /prefix
		}
		body, _ := json.Marshal(reqBody)

		w := httptest.NewRecorder()
		r, _ := http.NewRequest(http.MethodPut, "/1/ip-restrictions", bytes.NewReader(body))
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		r.Header.Set(echo.HeaderAuthorization, "Bearer "+tokens.AccessToken)

		e.ServeHTTP(w, r)
		resp := w.Result()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var errorResp apierrors.ErrorResponse
		err := json.NewDecoder(resp.Body).Decode(&errorResp)
		assert.NoError(t, err)
		assert.Contains(t, errorResp.Error.Message, "ip_restrictions")
		assert.Contains(t, errorResp.Error.Message, "CIDR")
	})
}
