//go:build integration

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/undernetirc/cservice-api/controllers"
	"github.com/undernetirc/cservice-api/controllers/admin"
	"github.com/undernetirc/cservice-api/internal/checks"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
	"github.com/undernetirc/cservice-api/routes"
)

// TestAPIKeyIntegration tests the complete API key workflow:
// 1. Login as Admin user to get JWT token
// 2. Create an API key with users:read scope
// 3. Use the API key to retrieve user information
func TestAPIKeyIntegration(t *testing.T) {
	config.DefaultConfig()

	service := models.NewService(db)
	checks.InitUser(context.Background(), db)

	// Step 1: Login as Admin to get JWT token
	authController := controllers.NewAuthenticationController(service, rdb, nil)

	e := echo.New()
	e.Validator = helper.NewValidator()
	e.POST("/login", authController.Login)

	w := httptest.NewRecorder()
	loginBody := bytes.NewBufferString(`{"username": "Admin", "password":"temPass2020@"}`)
	r, _ := http.NewRequest("POST", "/login", loginBody)
	r.Header.Set("Content-Type", "application/json")

	e.ServeHTTP(w, r)

	resp := w.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode, "Admin login should succeed")

	loginResponse := new(controllers.LoginResponse)
	err := json.NewDecoder(resp.Body).Decode(loginResponse)
	require.NoError(t, err, "Should decode login response")
	require.NotEmpty(t, loginResponse.AccessToken, "Access token should not be empty")

	adminToken := loginResponse.AccessToken

	// Step 2: Create an API key with users:read scope using Admin JWT token
	// Setup full route service for proper authentication middleware
	e2 := routes.NewEcho()
	routeService := routes.NewRouteService(e2, service, dbPool, rdb)
	err = routes.LoadRoutesWithOptions(routeService, false)
	require.NoError(t, err, "Should load routes")

	// Create API key
	w2 := httptest.NewRecorder()
	createAPIKeyBody := bytes.NewBufferString(`{
		"name": "Integration Test Key",
		"description": "API key for integration testing",
		"scopes": ["users:read"]
	}`)
	r2, _ := http.NewRequest("POST", "/api/v1/admin/api-keys", createAPIKeyBody)
	r2.Header.Set("Content-Type", "application/json")
	r2.Header.Set("Authorization", "Bearer "+adminToken)

	e2.ServeHTTP(w2, r2)

	resp2 := w2.Result()
	require.Equal(t, http.StatusCreated, resp2.StatusCode, "API key creation should succeed")

	createAPIKeyResponse := new(admin.CreateAPIKeyResponse)
	err = json.NewDecoder(resp2.Body).Decode(createAPIKeyResponse)
	require.NoError(t, err, "Should decode create API key response")
	require.NotEmpty(t, createAPIKeyResponse.Key, "API key should not be empty")
	require.Contains(t, createAPIKeyResponse.Key, "cserv_", "API key should have correct prefix")
	require.Equal(t, "Integration Test Key", createAPIKeyResponse.Name)
	require.Contains(t, createAPIKeyResponse.Scopes, "users:read")

	apiKey := createAPIKeyResponse.Key

	// Step 3: Use the API key to retrieve user ID 1 via /users/1 endpoint
	w3 := httptest.NewRecorder()
	r3, _ := http.NewRequest("GET", "/api/v1/users/1", nil)
	r3.Header.Set("X-API-Key", apiKey)

	e2.ServeHTTP(w3, r3)

	resp3 := w3.Result()
	assert.Equal(t, http.StatusOK, resp3.StatusCode, "API key should successfully authenticate and retrieve user")

	userResponse := new(controllers.UserResponse)
	err = json.NewDecoder(resp3.Body).Decode(userResponse)
	require.NoError(t, err, "Should decode user response")
	assert.Equal(t, "Admin", userResponse.Username, "Should retrieve Admin user")
	assert.Equal(t, int32(1), userResponse.ID, "Should retrieve user ID 1")
}

// TestAPIKeyIntegration_InvalidScope tests that an API key without the correct scope is denied
func TestAPIKeyIntegration_InvalidScope(t *testing.T) {
	config.DefaultConfig()

	service := models.NewService(db)
	checks.InitUser(context.Background(), db)

	// Step 1: Login as Admin
	authController := controllers.NewAuthenticationController(service, rdb, nil)

	e := echo.New()
	e.Validator = helper.NewValidator()
	e.POST("/login", authController.Login)

	w := httptest.NewRecorder()
	loginBody := bytes.NewBufferString(`{"username": "Admin", "password":"temPass2020@"}`)
	r, _ := http.NewRequest("POST", "/login", loginBody)
	r.Header.Set("Content-Type", "application/json")

	e.ServeHTTP(w, r)

	resp := w.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	loginResponse := new(controllers.LoginResponse)
	err := json.NewDecoder(resp.Body).Decode(loginResponse)
	require.NoError(t, err)

	adminToken := loginResponse.AccessToken

	// Step 2: Create an API key with channels:read scope (NOT users:read)
	e2 := routes.NewEcho()
	routeService := routes.NewRouteService(e2, service, dbPool, rdb)
	err = routes.LoadRoutesWithOptions(routeService, false)
	require.NoError(t, err)

	w2 := httptest.NewRecorder()
	createAPIKeyBody := bytes.NewBufferString(`{
		"name": "Wrong Scope Key",
		"description": "API key with wrong scope",
		"scopes": ["channels:read"]
	}`)
	r2, _ := http.NewRequest("POST", "/api/v1/admin/api-keys", createAPIKeyBody)
	r2.Header.Set("Content-Type", "application/json")
	r2.Header.Set("Authorization", "Bearer "+adminToken)

	e2.ServeHTTP(w2, r2)

	resp2 := w2.Result()
	require.Equal(t, http.StatusCreated, resp2.StatusCode)

	createAPIKeyResponse := new(admin.CreateAPIKeyResponse)
	err = json.NewDecoder(resp2.Body).Decode(createAPIKeyResponse)
	require.NoError(t, err)

	apiKey := createAPIKeyResponse.Key

	// Step 3: Try to use the API key to retrieve user ID 1 (should fail - wrong scope)
	w3 := httptest.NewRecorder()
	r3, _ := http.NewRequest("GET", "/api/v1/users/1", nil)
	r3.Header.Set("X-API-Key", apiKey)

	e2.ServeHTTP(w3, r3)

	resp3 := w3.Result()
	assert.Equal(t, http.StatusForbidden, resp3.StatusCode, "API key without users:read scope should be denied")
}

// TestAPIKeyIntegration_ListScopes tests that any authenticated user can list available scopes
func TestAPIKeyIntegration_ListScopes(t *testing.T) {
	config.DefaultConfig()

	service := models.NewService(db)
	checks.InitUser(context.Background(), db)

	// Login as Admin
	authController := controllers.NewAuthenticationController(service, rdb, nil)

	e := echo.New()
	e.Validator = helper.NewValidator()
	e.POST("/login", authController.Login)

	w := httptest.NewRecorder()
	loginBody := bytes.NewBufferString(`{"username": "Admin", "password":"temPass2020@"}`)
	r, _ := http.NewRequest("POST", "/login", loginBody)
	r.Header.Set("Content-Type", "application/json")

	e.ServeHTTP(w, r)

	resp := w.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	loginResponse := new(controllers.LoginResponse)
	err := json.NewDecoder(resp.Body).Decode(loginResponse)
	require.NoError(t, err)

	adminToken := loginResponse.AccessToken

	// List available scopes
	e2 := routes.NewEcho()
	routeService := routes.NewRouteService(e2, service, dbPool, rdb)
	err = routes.LoadRoutesWithOptions(routeService, false)
	require.NoError(t, err)

	w2 := httptest.NewRecorder()
	r2, _ := http.NewRequest("GET", "/api/v1/admin/api-keys/scopes", nil)
	r2.Header.Set("Authorization", "Bearer "+adminToken)

	e2.ServeHTTP(w2, r2)

	resp2 := w2.Result()
	assert.Equal(t, http.StatusOK, resp2.StatusCode, "Listing scopes should succeed")

	var scopes []admin.ScopeInfo
	err = json.NewDecoder(resp2.Body).Decode(&scopes)
	require.NoError(t, err)
	assert.NotEmpty(t, scopes, "Should return available scopes")
	assert.GreaterOrEqual(t, len(scopes), 8, "Should have at least 8 scopes")

	// Verify scope structure
	foundUsersRead := false
	for _, scope := range scopes {
		assert.NotEmpty(t, scope.Scope)
		assert.NotEmpty(t, scope.Resource)
		assert.NotEmpty(t, scope.Action)
		assert.NotEmpty(t, scope.Description)

		if scope.Scope == "users:read" {
			foundUsersRead = true
			assert.Equal(t, "users", scope.Resource)
			assert.Equal(t, "read", scope.Action)
		}
	}
	assert.True(t, foundUsersRead, "Should include users:read scope")
}
