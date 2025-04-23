// SPDX-License-Identifier: MIT
// SPDX-FileCopyRightText: Copyright (c) 2023 UnderNET

package routes

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"

	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
)

func TestAuthenticationRoutes(t *testing.T) {
	// Set up configuration
	config.DefaultConfig()
	config.ServiceAPIPrefix.Set("api")

	// Get the API prefix for correct path construction
	prefixV1 := strings.Join([]string{config.ServiceAPIPrefix.GetString(), "v1"}, "/")

	// Create a new echo instance
	e := echo.New()
	e.Validator = helper.NewValidator()

	// Use nil Redis client to trigger fallback mode
	var rdb *redis.Client

	// Create a route service
	db := mocks.NewQuerier(t)
	r := NewRouteService(e, db, nil, rdb)

	// Load authentication routes
	r.AuthnRoutes()

	// Test cases for the actual endpoints
	tests := []struct {
		name         string
		path         string
		method       string
		expectedCode int
	}{
		{
			name:         "Login endpoint",
			path:         "/" + prefixV1 + "/login",
			method:       http.MethodPost,
			expectedCode: http.StatusBadRequest, // Expected without valid request body
		},
		{
			name:         "Factor verify endpoint",
			path:         "/" + prefixV1 + "/authn/factor_verify",
			method:       http.MethodPost,
			expectedCode: http.StatusBadRequest, // Expected without valid request body
		},
		{
			name:         "Register endpoint",
			path:         "/" + prefixV1 + "/register",
			method:       http.MethodPost,
			expectedCode: http.StatusBadRequest, // Expected without valid request body
		},
	}

	// Run endpoint tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			// Serve the request
			e.ServeHTTP(rec, req)

			// Assert the response code
			assert.Equal(t, tc.expectedCode, rec.Code)
		})
	}
}
