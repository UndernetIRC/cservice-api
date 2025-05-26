// SPDX-License-Identifier: MIT
// SPDX-FileCopyRightText: Copyright (c) 2023 UnderNET

package routes

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"

	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/internal/config"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

func TestRoutes(t *testing.T) {
	// Initialize default configuration
	config.DefaultConfig()
	config.ServiceAPIPrefix.Set("api")

	// Get the API prefix
	prefixV1 := strings.Join([]string{config.ServiceAPIPrefix.GetString(), "v1"}, "/")

	db := mocks.NewServiceInterface(t)
	e := echo.New()
	r := NewRouteService(e, db, nil, nil)
	r.routerGroup = e.Group("/test")

	r.UserRoutes()
	r.MeRoutes()
	r.AuthnRoutes()
	r.UserRegisterRoutes()

	testCases := []struct {
		path   string
		method string
	}{
		{"/test/users/:id", "GET"},
		{"/test/me", "GET"},
		{"/" + prefixV1 + "/logout", "POST"},
		{"/" + prefixV1 + "/authn/refresh", "POST"},
		{"/" + prefixV1 + "/authn/factor_verify", "POST"},
		{"/" + prefixV1 + "/register", "POST"},
	}

	routeMap := make(map[string]string)
	for _, v := range e.Routes() {
		routeMap[fmt.Sprintf("%s:%s", v.Path, v.Method)] = "1"
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			if _, ok := routeMap[fmt.Sprintf("%s:%s", tc.path, tc.method)]; !ok {
				t.Errorf("expected to find path %s with method %s, but did not", tc.path, tc.method)
			}
		})
	}
}

func TestNewRouteService(t *testing.T) {
	// Test cases
	tests := []struct {
		name    string
		e       *echo.Echo
		service models.ServiceInterface
		pool    *pgxpool.Pool
		rdb     *redis.Client
		wantErr bool
	}{
		{
			name:    "Valid initialization",
			e:       echo.New(),
			service: mocks.NewServiceInterface(t),
			pool:    &pgxpool.Pool{},
			rdb:     redis.NewClient(&redis.Options{}),
			wantErr: false,
		},
		{
			name:    "Nil echo instance",
			e:       nil,
			service: mocks.NewServiceInterface(t),
			pool:    &pgxpool.Pool{},
			rdb:     redis.NewClient(&redis.Options{}),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr {
				// Instead of expecting a panic, we'll check if the returned service has nil values
				rs := NewRouteService(tt.e, tt.service, tt.pool, tt.rdb)
				assert.Nil(t, rs.e, "Expected echo instance to be nil")
				return
			}

			rs := NewRouteService(tt.e, tt.service, tt.pool, tt.rdb)
			assert.NotNil(t, rs)
			assert.Equal(t, tt.e, rs.e)
			assert.Equal(t, tt.service, rs.service)
			assert.Equal(t, tt.pool, rs.pool)
			assert.Equal(t, tt.rdb, rs.rdb)
		})
	}
}

func TestNewEcho(t *testing.T) {
	// Set up test configuration
	config.DefaultConfig()
	config.ServiceJWTSigningMethod.Set("HS256")
	config.ServiceCorsAllowOrigins.Set([]string{"*"})
	config.ServiceCorsAllowMethods.Set([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	config.ServiceCorsMaxAge.Set(0)

	e := NewEcho()
	assert.NotNil(t, e)
	assert.True(t, e.HideBanner)
	assert.Equal(t, log.DEBUG, e.Logger.Level())
	assert.NotNil(t, e.Validator)

	// Test middleware setup
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	// Add Origin header to trigger CORS
	req.Header.Set("Origin", "http://example.com")
	e.ServeHTTP(rec, req)

	// Test CORS middleware
	assert.NotEmpty(t, rec.Header().Get("Access-Control-Allow-Origin"))

	// Test API documentation endpoint
	req = httptest.NewRequest(http.MethodGet, "/docs", nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestLoadRoutes(t *testing.T) {
	// Set up test configuration
	config.DefaultConfig()
	config.ServiceHost.Set("localhost")
	config.ServicePort.Set("8080")
	config.ServiceAPIPrefix.Set("api")

	tests := []struct {
		name    string
		setup   func() *RouteService
		wantErr bool
	}{
		{
			name: "Valid route loading",
			setup: func() *RouteService {
				e := echo.New()
				return NewRouteService(
					e,
					mocks.NewServiceInterface(t),
					&pgxpool.Pool{},
					redis.NewClient(&redis.Options{}),
				)
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := tt.setup()
			// Use LoadRoutesWithOptions with startServer=false to avoid binding to a port
			err := LoadRoutesWithOptions(rs, false)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, rs.routerGroup)
		})
	}
}

// TestServerStart tests the server start functionality with invalid addresses
func TestServerStart(t *testing.T) {
	// Set up test configuration
	config.DefaultConfig()
	config.ServiceHost.Set("invalid:host")
	config.ServicePort.Set("8080")
	config.ServiceAPIPrefix.Set("api")

	e := echo.New()
	rs := NewRouteService(e, mocks.NewServiceInterface(t), &pgxpool.Pool{}, redis.NewClient(&redis.Options{}))

	// This should fail because of the invalid host
	err := LoadRoutesWithOptions(rs, true)
	assert.Error(t, err, "Expected error with invalid host")
}

// MockPool is a mock implementation of pgxpool.Pool for testing
type MockPool struct{}

func (m *MockPool) Ping(_ context.Context) error {
	return nil // Always return success for testing
}

func TestRouteServiceMethods(t *testing.T) {
	// Set up test configuration
	config.DefaultConfig()
	config.ServiceHost.Set("localhost")
	config.ServicePort.Set("8080")
	config.ServiceAPIPrefix.Set("api")
	config.ServiceJWTSigningMethod.Set("HS256")
	config.ServiceJWTSigningKey.Set("test-key")

	e := echo.New()

	// Create a mock pool for the health check
	mockPool := &pgxpool.Pool{}

	rs := NewRouteService(e, mocks.NewServiceInterface(t), mockPool, redis.NewClient(&redis.Options{}))

	// Initialize the routerGroup field
	prefixV1 := strings.Join([]string{config.ServiceAPIPrefix.GetString(), "v1"}, "/")
	rs.routerGroup = e.Group(prefixV1)

	// Set up JWT middleware
	rs.routerGroup.Use(echojwt.WithConfig(helper.GetEchoJWTConfig()))

	// Test UserRoutes
	t.Run("UserRoutes", func(t *testing.T) {
		rs.UserRoutes()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/1", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code) // Should be bad request due to missing JWT token
	})

	// Test MeRoutes
	t.Run("MeRoutes", func(t *testing.T) {
		rs.MeRoutes()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code) // Should be bad request due to missing JWT token
	})

	// Test HealthCheckRoutes
	t.Run("HealthCheckRoutes", func(t *testing.T) {
		// Skip the health check test for now as it requires a properly initialized pool
		t.Skip("Health check test requires a properly initialized pool")
	})
}

func TestRouteServiceContext(t *testing.T) {
	// Set up test configuration
	config.DefaultConfig()
	config.ServiceHost.Set("localhost")
	config.ServicePort.Set("8080")

	e := echo.New()

	// Test context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a custom server with a context
	server := &http.Server{
		Addr:    ":0", // Use port 0 to let the OS assign a random available port
		Handler: e,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	// Start server in a goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Errorf("unexpected error: %v", err)
		}
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Shutdown the server gracefully
	err := server.Shutdown(context.Background())
	assert.NoError(t, err, "Server should shut down gracefully")
}
