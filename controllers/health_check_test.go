// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockPgxPool is a mock implementation of DBInterface
type MockPgxPool struct {
	mock.Mock
}

func (m *MockPgxPool) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// MockRedisClient is a mock implementation of RedisInterface
type MockRedisClient struct {
	mock.Mock
}

func (m *MockRedisClient) Ping(ctx context.Context) *redis.StatusCmd {
	args := m.Called(ctx)
	cmd := redis.NewStatusCmd(ctx)
	if args.Error(0) != nil {
		cmd.SetErr(args.Error(0))
	} else {
		cmd.SetVal("PONG")
	}
	return cmd
}

// Create a test controller with mock dependencies
func createTestController() (*HealthCheckController, *MockPgxPool, *MockRedisClient) {
	mockDB := new(MockPgxPool)
	mockRedis := new(MockRedisClient)

	// Create a controller with the mock dependencies
	controller := &HealthCheckController{
		dbPool: mockDB,
		rdb:    mockRedis,
	}

	return controller, mockDB, mockRedis
}

func TestHealthCheck_AllServicesUp(t *testing.T) {
	// Setup
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	controller, mockDB, mockRedis := createTestController()

	// Set expectations
	mockDB.On("Ping", mock.Anything).Return(nil)
	mockRedis.On("Ping", mock.Anything).Return(nil)

	// Execute
	err := controller.HealthCheck(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"status":"OK"`)
	assert.Contains(t, rec.Body.String(), `"postgres":"UP"`)
	assert.Contains(t, rec.Body.String(), `"redis":"UP"`)

	mockDB.AssertExpectations(t)
	mockRedis.AssertExpectations(t)
}

func TestHealthCheck_PostgresDown(t *testing.T) {
	// Setup
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	controller, mockDB, mockRedis := createTestController()

	// Set expectations
	mockDB.On("Ping", mock.Anything).Return(errors.New("connection refused"))
	mockRedis.On("Ping", mock.Anything).Return(nil)

	// Execute
	err := controller.HealthCheck(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"status":"DEGRADED"`)
	assert.Contains(t, rec.Body.String(), `"postgres":"DOWN"`)
	assert.Contains(t, rec.Body.String(), `"redis":"UP"`)

	mockDB.AssertExpectations(t)
	mockRedis.AssertExpectations(t)
}

func TestHealthCheck_RedisDown(t *testing.T) {
	// Setup
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	controller, mockDB, mockRedis := createTestController()

	// Set expectations
	mockDB.On("Ping", mock.Anything).Return(nil)
	mockRedis.On("Ping", mock.Anything).Return(errors.New("connection refused"))

	// Execute
	err := controller.HealthCheck(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"status":"DEGRADED"`)
	assert.Contains(t, rec.Body.String(), `"postgres":"UP"`)
	assert.Contains(t, rec.Body.String(), `"redis":"DOWN"`)

	mockDB.AssertExpectations(t)
	mockRedis.AssertExpectations(t)
}

func TestHealthCheck_BothServicesDown(t *testing.T) {
	// Setup
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	controller, mockDB, mockRedis := createTestController()

	// Set expectations
	mockDB.On("Ping", mock.Anything).Return(errors.New("connection refused"))
	mockRedis.On("Ping", mock.Anything).Return(errors.New("connection refused"))

	// Execute
	err := controller.HealthCheck(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"status":"DEGRADED"`)
	assert.Contains(t, rec.Body.String(), `"postgres":"DOWN"`)
	assert.Contains(t, rec.Body.String(), `"redis":"DOWN"`)

	mockDB.AssertExpectations(t)
	mockRedis.AssertExpectations(t)
}
