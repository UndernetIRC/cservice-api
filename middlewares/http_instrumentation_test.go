// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package middlewares

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

func TestHTTPInstrumentation(t *testing.T) {
	// Create a test meter provider
	res := resource.NewWithAttributes("test")
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
	)
	meter := meterProvider.Meter("test-meter")

	// Create Echo instance
	e := echo.New()

	// Add the HTTP instrumentation middleware
	e.Use(HTTPInstrumentation(meter))

	// Add a test route
	e.GET("/test", func(c echo.Context) error {
		time.Sleep(10 * time.Millisecond) // Simulate some processing time
		return c.String(http.StatusOK, "test response")
	})

	e.POST("/test-post", func(c echo.Context) error {
		return c.String(http.StatusCreated, "created")
	})

	e.GET("/test-error", func(c echo.Context) error {
		return c.String(http.StatusInternalServerError, "error")
	})

	// Test successful GET request
	t.Run("successful GET request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "test response", rec.Body.String())
	})

	// Test POST request with body
	t.Run("POST request with body", func(t *testing.T) {
		body := strings.NewReader(`{"test": "data"}`)
		req := httptest.NewRequest(http.MethodPost, "/test-post", body)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code)
		assert.Equal(t, "created", rec.Body.String())
	})

	// Test error response
	t.Run("error response", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test-error", nil)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Equal(t, "error", rec.Body.String())
	})

	// Test 404 response
	t.Run("404 response", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
		rec := httptest.NewRecorder()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestHTTPInstrumentationWithConfig(t *testing.T) {
	// Create a test meter provider
	res := resource.NewWithAttributes("test")
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
	)
	meter := meterProvider.Meter("test-meter")

	// Test with custom config
	t.Run("custom config", func(t *testing.T) {
		e := echo.New()

		config := HTTPInstrumentationConfig{
			Meter:       meter,
			ServiceName: "test-service",
			Skipper: func(c echo.Context) bool {
				return c.Path() == "/skip"
			},
		}

		e.Use(HTTPInstrumentationWithConfig(config))

		e.GET("/test", func(c echo.Context) error {
			return c.String(http.StatusOK, "test")
		})

		e.GET("/skip", func(c echo.Context) error {
			return c.String(http.StatusOK, "skipped")
		})

		// Test normal request
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		// Test skipped request
		req = httptest.NewRequest(http.MethodGet, "/skip", nil)
		rec = httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	// Test with nil meter (should not panic)
	t.Run("nil meter", func(t *testing.T) {
		e := echo.New()

		config := HTTPInstrumentationConfig{
			Meter:       nil,
			ServiceName: "test-service",
		}

		// This should not panic and should return a no-op middleware
		middleware := HTTPInstrumentationWithConfig(config)
		e.Use(middleware)

		e.GET("/test", func(c echo.Context) error {
			return c.String(http.StatusOK, "test")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestCreateHTTPInstruments(t *testing.T) {
	// Create a test meter provider
	res := resource.NewWithAttributes("test")
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
	)
	meter := meterProvider.Meter("test-meter")

	t.Run("successful creation", func(t *testing.T) {
		instruments, err := createHTTPInstruments(meter)
		require.NoError(t, err)
		require.NotNil(t, instruments)

		assert.NotNil(t, instruments.requestDuration)
		assert.NotNil(t, instruments.requestCounter)
		assert.NotNil(t, instruments.requestSize)
		assert.NotNil(t, instruments.responseSize)
		assert.NotNil(t, instruments.activeRequests)
	})

	t.Run("nil meter", func(t *testing.T) {
		instruments, err := createHTTPInstruments(nil)
		assert.Error(t, err)
		assert.Nil(t, instruments)
	})
}

func TestGetStatusClass(t *testing.T) {
	tests := []struct {
		status   int
		expected string
	}{
		{100, "1xx"},
		{199, "1xx"},
		{200, "2xx"},
		{299, "2xx"},
		{300, "3xx"},
		{399, "3xx"},
		{400, "4xx"},
		{499, "4xx"},
		{500, "5xx"},
		{599, "5xx"},
		{99, "unknown"},
		{600, "unknown"},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.status)), func(t *testing.T) {
			result := getStatusClass(tt.status)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func BenchmarkHTTPInstrumentation(b *testing.B) {
	// Create a test meter provider
	res := resource.NewWithAttributes("test")
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
	)
	meter := meterProvider.Meter("test-meter")

	// Create Echo instance
	e := echo.New()
	e.Use(HTTPInstrumentation(meter))

	e.GET("/test", func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
	}
}
