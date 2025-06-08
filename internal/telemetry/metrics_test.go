// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

func TestNewMetricsHandler_Disabled(t *testing.T) {
	config := &Config{
		Enabled:           false,
		PrometheusEnabled: false,
	}
	provider := &Provider{config: config}

	_, err := NewMetricsHandler(provider, config)
	if err == nil {
		t.Error("Expected error when prometheus is disabled")
	}
}

func TestNewMetricsHandler_Enabled(t *testing.T) {
	config := &Config{
		Enabled:            true,
		PrometheusEnabled:  true,
		ServiceName:        "test-service",
		ServiceVersion:     "1.0.0",
		ResourceAttributes: make(map[string]string),
	}

	// Create a simple provider with resource
	provider := &Provider{config: config}
	res, err := provider.createResource(context.Background())
	if err != nil {
		t.Fatalf("Failed to create resource: %v", err)
	}
	provider.resource = res

	handler, err := NewMetricsHandler(provider, config)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if handler == nil {
		t.Error("Expected handler to not be nil")
		return
	}

	if handler.registry == nil {
		t.Error("Expected registry to not be nil")
	}

	if handler.meter == nil {
		t.Error("Expected meter to not be nil")
	}
}

func TestMetricsHandler_HTTPHandler(t *testing.T) {
	config := &Config{
		Enabled:            true,
		PrometheusEnabled:  true,
		ServiceName:        "test-service",
		ServiceVersion:     "1.0.0",
		ResourceAttributes: make(map[string]string),
	}

	provider := &Provider{config: config}
	res, err := provider.createResource(context.Background())
	if err != nil {
		t.Fatalf("Failed to create resource: %v", err)
	}
	provider.resource = res

	handler, err := NewMetricsHandler(provider, config)
	if err != nil {
		t.Fatalf("Failed to create metrics handler: %v", err)
	}

	// Test HTTP handler
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	httpHandler := handler.Handler()
	httpHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "# HELP") {
		t.Error("Expected Prometheus format output")
	}

	// Check for Go metrics (should be present)
	if !strings.Contains(body, "go_") {
		t.Error("Expected Go runtime metrics")
	}
}

func TestMetricsHandler_EchoHandler(t *testing.T) {
	config := &Config{
		Enabled:            true,
		PrometheusEnabled:  true,
		ServiceName:        "test-service",
		ServiceVersion:     "1.0.0",
		ResourceAttributes: make(map[string]string),
	}

	provider := &Provider{config: config}
	res, err := provider.createResource(context.Background())
	if err != nil {
		t.Fatalf("Failed to create resource: %v", err)
	}
	provider.resource = res

	handler, err := NewMetricsHandler(provider, config)
	if err != nil {
		t.Fatalf("Failed to create metrics handler: %v", err)
	}

	// Test Echo handler
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	echoHandler := handler.EchoHandler()
	err = echoHandler(c)
	if err != nil {
		t.Fatalf("Echo handler returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestRegisterMetricsEndpoint_Disabled(t *testing.T) {
	config := &Config{
		Enabled:           false,
		PrometheusEnabled: false,
	}
	provider := &Provider{config: config}

	e := echo.New()
	err := RegisterMetricsEndpoint(e, provider, config)
	if err != nil {
		t.Errorf("Expected no error when disabled, got %v", err)
	}
}

func TestRegisterMetricsEndpoint_Enabled(t *testing.T) {
	config := &Config{
		Enabled:            true,
		PrometheusEnabled:  true,
		PrometheusEndpoint: "/metrics",
		ServiceName:        "test-service",
		ServiceVersion:     "1.0.0",
		ResourceAttributes: make(map[string]string),
	}

	provider := &Provider{config: config}
	res, err := provider.createResource(context.Background())
	if err != nil {
		t.Fatalf("Failed to create resource: %v", err)
	}
	provider.resource = res

	e := echo.New()
	err = RegisterMetricsEndpoint(e, provider, config)
	if err != nil {
		t.Fatalf("Failed to register metrics endpoint: %v", err)
	}

	// Test that the endpoint was registered by making a request
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestNewHealthMetrics(t *testing.T) {
	config := &Config{
		Enabled:            true,
		PrometheusEnabled:  true,
		ServiceName:        "test-service",
		ServiceVersion:     "1.0.0",
		ResourceAttributes: make(map[string]string),
	}

	provider := &Provider{config: config}
	res, err := provider.createResource(context.Background())
	if err != nil {
		t.Fatalf("Failed to create resource: %v", err)
	}
	provider.resource = res

	handler, err := NewMetricsHandler(provider, config)
	if err != nil {
		t.Fatalf("Failed to create metrics handler: %v", err)
	}

	healthMetrics, err := NewHealthMetrics(handler.meter, "test-service", "1.0.0")
	if err != nil {
		t.Fatalf("Failed to create health metrics: %v", err)
	}

	if healthMetrics == nil {
		t.Error("Expected health metrics to not be nil")
		return
	}

	// Test recording a health check
	ctx := context.Background()
	healthMetrics.RecordHealthCheck(ctx, "healthy")

	// Verify start time is set
	if healthMetrics.startTime.IsZero() {
		t.Error("Expected start time to be set")
	}

	// Verify uptime is reasonable
	uptime := time.Since(healthMetrics.startTime)
	if uptime < 0 || uptime > time.Second {
		t.Errorf("Expected reasonable uptime, got %v", uptime)
	}
}

func TestMetricsPerformance(t *testing.T) {
	config := &Config{
		Enabled:            true,
		PrometheusEnabled:  true,
		ServiceName:        "test-service",
		ServiceVersion:     "1.0.0",
		ResourceAttributes: make(map[string]string),
	}

	provider := &Provider{config: config}
	res, err := provider.createResource(context.Background())
	if err != nil {
		t.Fatalf("Failed to create resource: %v", err)
	}
	provider.resource = res

	handler, err := NewMetricsHandler(provider, config)
	if err != nil {
		t.Fatalf("Failed to create metrics handler: %v", err)
	}

	// Test that metrics endpoint responds within 100ms
	start := time.Now()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	httpHandler := handler.Handler()
	httpHandler.ServeHTTP(rec, req)

	duration := time.Since(start)
	if duration > 100*time.Millisecond {
		t.Errorf("Metrics endpoint took too long: %v", duration)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}
