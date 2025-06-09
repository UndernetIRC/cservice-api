// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package telemetry

import (
	"context"
	"testing"
	"time"
)

func TestNewProvider_Disabled(t *testing.T) {
	config := &Config{
		Enabled: false,
	}

	provider, err := NewProvider(context.Background(), config)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if provider == nil {
		t.Fatal("Expected provider to not be nil")
	}

	if provider.IsEnabled() {
		t.Error("Expected provider to be disabled")
	}
}

func TestNewProvider_NilConfig(t *testing.T) {
	_, err := NewProvider(context.Background(), nil)
	if err == nil {
		t.Fatal("Expected error for nil config")
	}
}

func TestNewProvider_EnabledWithMinimalConfig(t *testing.T) {
	config := &Config{
		Enabled:            true,
		ServiceName:        "test-service",
		ServiceVersion:     "1.0.0",
		TracingEnabled:     false,
		MetricsEnabled:     false,
		TracingSampleRate:  0.1,
		MetricsInterval:    30,
		ResourceAttributes: make(map[string]string),
		OTLPHeaders:        make(map[string]string),
	}

	provider, err := NewProvider(context.Background(), config)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !provider.IsEnabled() {
		t.Error("Expected provider to be enabled")
	}

	// Test shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = provider.Shutdown(ctx)
	if err != nil {
		t.Errorf("Expected no error during shutdown, got %v", err)
	}
}

func TestProvider_GetTracer(t *testing.T) {
	config := &Config{
		Enabled:        false,
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
	}

	provider, err := NewProvider(context.Background(), config)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	tracer := provider.GetTracer("test-tracer")
	if tracer == nil {
		t.Error("Expected tracer to not be nil")
	}
}

func TestProvider_GetMeter(t *testing.T) {
	config := &Config{
		Enabled:        false,
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
	}

	provider, err := NewProvider(context.Background(), config)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	meter := provider.GetMeter("test-meter")
	if meter == nil {
		t.Error("Expected meter to not be nil")
	}
}

func TestWithShutdownTimeout(t *testing.T) {
	timeout := 5 * time.Second
	ctx, cancel := WithShutdownTimeout(context.Background(), timeout)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Error("Expected context to have deadline")
	}

	if time.Until(deadline) > timeout {
		t.Error("Expected deadline to be within timeout")
	}
}

func TestValidateExporterConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "disabled config",
			config: &Config{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "enabled with prometheus",
			config: &Config{
				Enabled:           true,
				PrometheusEnabled: true,
				TracingSampleRate: 0.5,
				MetricsInterval:   30,
			},
			wantErr: false,
		},
		{
			name: "enabled with OTLP",
			config: &Config{
				Enabled:           true,
				OTLPEndpoint:      "http://localhost:4318",
				TracingSampleRate: 0.5,
				MetricsInterval:   30,
			},
			wantErr: false,
		},
		{
			name: "enabled without exporters",
			config: &Config{
				Enabled:           true,
				TracingSampleRate: 0.5,
				MetricsInterval:   30,
			},
			wantErr: true,
		},
		{
			name: "invalid sample rate",
			config: &Config{
				Enabled:           true,
				PrometheusEnabled: true,
				TracingSampleRate: 1.5,
				MetricsInterval:   30,
			},
			wantErr: true,
		},
		{
			name: "invalid metrics interval",
			config: &Config{
				Enabled:           true,
				PrometheusEnabled: true,
				TracingSampleRate: 0.5,
				MetricsInterval:   -1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateExporterConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateExporterConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
