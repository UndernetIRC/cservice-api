// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

package telemetry

import (
	"context"
	"fmt"
	"log"
	"time"
)

// DefaultShutdownTimeout is the default timeout for telemetry shutdown
const DefaultShutdownTimeout = 10 * time.Second

// Initialize sets up OpenTelemetry with the provided configuration
func Initialize(ctx context.Context) (*Provider, error) {
	// Load configuration from Viper
	cfg, err := LoadConfigFromViper()
	if err != nil {
		return nil, fmt.Errorf("failed to load telemetry configuration: %w", err)
	}

	// Log telemetry initialization
	if cfg.Enabled {
		log.Printf("Initializing OpenTelemetry: service=%s version=%s tracing=%v metrics=%v sample_rate=%f",
			cfg.ServiceName, cfg.ServiceVersion, cfg.TracingEnabled, cfg.MetricsEnabled, cfg.TracingSampleRate)
	} else {
		log.Printf("OpenTelemetry is disabled")
	}

	// Create provider
	provider, err := NewProvider(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create telemetry provider: %w", err)
	}

	return provider, nil
}

// MustInitialize initializes telemetry and panics on error
func MustInitialize(ctx context.Context) *Provider {
	provider, err := Initialize(ctx)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize telemetry: %v", err))
	}
	return provider
}

// InitializeWithConfig sets up OpenTelemetry with a custom configuration
func InitializeWithConfig(ctx context.Context, cfg *Config) (*Provider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("telemetry config cannot be nil")
	}

	// Validate configuration
	if err := ValidateExporterConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid telemetry configuration: %w", err)
	}

	// Log telemetry initialization
	if cfg.Enabled {
		log.Printf("Initializing OpenTelemetry with custom config: service=%s version=%s tracing=%v metrics=%v sample_rate=%f",
			cfg.ServiceName, cfg.ServiceVersion, cfg.TracingEnabled, cfg.MetricsEnabled, cfg.TracingSampleRate)
	}

	// Create provider
	provider, err := NewProvider(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create telemetry provider: %w", err)
	}

	return provider, nil
}

// Shutdown gracefully shuts down the telemetry provider with a timeout
func Shutdown(provider *Provider) error {
	if provider == nil {
		return nil
	}

	ctx, cancel := WithShutdownTimeout(context.Background(), DefaultShutdownTimeout)
	defer cancel()

	log.Printf("Shutting down OpenTelemetry")

	if err := provider.Shutdown(ctx); err != nil {
		log.Printf("Failed to shutdown telemetry: %v", err)
		return err
	}

	log.Printf("OpenTelemetry shutdown completed")
	return nil
}

// ShutdownWithTimeout gracefully shuts down the telemetry provider with a custom timeout
func ShutdownWithTimeout(provider *Provider, timeout time.Duration) error {
	if provider == nil {
		return nil
	}

	ctx, cancel := WithShutdownTimeout(context.Background(), timeout)
	defer cancel()

	log.Printf("Shutting down OpenTelemetry with timeout: %v", timeout)

	if err := provider.Shutdown(ctx); err != nil {
		log.Printf("Failed to shutdown telemetry with timeout %v: %v", timeout, err)
		return err
	}

	log.Printf("OpenTelemetry shutdown completed")
	return nil
}
