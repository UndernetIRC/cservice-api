// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

package telemetry

import (
	"fmt"

	"github.com/undernetirc/cservice-api/internal/config"
)

// LoadConfigFromViper loads telemetry configuration from Viper
func LoadConfigFromViper() (*Config, error) {
	cfg := &Config{
		Enabled:            config.TelemetryEnabled.GetBool(),
		ServiceName:        config.TelemetryServiceName.GetString(),
		ServiceVersion:     config.TelemetryServiceVersion.GetString(),
		OTLPEndpoint:       config.TelemetryOTLPEndpoint.GetString(),
		OTLPInsecure:       config.TelemetryOTLPInsecure.GetBool(),
		PrometheusEnabled:  config.TelemetryPrometheusEnabled.GetBool(),
		PrometheusEndpoint: config.TelemetryPrometheusEndpoint.GetString(),
		JaegerEnabled:      config.TelemetryJaegerEnabled.GetBool(),
		JaegerEndpoint:     config.TelemetryJaegerEndpoint.GetString(),
		TracingEnabled:     config.TelemetryTracingEnabled.GetBool(),
		TracingSampleRate:  config.TelemetryTracingSampleRate.GetFloat64(),
		MetricsEnabled:     config.TelemetryMetricsEnabled.GetBool(),
		MetricsInterval:    config.TelemetryMetricsInterval.GetInt(),
	}

	// Load OTLP headers
	headers := config.TelemetryOTLPHeaders.Get()
	if headersMap, ok := headers.(map[string]string); ok {
		cfg.OTLPHeaders = headersMap
	} else {
		cfg.OTLPHeaders = make(map[string]string)
	}

	// Load resource attributes
	attrs := config.TelemetryResourceAttributes.Get()
	if attrsMap, ok := attrs.(map[string]string); ok {
		cfg.ResourceAttributes = attrsMap
	} else {
		cfg.ResourceAttributes = make(map[string]string)
	}

	// Validate configuration
	if err := ValidateExporterConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid telemetry configuration: %w", err)
	}

	return cfg, nil
}
