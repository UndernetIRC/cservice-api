// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023-2024 UnderNET

package telemetry

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

// createResource creates an OpenTelemetry resource with service information
func (p *Provider) createResource(ctx context.Context) (*resource.Resource, error) {
	// Start with basic service attributes
	attributes := []attribute.KeyValue{
		semconv.ServiceNameKey.String(p.config.ServiceName),
		semconv.ServiceVersionKey.String(p.config.ServiceVersion),
	}

	// Add runtime information
	attributes = append(attributes,
		semconv.ProcessRuntimeNameKey.String("go"),
		semconv.ProcessRuntimeVersionKey.String(runtime.Version()),
		semconv.ProcessRuntimeDescriptionKey.String("Go runtime"),
	)

	// Add host information
	if hostname, err := os.Hostname(); err == nil {
		attributes = append(attributes, semconv.HostNameKey.String(hostname))
	}

	// Add environment detection
	env := detectEnvironment()
	if env != "" {
		attributes = append(attributes, attribute.String("environment", env))
	}

	// Add container detection if available
	if containerID := detectContainerID(); containerID != "" {
		attributes = append(attributes, semconv.ContainerIDKey.String(containerID))
	}

	// Add Kubernetes detection if available
	if k8sAttrs := detectKubernetesAttributes(); len(k8sAttrs) > 0 {
		attributes = append(attributes, k8sAttrs...)
	}

	// Add custom resource attributes from configuration
	for key, value := range p.config.ResourceAttributes {
		attributes = append(attributes, attribute.String(key, value))
	}

	// Create resource with all attributes
	res, err := resource.New(ctx,
		resource.WithAttributes(attributes...),
		resource.WithFromEnv(),
		resource.WithProcess(),
		resource.WithOS(),
		resource.WithHost(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	return res, nil
}

// detectEnvironment attempts to detect the deployment environment
func detectEnvironment() string {
	// Check common environment variables
	if env := os.Getenv("ENVIRONMENT"); env != "" {
		return env
	}
	if env := os.Getenv("ENV"); env != "" {
		return env
	}
	if env := os.Getenv("DEPLOYMENT_ENV"); env != "" {
		return env
	}

	// Check for Kubernetes
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return "kubernetes"
	}

	// Check for Docker
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker"
	}

	// Default to development
	return "development"
}

// detectContainerID attempts to detect the container ID
func detectContainerID() string {
	// Try to read from cgroup file (Docker)
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		// Parse cgroup data to extract container ID
		// This is a simplified implementation
		content := string(data)
		if len(content) > 64 {
			// Extract last 64 characters which might be container ID
			lines := []rune(content)
			if len(lines) >= 64 {
				return string(lines[len(lines)-64:])
			}
		}
	}

	// Check hostname for container ID (common in Kubernetes)
	if hostname, err := os.Hostname(); err == nil && len(hostname) == 64 {
		return hostname
	}

	return ""
}

// detectKubernetesAttributes detects Kubernetes-specific attributes
func detectKubernetesAttributes() []attribute.KeyValue {
	var attrs []attribute.KeyValue

	// Pod name
	if podName := os.Getenv("HOSTNAME"); podName != "" {
		attrs = append(attrs, semconv.K8SPodNameKey.String(podName))
	}

	// Namespace
	if namespace := os.Getenv("NAMESPACE"); namespace != "" {
		attrs = append(attrs, semconv.K8SNamespaceNameKey.String(namespace))
	}

	// Node name
	if nodeName := os.Getenv("NODE_NAME"); nodeName != "" {
		attrs = append(attrs, semconv.K8SNodeNameKey.String(nodeName))
	}

	// Deployment name
	if deployment := os.Getenv("DEPLOYMENT_NAME"); deployment != "" {
		attrs = append(attrs, semconv.K8SDeploymentNameKey.String(deployment))
	}

	// Service account
	if serviceAccount := os.Getenv("SERVICE_ACCOUNT"); serviceAccount != "" {
		attrs = append(attrs, attribute.String("k8s.serviceaccount.name", serviceAccount))
	}

	// Cluster name
	if cluster := os.Getenv("CLUSTER_NAME"); cluster != "" {
		attrs = append(attrs, semconv.K8SClusterNameKey.String(cluster))
	}

	return attrs
}

// MergeResourceAttributes merges additional attributes into an existing resource
func MergeResourceAttributes(base *resource.Resource, attrs map[string]string) (*resource.Resource, error) {
	if len(attrs) == 0 {
		return base, nil
	}

	var attributes []attribute.KeyValue
	for key, value := range attrs {
		attributes = append(attributes, attribute.String(key, value))
	}

	merged, err := resource.Merge(base, resource.NewWithAttributes(
		base.SchemaURL(),
		attributes...,
	))
	if err != nil {
		return nil, fmt.Errorf("failed to merge resource attributes: %w", err)
	}

	return merged, nil
}
