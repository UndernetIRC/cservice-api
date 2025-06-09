// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package telemetry

import (
	"regexp"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// MetricsFilter defines interface for filtering metrics
type MetricsFilter interface {
	FilterRegistry(registry *prometheus.Registry) prometheus.Gatherer
	ShouldIncludeMetric(name string, labels map[string]string) bool
}

// DefaultMetricsFilter implements basic filtering based on patterns
type DefaultMetricsFilter struct {
	IncludePatterns []*regexp.Regexp
	ExcludePatterns []*regexp.Regexp
	IncludePrefixes []string
	ExcludePrefixes []string
}

// NewDefaultMetricsFilter creates a new default metrics filter
func NewDefaultMetricsFilter() *DefaultMetricsFilter {
	return &DefaultMetricsFilter{
		IncludePatterns: make([]*regexp.Regexp, 0),
		ExcludePatterns: make([]*regexp.Regexp, 0),
		IncludePrefixes: make([]string, 0),
		ExcludePrefixes: make([]string, 0),
	}
}

// AddIncludePattern adds a regex pattern for metrics to include
func (f *DefaultMetricsFilter) AddIncludePattern(pattern string) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	f.IncludePatterns = append(f.IncludePatterns, regex)
	return nil
}

// AddExcludePattern adds a regex pattern for metrics to exclude
func (f *DefaultMetricsFilter) AddExcludePattern(pattern string) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	f.ExcludePatterns = append(f.ExcludePatterns, regex)
	return nil
}

// AddIncludePrefix adds a prefix for metrics to include
func (f *DefaultMetricsFilter) AddIncludePrefix(prefix string) {
	f.IncludePrefixes = append(f.IncludePrefixes, prefix)
}

// AddExcludePrefix adds a prefix for metrics to exclude
func (f *DefaultMetricsFilter) AddExcludePrefix(prefix string) {
	f.ExcludePrefixes = append(f.ExcludePrefixes, prefix)
}

// ShouldIncludeMetric determines if a metric should be included
func (f *DefaultMetricsFilter) ShouldIncludeMetric(name string, _ map[string]string) bool {
	// Check exclude patterns first (they take precedence)
	for _, pattern := range f.ExcludePatterns {
		if pattern.MatchString(name) {
			return false
		}
	}

	// Check exclude prefixes
	for _, prefix := range f.ExcludePrefixes {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}

	// If we have include patterns or prefixes, check them
	hasIncludeRules := len(f.IncludePatterns) > 0 || len(f.IncludePrefixes) > 0

	if hasIncludeRules {
		// Check include patterns
		for _, pattern := range f.IncludePatterns {
			if pattern.MatchString(name) {
				return true
			}
		}

		// Check include prefixes
		for _, prefix := range f.IncludePrefixes {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}

		// If we have include rules but none matched, exclude
		return false
	}

	// No include rules, so include by default (unless excluded above)
	return true
}

// FilterRegistry returns a filtered gatherer
func (f *DefaultMetricsFilter) FilterRegistry(registry *prometheus.Registry) prometheus.Gatherer {
	return &filteredGatherer{
		gatherer: registry,
		filter:   f,
	}
}

// filteredGatherer wraps a prometheus.Gatherer and applies filtering
type filteredGatherer struct {
	gatherer prometheus.Gatherer
	filter   MetricsFilter
}

// Gather implements prometheus.Gatherer
func (fg *filteredGatherer) Gather() ([]*dto.MetricFamily, error) {
	families, err := fg.gatherer.Gather()
	if err != nil {
		return nil, err
	}

	filtered := make([]*dto.MetricFamily, 0, len(families))
	for _, family := range families {
		if family.GetName() == "" {
			continue
		}

		// Check if this metric family should be included
		if fg.filter.ShouldIncludeMetric(family.GetName(), nil) {
			// Filter individual metrics within the family if needed
			filteredFamily := fg.filterMetricFamily(family)
			if filteredFamily != nil && len(filteredFamily.Metric) > 0 {
				filtered = append(filtered, filteredFamily)
			}
		}
	}

	return filtered, nil
}

// filterMetricFamily filters individual metrics within a family
func (fg *filteredGatherer) filterMetricFamily(family *dto.MetricFamily) *dto.MetricFamily {
	// For now, we don't filter individual metrics within a family
	// This could be extended to filter based on label values
	return family
}

// ApplicationMetricsFilter filters to show only application-specific metrics
type ApplicationMetricsFilter struct {
	*DefaultMetricsFilter
}

// NewApplicationMetricsFilter creates a filter for application metrics only
func NewApplicationMetricsFilter() *ApplicationMetricsFilter {
	base := NewDefaultMetricsFilter()

	// Include application metrics
	base.AddIncludePrefix("http_")
	base.AddIncludePrefix("db_")
	base.AddIncludePrefix("redis_")
	base.AddIncludePrefix("auth_")
	base.AddIncludePrefix("mail_")
	base.AddIncludePrefix("health_")
	base.AddIncludePrefix("uptime_")
	base.AddIncludePrefix("version_")
	base.AddIncludePrefix("process_")

	// Exclude Go runtime metrics
	base.AddExcludePrefix("go_")
	base.AddExcludePrefix("promhttp_")

	return &ApplicationMetricsFilter{
		DefaultMetricsFilter: base,
	}
}

// SystemMetricsFilter filters to show only system-level metrics
type SystemMetricsFilter struct {
	*DefaultMetricsFilter
}

// NewSystemMetricsFilter creates a filter for system metrics only
func NewSystemMetricsFilter() *SystemMetricsFilter {
	base := NewDefaultMetricsFilter()

	// Include system metrics
	base.AddIncludePrefix("go_")
	base.AddIncludePrefix("process_")
	base.AddIncludePrefix("promhttp_")

	return &SystemMetricsFilter{
		DefaultMetricsFilter: base,
	}
}

// CreateFilterFromConfig creates a metrics filter based on configuration
func CreateFilterFromConfig(_ *Config) MetricsFilter {
	// For now, return a filter that includes everything
	// This can be extended to read filter settings from config
	return NewDefaultMetricsFilter()
}
