// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package helper

import (
	"encoding/json"
	"fmt"
	"net"
)

// ValidateCIDR validates if a string is a valid CIDR notation
func ValidateCIDR(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR notation: %s", cidr)
	}
	return nil
}

// ValidateCIDRList validates a list of CIDR notations
func ValidateCIDRList(cidrs []string) error {
	if len(cidrs) == 0 {
		return nil // Empty list is valid (no restrictions)
	}

	for _, cidr := range cidrs {
		if err := ValidateCIDR(cidr); err != nil {
			return err
		}
	}
	return nil
}

// IsIPAllowed checks if an IP address is within any of the allowed CIDR ranges
func IsIPAllowed(ipStr string, allowedCIDRs []string) (bool, error) {
	// If no restrictions, allow all IPs
	if len(allowedCIDRs) == 0 {
		return true, nil
	}

	// Parse the IP address
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// Check if IP is in any of the allowed CIDR ranges
	for _, cidrStr := range allowedCIDRs {
		_, cidrNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			// This shouldn't happen if validation was done properly
			return false, fmt.Errorf("invalid CIDR in database: %s", cidrStr)
		}

		if cidrNet.Contains(ip) {
			return true, nil
		}
	}

	return false, nil
}

// ParseIPRestrictions parses IP restrictions from JSON bytes
func ParseIPRestrictions(data []byte) ([]string, error) {
	var cidrs []string
	if len(data) == 0 {
		return cidrs, nil
	}

	if err := json.Unmarshal(data, &cidrs); err != nil {
		return nil, fmt.Errorf("failed to parse IP restrictions: %w", err)
	}

	return cidrs, nil
}

// SerializeIPRestrictions serializes IP restrictions to JSON bytes
func SerializeIPRestrictions(cidrs []string) ([]byte, error) {
	if len(cidrs) == 0 {
		return []byte("[]"), nil
	}

	data, err := json.Marshal(cidrs)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize IP restrictions: %w", err)
	}

	return data, nil
}
