// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package helper

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateCIDR(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		wantErr bool
	}{
		{
			name:    "Valid IPv4 CIDR",
			cidr:    "192.168.1.0/24",
			wantErr: false,
		},
		{
			name:    "Valid IPv4 single host",
			cidr:    "192.168.1.1/32",
			wantErr: false,
		},
		{
			name:    "Valid IPv6 CIDR",
			cidr:    "2001:db8::/32",
			wantErr: false,
		},
		{
			name:    "Valid IPv6 single host",
			cidr:    "2001:db8::1/128",
			wantErr: false,
		},
		{
			name:    "Invalid CIDR - no prefix",
			cidr:    "192.168.1.0",
			wantErr: true,
		},
		{
			name:    "Invalid CIDR - bad IP",
			cidr:    "256.256.256.256/24",
			wantErr: true,
		},
		{
			name:    "Invalid CIDR - bad prefix",
			cidr:    "192.168.1.0/33",
			wantErr: true,
		},
		{
			name:    "Empty string",
			cidr:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCIDR(tt.cidr)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateCIDRList(t *testing.T) {
	tests := []struct {
		name    string
		cidrs   []string
		wantErr bool
	}{
		{
			name:    "Empty list",
			cidrs:   []string{},
			wantErr: false,
		},
		{
			name:    "Valid list",
			cidrs:   []string{"192.168.1.0/24", "10.0.0.0/8", "2001:db8::/32"},
			wantErr: false,
		},
		{
			name:    "List with one invalid CIDR",
			cidrs:   []string{"192.168.1.0/24", "invalid", "10.0.0.0/8"},
			wantErr: true,
		},
		{
			name:    "All invalid",
			cidrs:   []string{"invalid1", "invalid2"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCIDRList(tt.cidrs)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsIPAllowed(t *testing.T) {
	tests := []struct {
		name         string
		ipStr        string
		allowedCIDRs []string
		wantAllowed  bool
		wantErr      bool
	}{
		{
			name:         "No restrictions - allow all",
			ipStr:        "192.168.1.100",
			allowedCIDRs: []string{},
			wantAllowed:  true,
			wantErr:      false,
		},
		{
			name:         "IPv4 in allowed range",
			ipStr:        "192.168.1.100",
			allowedCIDRs: []string{"192.168.1.0/24"},
			wantAllowed:  true,
			wantErr:      false,
		},
		{
			name:         "IPv4 not in allowed range",
			ipStr:        "10.0.0.1",
			allowedCIDRs: []string{"192.168.1.0/24"},
			wantAllowed:  false,
			wantErr:      false,
		},
		{
			name:         "IPv4 in one of multiple ranges",
			ipStr:        "10.0.0.1",
			allowedCIDRs: []string{"192.168.1.0/24", "10.0.0.0/8"},
			wantAllowed:  true,
			wantErr:      false,
		},
		{
			name:         "IPv6 in allowed range",
			ipStr:        "2001:db8::1",
			allowedCIDRs: []string{"2001:db8::/32"},
			wantAllowed:  true,
			wantErr:      false,
		},
		{
			name:         "IPv6 not in allowed range",
			ipStr:        "2001:db8::1",
			allowedCIDRs: []string{"2001:0db8:85a3::/64"},
			wantAllowed:  false,
			wantErr:      false,
		},
		{
			name:         "Mixed IPv4 and IPv6 ranges - IPv4 match",
			ipStr:        "192.168.1.1",
			allowedCIDRs: []string{"2001:db8::/32", "192.168.1.0/24"},
			wantAllowed:  true,
			wantErr:      false,
		},
		{
			name:         "Mixed IPv4 and IPv6 ranges - IPv6 match",
			ipStr:        "2001:db8::1",
			allowedCIDRs: []string{"192.168.1.0/24", "2001:db8::/32"},
			wantAllowed:  true,
			wantErr:      false,
		},
		{
			name:         "Invalid IP address",
			ipStr:        "not-an-ip",
			allowedCIDRs: []string{"192.168.1.0/24"},
			wantAllowed:  false,
			wantErr:      true,
		},
		{
			name:         "Localhost IPv4",
			ipStr:        "127.0.0.1",
			allowedCIDRs: []string{"127.0.0.0/8"},
			wantAllowed:  true,
			wantErr:      false,
		},
		{
			name:         "Localhost IPv6",
			ipStr:        "::1",
			allowedCIDRs: []string{"::1/128"},
			wantAllowed:  true,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, err := IsIPAllowed(tt.ipStr, tt.allowedCIDRs)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantAllowed, allowed)
			}
		})
	}
}

func TestParseIPRestrictions(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    []string
		wantErr bool
	}{
		{
			name:    "Empty JSON array",
			data:    []byte("[]"),
			want:    []string{},
			wantErr: false,
		},
		{
			name:    "Empty data",
			data:    []byte{},
			want:    nil, // Empty data returns nil slice
			wantErr: false,
		},
		{
			name:    "Valid IP restrictions",
			data:    []byte(`["192.168.1.0/24","10.0.0.0/8"]`),
			want:    []string{"192.168.1.0/24", "10.0.0.0/8"},
			wantErr: false,
		},
		{
			name:    "Invalid JSON",
			data:    []byte(`{invalid json}`),
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIPRestrictions(tt.data)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.want == nil && got == nil {
					// Both nil, pass
					return
				}
				if len(tt.want) == 0 && len(got) == 0 {
					// Both empty, pass
					return
				}
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestSerializeIPRestrictions(t *testing.T) {
	tests := []struct {
		name    string
		cidrs   []string
		want    string
		wantErr bool
	}{
		{
			name:    "Empty list",
			cidrs:   []string{},
			want:    "[]",
			wantErr: false,
		},
		{
			name:    "Single CIDR",
			cidrs:   []string{"192.168.1.0/24"},
			want:    `["192.168.1.0/24"]`,
			wantErr: false,
		},
		{
			name:    "Multiple CIDRs",
			cidrs:   []string{"192.168.1.0/24", "10.0.0.0/8"},
			want:    `["192.168.1.0/24","10.0.0.0/8"]`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SerializeIPRestrictions(tt.cidrs)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.JSONEq(t, tt.want, string(got))
			}
		})
	}
}
