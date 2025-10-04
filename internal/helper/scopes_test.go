// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package helper

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllScopes(t *testing.T) {
	scopes := AllScopes()

	// Check that we get expected scopes
	assert.Contains(t, scopes, ScopeChannelsRead)
	assert.Contains(t, scopes, ScopeChannelsWrite)
	assert.Contains(t, scopes, ScopeChannelsDelete)
	assert.Contains(t, scopes, ScopeUsersRead)
	assert.Contains(t, scopes, ScopeUsersWrite)
	assert.Contains(t, scopes, ScopeUsersDelete)
	assert.Contains(t, scopes, ScopeRegistrationsRead)
	assert.Contains(t, scopes, ScopeRegistrationsWrite)

	// Verify it returns a copy (modifying returned slice shouldn't affect original)
	scopes1 := AllScopes()
	scopes2 := AllScopes()
	scopes1[0] = "modified"
	assert.NotEqual(t, scopes1[0], scopes2[0], "AllScopes should return a copy")
}

func TestValidateScopes(t *testing.T) {
	tests := []struct {
		name    string
		scopes  []string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid single scope",
			scopes:  []string{ScopeChannelsRead},
			wantErr: false,
		},
		{
			name:    "valid multiple scopes",
			scopes:  []string{ScopeChannelsRead, ScopeUsersWrite, ScopeRegistrationsRead},
			wantErr: false,
		},
		{
			name:    "all valid scopes",
			scopes:  AllScopes(),
			wantErr: false,
		},
		{
			name:    "invalid scope",
			scopes:  []string{"invalid:scope"},
			wantErr: true,
			errMsg:  "invalid scopes: invalid:scope",
		},
		{
			name:    "mixed valid and invalid",
			scopes:  []string{ScopeChannelsRead, "invalid:scope", ScopeUsersRead},
			wantErr: true,
			errMsg:  "invalid scopes: invalid:scope",
		},
		{
			name:    "multiple invalid scopes",
			scopes:  []string{"invalid1", "invalid2"},
			wantErr: true,
			errMsg:  "invalid scopes: invalid1, invalid2",
		},
		{
			name:    "empty scopes",
			scopes:  []string{},
			wantErr: true,
			errMsg:  "at least one scope is required",
		},
		{
			name:    "nil scopes",
			scopes:  nil,
			wantErr: true,
			errMsg:  "at least one scope is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateScopes(tt.scopes)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestHasRequiredScope(t *testing.T) {
	tests := []struct {
		name           string
		userScopes     []string
		requiredScopes []string
		want           bool
	}{
		{
			name:           "has required scope",
			userScopes:     []string{ScopeChannelsRead, ScopeUsersWrite},
			requiredScopes: []string{ScopeChannelsRead},
			want:           true,
		},
		{
			name:           "has one of multiple required scopes",
			userScopes:     []string{ScopeChannelsRead},
			requiredScopes: []string{ScopeChannelsRead, ScopeChannelsWrite},
			want:           true,
		},
		{
			name:           "missing required scope",
			userScopes:     []string{ScopeChannelsRead},
			requiredScopes: []string{ScopeChannelsWrite},
			want:           false,
		},
		{
			name:           "empty required scopes",
			userScopes:     []string{ScopeChannelsRead},
			requiredScopes: []string{},
			want:           true,
		},
		{
			name:           "nil required scopes",
			userScopes:     []string{ScopeChannelsRead},
			requiredScopes: nil,
			want:           true,
		},
		{
			name:           "empty user scopes",
			userScopes:     []string{},
			requiredScopes: []string{ScopeChannelsRead},
			want:           false,
		},
		{
			name:           "nil user scopes",
			userScopes:     nil,
			requiredScopes: []string{ScopeChannelsRead},
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasRequiredScope(tt.userScopes, tt.requiredScopes)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHasAllRequiredScopes(t *testing.T) {
	tests := []struct {
		name           string
		userScopes     []string
		requiredScopes []string
		want           bool
	}{
		{
			name:           "has all required scopes",
			userScopes:     []string{ScopeChannelsRead, ScopeChannelsWrite, ScopeUsersRead},
			requiredScopes: []string{ScopeChannelsRead, ScopeChannelsWrite},
			want:           true,
		},
		{
			name:           "has exact required scopes",
			userScopes:     []string{ScopeChannelsRead, ScopeChannelsWrite},
			requiredScopes: []string{ScopeChannelsRead, ScopeChannelsWrite},
			want:           true,
		},
		{
			name:           "missing one required scope",
			userScopes:     []string{ScopeChannelsRead},
			requiredScopes: []string{ScopeChannelsRead, ScopeChannelsWrite},
			want:           false,
		},
		{
			name:           "missing all required scopes",
			userScopes:     []string{ScopeUsersRead},
			requiredScopes: []string{ScopeChannelsRead, ScopeChannelsWrite},
			want:           false,
		},
		{
			name:           "empty required scopes",
			userScopes:     []string{ScopeChannelsRead},
			requiredScopes: []string{},
			want:           true,
		},
		{
			name:           "nil required scopes",
			userScopes:     []string{ScopeChannelsRead},
			requiredScopes: nil,
			want:           true,
		},
		{
			name:           "empty user scopes",
			userScopes:     []string{},
			requiredScopes: []string{ScopeChannelsRead},
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasAllRequiredScopes(tt.userScopes, tt.requiredScopes)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetScopeDescription(t *testing.T) {
	tests := []struct {
		name     string
		scope    string
		expected string
	}{
		{
			name:     "Valid scope - channels:read",
			scope:    ScopeChannelsRead,
			expected: "Read channel information and settings",
		},
		{
			name:     "Valid scope - users:write",
			scope:    ScopeUsersWrite,
			expected: "Create and modify users",
		},
		{
			name:     "Valid scope - registrations:read",
			scope:    ScopeRegistrationsRead,
			expected: "Read registration information",
		},
		{
			name:     "Invalid scope",
			scope:    "invalid:scope",
			expected: "",
		},
		{
			name:     "Empty scope",
			scope:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetScopeDescription(tt.scope)
			assert.Equal(t, tt.expected, result)
		})
	}
}
