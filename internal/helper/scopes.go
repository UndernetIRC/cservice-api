// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package helper

import (
	"fmt"
	"strings"
)

// Predefined API key scopes for resource:action based permissions
const (
	// Channel scopes
	ScopeChannelsRead   = "channels:read"
	ScopeChannelsWrite  = "channels:write"
	ScopeChannelsDelete = "channels:delete"

	// User scopes
	ScopeUsersRead   = "users:read"
	ScopeUsersWrite  = "users:write"
	ScopeUsersDelete = "users:delete"

	// Registration scopes
	ScopeRegistrationsRead  = "registrations:read"
	ScopeRegistrationsWrite = "registrations:write"
)

// allValidScopes contains all valid scope values
var allValidScopes = []string{
	ScopeChannelsRead,
	ScopeChannelsWrite,
	ScopeChannelsDelete,
	ScopeUsersRead,
	ScopeUsersWrite,
	ScopeUsersDelete,
	ScopeRegistrationsRead,
	ScopeRegistrationsWrite,
}

// scopeDescriptions maps scope names to human-readable descriptions
var scopeDescriptions = map[string]string{
	ScopeChannelsRead:       "Read channel information and settings",
	ScopeChannelsWrite:      "Create and modify channels",
	ScopeChannelsDelete:     "Delete channels",
	ScopeUsersRead:          "Read user information",
	ScopeUsersWrite:         "Create and modify users",
	ScopeUsersDelete:        "Delete users",
	ScopeRegistrationsRead:  "Read registration information",
	ScopeRegistrationsWrite: "Create and process registrations",
}

// AllScopes returns all valid scopes
func AllScopes() []string {
	// Return a copy to prevent modification
	scopes := make([]string, len(allValidScopes))
	copy(scopes, allValidScopes)
	return scopes
}

// GetScopeDescription returns the description for a given scope
func GetScopeDescription(scope string) string {
	if desc, ok := scopeDescriptions[scope]; ok {
		return desc
	}
	return ""
}

// ValidateScopes checks if all provided scopes are valid
func ValidateScopes(scopes []string) error {
	if len(scopes) == 0 {
		return fmt.Errorf("at least one scope is required")
	}

	validScopesMap := make(map[string]bool)
	for _, scope := range allValidScopes {
		validScopesMap[scope] = true
	}

	var invalidScopes []string
	for _, scope := range scopes {
		if !validScopesMap[scope] {
			invalidScopes = append(invalidScopes, scope)
		}
	}

	if len(invalidScopes) > 0 {
		return fmt.Errorf("invalid scopes: %s", strings.Join(invalidScopes, ", "))
	}

	return nil
}

// HasRequiredScope checks if userScopes contains at least one of the requiredScopes
func HasRequiredScope(userScopes []string, requiredScopes []string) bool {
	if len(requiredScopes) == 0 {
		return true
	}

	userScopesMap := make(map[string]bool)
	for _, scope := range userScopes {
		userScopesMap[scope] = true
	}

	for _, required := range requiredScopes {
		if userScopesMap[required] {
			return true
		}
	}

	return false
}

// HasAllRequiredScopes checks if userScopes contains all of the requiredScopes
func HasAllRequiredScopes(userScopes []string, requiredScopes []string) bool {
	if len(requiredScopes) == 0 {
		return true
	}

	userScopesMap := make(map[string]bool)
	for _, scope := range userScopes {
		userScopesMap[scope] = true
	}

	for _, required := range requiredScopes {
		if !userScopesMap[required] {
			return false
		}
	}

	return true
}
