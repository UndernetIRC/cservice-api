// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package helper

import (
	"strings"
	"testing"
)

// Helper function to create int pointers
func intPtr(i int) *int {
	return &i
}

// TestInputValidation_EdgeCases tests edge cases and boundary conditions
func TestInputValidation_EdgeCases(t *testing.T) {
	validator := NewValidator()

	// Test struct for validation
	type ManagerChangeRequest struct {
		NewManagerUsername string `json:"new_manager_username"     validate:"required,min=2,max=12,ircusername"`
		ChangeType         string `json:"change_type"              validate:"required,oneof=temporary permanent"`
		DurationWeeks      *int   `json:"duration_weeks,omitempty" validate:"omitempty,min=3,max=7"`
		Reason             string `json:"reason"                   validate:"required,min=1,max=500,nocontrolchars,meaningful"`
	}

	tests := []struct {
		name      string
		request   ManagerChangeRequest
		shouldErr bool
		errorMsg  string
	}{
		// Username edge cases
		{
			name: "Username exactly 2 chars",
			request: ManagerChangeRequest{
				NewManagerUsername: "ab",
				ChangeType:         "temporary",
				DurationWeeks:      intPtr(5),
				Reason:             "Valid meaningful reason",
			},
			shouldErr: false,
		},
		{
			name: "Username exactly 12 chars",
			request: ManagerChangeRequest{
				NewManagerUsername: "abcdefghijkl",
				ChangeType:         "temporary",
				DurationWeeks:      intPtr(5),
				Reason:             "Valid meaningful reason",
			},
			shouldErr: false,
		},
		{
			name: "Username with numbers",
			request: ManagerChangeRequest{
				NewManagerUsername: "test123",
				ChangeType:         "permanent",
				Reason:             "Valid meaningful reason",
			},
			shouldErr: false,
		},
		{
			name: "Username starting with underscore",
			request: ManagerChangeRequest{
				NewManagerUsername: "_invalid",
				ChangeType:         "permanent",
				Reason:             "Valid meaningful reason",
			},
			shouldErr: true,
			errorMsg:  "must be a valid IRC username",
		},
		{
			name: "Username starting with hyphen",
			request: ManagerChangeRequest{
				NewManagerUsername: "-invalid",
				ChangeType:         "permanent",
				Reason:             "Valid meaningful reason",
			},
			shouldErr: true,
			errorMsg:  "must be a valid IRC username",
		},
		{
			name: "Username with underscore",
			request: ManagerChangeRequest{
				NewManagerUsername: "test_user",
				ChangeType:         "permanent",
				Reason:             "Valid meaningful reason",
			},
			shouldErr: true,
			errorMsg:  "must be a valid IRC username",
		},
		{
			name: "Username with invalid characters",
			request: ManagerChangeRequest{
				NewManagerUsername: "test@user",
				ChangeType:         "permanent",
				Reason:             "Valid meaningful reason",
			},
			shouldErr: true,
			errorMsg:  "must be a valid IRC username",
		},
		// Duration edge cases
		{
			name: "Duration exactly 3 weeks",
			request: ManagerChangeRequest{
				NewManagerUsername: "testuser",
				ChangeType:         "temporary",
				DurationWeeks:      intPtr(3),
				Reason:             "Valid meaningful reason",
			},
			shouldErr: false,
		},
		{
			name: "Duration exactly 7 weeks",
			request: ManagerChangeRequest{
				NewManagerUsername: "testuser",
				ChangeType:         "temporary",
				DurationWeeks:      intPtr(7),
				Reason:             "Valid meaningful reason",
			},
			shouldErr: false,
		},
		{
			name: "Duration 2 weeks (too short)",
			request: ManagerChangeRequest{
				NewManagerUsername: "testuser",
				ChangeType:         "temporary",
				DurationWeeks:      intPtr(2),
				Reason:             "Valid meaningful reason",
			},
			shouldErr: true,
			errorMsg:  "must be 3 or greater",
		},
		{
			name: "Duration 8 weeks (too long)",
			request: ManagerChangeRequest{
				NewManagerUsername: "testuser",
				ChangeType:         "temporary",
				DurationWeeks:      intPtr(8),
				Reason:             "Valid meaningful reason",
			},
			shouldErr: true,
			errorMsg:  "must be 7 or less",
		},
		// Reason edge cases
		{
			name: "Reason exactly 1 char",
			request: ManagerChangeRequest{
				NewManagerUsername: "testuser",
				ChangeType:         "permanent",
				Reason:             "a",
			},
			shouldErr: true,
			errorMsg:  "meaningful",
		},
		{
			name: "Reason exactly 500 chars",
			request: ManagerChangeRequest{
				NewManagerUsername: "testuser",
				ChangeType:         "permanent",
				Reason: strings.Repeat(
					"This is a valid meaningful reason with multiple words. ",
					9,
				) + "End",
			},
			shouldErr: false,
		},
		{
			name: "Reason 501 chars (too long)",
			request: ManagerChangeRequest{
				NewManagerUsername: "testuser",
				ChangeType:         "permanent",
				Reason:             strings.Repeat("This is a valid meaningful reason with multiple words. ", 10),
			},
			shouldErr: true,
			errorMsg:  "must be a maximum of 500 characters",
		},
		{
			name: "Reason with control characters",
			request: ManagerChangeRequest{
				NewManagerUsername: "testuser",
				ChangeType:         "permanent",
				Reason:             "Valid reason with\x00null character",
			},
			shouldErr: true,
			errorMsg:  "cannot contain control characters",
		},
		{
			name: "Reason with only one word",
			request: ManagerChangeRequest{
				NewManagerUsername: "testuser",
				ChangeType:         "permanent",
				Reason:             "onlyoneword",
			},
			shouldErr: true,
			errorMsg:  "meaningful",
		},
		{
			name: "Reason with placeholder text",
			request: ManagerChangeRequest{
				NewManagerUsername: "testuser",
				ChangeType:         "permanent",
				Reason:             "This is just testing placeholder",
			},
			shouldErr: true,
			errorMsg:  "meaningful",
		},
		{
			name: "Reason with repeated characters",
			request: ManagerChangeRequest{
				NewManagerUsername: "testuser",
				ChangeType:         "permanent",
				Reason:             "aaaaaaaaaaaaa bb",
			},
			shouldErr: true,
			errorMsg:  "meaningful",
		},
		// Change type edge cases
		{
			name: "Change type mixed case",
			request: ManagerChangeRequest{
				NewManagerUsername: "testuser",
				ChangeType:         "TEMPORARY",
				DurationWeeks:      intPtr(5),
				Reason:             "Valid meaningful reason",
			},
			shouldErr: true,
			errorMsg:  "must be one of",
		},
		{
			name: "Change type with whitespace",
			request: ManagerChangeRequest{
				NewManagerUsername: "testuser",
				ChangeType:         " temporary ",
				DurationWeeks:      intPtr(5),
				Reason:             "Valid meaningful reason",
			},
			shouldErr: true,
			errorMsg:  "must be one of",
		},
		// Complex boundary combinations
		{
			name: "All minimum values",
			request: ManagerChangeRequest{
				NewManagerUsername: "ab",
				ChangeType:         "temporary",
				DurationWeeks:      intPtr(3),
				Reason:             "a b",
			},
			shouldErr: false,
		},
		{
			name: "All maximum values",
			request: ManagerChangeRequest{
				NewManagerUsername: "abcdefghijkl",
				ChangeType:         "temporary",
				DurationWeeks:      intPtr(7),
				Reason: strings.Repeat(
					"This is a valid meaningful reason with multiple words. ",
					9,
				) + "End",
			},
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(tt.request)

			if tt.shouldErr {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error message to contain '%s', got: %s", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
