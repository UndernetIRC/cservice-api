// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package helper

import (
	"testing"
)

func TestStrPtr2Str(t *testing.T) {
	tests := []struct {
		name  string
		input *string
		want  string
	}{
		{
			name:  "nil pointer",
			input: nil,
			want:  "",
		},
		{
			name:  "empty string",
			input: strPtr(""),
			want:  "",
		},
		{
			name:  "non-empty string",
			input: strPtr("test string"),
			want:  "test string",
		},
		{
			name:  "string with special characters",
			input: strPtr("!@#$%^&*()_+"),
			want:  "!@#$%^&*()_+",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StrPtr2Str(tt.input)
			if got != tt.want {
				t.Errorf("StrPtr2Str() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInArray(t *testing.T) {
	tests := []struct {
		name     string
		needle   string
		haystack []string
		want     bool
	}{
		{
			name:     "found in array",
			needle:   "apple",
			haystack: []string{"banana", "apple", "orange"},
			want:     true,
		},
		{
			name:     "not found in array",
			needle:   "grape",
			haystack: []string{"banana", "apple", "orange"},
			want:     false,
		},
		{
			name:     "empty array",
			needle:   "apple",
			haystack: []string{},
			want:     false,
		},
		{
			name:     "empty needle",
			needle:   "",
			haystack: []string{"banana", "apple", "orange"},
			want:     false,
		},
		{
			name:     "empty needle found",
			needle:   "",
			haystack: []string{"banana", "", "orange"},
			want:     true,
		},
		{
			name:     "case sensitivity check",
			needle:   "Apple",
			haystack: []string{"banana", "apple", "orange"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InArray(tt.needle, tt.haystack)
			if got != tt.want {
				t.Errorf("InArray() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Helper function to create string pointers
func strPtr(s string) *string {
	return &s
}
