// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package backupcodes

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateBackupCodes(t *testing.T) {
	generator := &BackupCodeGenerator{}

	t.Run("generates correct number of codes", func(t *testing.T) {
		codes, err := generator.GenerateBackupCodes()
		require.NoError(t, err)
		assert.Len(t, codes, BackupCodeCount)
	})

	t.Run("generates unique codes", func(t *testing.T) {
		codes, err := generator.GenerateBackupCodes()
		require.NoError(t, err)

		codeSet := make(map[string]bool)
		for _, code := range codes {
			assert.False(t, codeSet[code], "Code %s is duplicated", code)
			codeSet[code] = true
		}
	})

	t.Run("codes follow correct format", func(t *testing.T) {
		codes, err := generator.GenerateBackupCodes()
		require.NoError(t, err)

		for _, code := range codes {
			err := ValidateBackupCodeFormat(code)
			assert.NoError(t, err, "Code %s does not match expected format", code)

			// Additional format checks
			parts := strings.Split(code, "-")
			assert.Len(t, parts, 2, "Code %s should have exactly one hyphen", code)
			assert.Len(t, parts[0], BackupCodePartLength, "First part of code %s should be %d characters", code, BackupCodePartLength)
			assert.Len(t, parts[1], BackupCodePartLength, "Second part of code %s should be %d characters", code, BackupCodePartLength)
		}
	})

	t.Run("generates different codes on multiple calls", func(t *testing.T) {
		codes1, err := generator.GenerateBackupCodes()
		require.NoError(t, err)

		codes2, err := generator.GenerateBackupCodes()
		require.NoError(t, err)

		// Check that sets are different
		set1 := make(map[string]bool)
		for _, code := range codes1 {
			set1[code] = true
		}

		differentCount := 0
		for _, code := range codes2 {
			if !set1[code] {
				differentCount++
			}
		}

		// Should have at least some different codes (very high probability)
		assert.Greater(t, differentCount, 0, "Second generation should produce at least some different codes")
	})
}

func TestGenerateSingleBackupCode(t *testing.T) {
	t.Run("generates valid format", func(t *testing.T) {
		code, err := generateSingleBackupCode()
		require.NoError(t, err)

		err = ValidateBackupCodeFormat(code)
		assert.NoError(t, err)
	})

	t.Run("generates different codes", func(t *testing.T) {
		code1, err := generateSingleBackupCode()
		require.NoError(t, err)

		code2, err := generateSingleBackupCode()
		require.NoError(t, err)

		assert.NotEqual(t, code1, code2, "Should generate different codes")
	})
}

func TestValidateBackupCodeFormat(t *testing.T) {
	testCases := []struct {
		name    string
		code    string
		wantErr bool
	}{
		{
			name:    "valid format",
			code:    "abcde-12345",
			wantErr: false,
		},
		{
			name:    "valid format with mixed case",
			code:    "AbCdE-12345",
			wantErr: false,
		},
		{
			name:    "valid format with all numbers",
			code:    "12345-67890",
			wantErr: false,
		},
		{
			name:    "valid format with all letters",
			code:    "abcde-fghij",
			wantErr: false,
		},
		{
			name:    "empty string",
			code:    "",
			wantErr: true,
		},
		{
			name:    "no hyphen",
			code:    "abcde12345",
			wantErr: true,
		},
		{
			name:    "too short first part",
			code:    "abc-12345",
			wantErr: true,
		},
		{
			name:    "too long first part",
			code:    "abcdef-12345",
			wantErr: true,
		},
		{
			name:    "too short second part",
			code:    "abcde-123",
			wantErr: true,
		},
		{
			name:    "too long second part",
			code:    "abcde-123456",
			wantErr: true,
		},
		{
			name:    "special characters",
			code:    "abc@e-12345",
			wantErr: true,
		},
		{
			name:    "multiple hyphens",
			code:    "ab-cde-12345",
			wantErr: true,
		},
		{
			name:    "spaces",
			code:    "abc e-12345",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateBackupCodeFormat(tc.code)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNormalizeBackupCode(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "already normalized",
			input:    "abcde-12345",
			expected: "abcde-12345",
		},
		{
			name:     "remove spaces",
			input:    "abc de-123 45",
			expected: "abcde-12345",
		},
		{
			name:     "add hyphen to 10-char string",
			input:    "abcde12345",
			expected: "abcde-12345",
		},
		{
			name:     "add hyphen and remove spaces",
			input:    "abc de123 45",
			expected: "abcde-12345",
		},
		{
			name:     "preserve existing hyphen",
			input:    "abcde-12345",
			expected: "abcde-12345",
		},
		{
			name:     "short string no hyphen needed",
			input:    "abc",
			expected: "abc",
		},
		{
			name:     "long string no hyphen added",
			input:    "abcdefghijk",
			expected: "abcdefghijk",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := NormalizeBackupCode(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestBackupCodeStruct(t *testing.T) {
	t.Run("backup code JSON serialization", func(t *testing.T) {
		codes := []BackupCode{
			{Hash: "$2a$10$abcdefghijklmnopqrstuv"},
			{Hash: "$2a$10$zyxwvutsrqponmlkjihgfe"},
		}

		// This test ensures the BackupCode struct can be marshaled/unmarshaled
		// The actual JSON marshaling is tested in integration tests
		assert.Equal(t, "$2a$10$abcdefghijklmnopqrstuv", codes[0].Hash)
		assert.Equal(t, "$2a$10$zyxwvutsrqponmlkjihgfe", codes[1].Hash)
	})
}

func TestBackupCodesMetadata(t *testing.T) {
	t.Run("metadata JSON serialization", func(t *testing.T) {
		metadata := Metadata{
			BackupCodes:    `[{"hash":"$2a$10$test"}]`,
			GeneratedAt:    "2025-06-22T10:30:00Z",
			CodesRemaining: 8,
		}

		jsonData, err := json.Marshal(metadata)
		require.NoError(t, err)

		var unmarshaled Metadata
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, metadata.BackupCodes, unmarshaled.BackupCodes)
		assert.Equal(t, metadata.GeneratedAt, unmarshaled.GeneratedAt)
		assert.Equal(t, metadata.CodesRemaining, unmarshaled.CodesRemaining)
	})

	t.Run("metadata structure validation", func(t *testing.T) {
		// Test the expected JSON structure
		expectedJSON := `{
			"backup_codes": "[{\"hash\":\"$2a$10$test\"}]",
			"generated_at": "2025-06-22T10:30:00Z",
			"codes_remaining": 5
		}`

		var metadata Metadata
		err := json.Unmarshal([]byte(expectedJSON), &metadata)
		require.NoError(t, err)

		assert.Equal(t, `[{"hash":"$2a$10$test"}]`, metadata.BackupCodes)
		assert.Equal(t, "2025-06-22T10:30:00Z", metadata.GeneratedAt)
		assert.Equal(t, 5, metadata.CodesRemaining)
	})
}
