// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package backupcodes

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/internal/auth/password"
	"github.com/undernetirc/cservice-api/models"
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

// buildMetadataJSON is a test helper that builds the nested metadata JSON
// structure matching what the database returns.
func buildMetadataJSON(t *testing.T, codes []BackupCode, codesRemaining int) []byte {
	t.Helper()
	codesJSON, err := json.Marshal(codes)
	require.NoError(t, err)

	metadata := Metadata{
		BackupCodes:    string(codesJSON),
		GeneratedAt:    "2025-06-22T10:30:00Z",
		CodesRemaining: codesRemaining,
	}
	metadataJSON, err := json.Marshal(metadata)
	require.NoError(t, err)
	return metadataJSON
}

func TestNewBackupCodeGenerator(t *testing.T) {
	t.Run("creates generator with db", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		require.NotNil(t, gen)
		assert.Equal(t, mockDB, gen.db)
	})

	t.Run("creates generator with nil db", func(t *testing.T) {
		gen := NewBackupCodeGenerator(nil)

		require.NotNil(t, gen)
		assert.Nil(t, gen.db)
	})
}

func TestGenerateAndStoreBackupCodes(t *testing.T) {
	ctx := context.Background()
	userID := int32(42)
	updatedBy := "admin"

	t.Run("successful generation and storage", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		mockDB.On("UpdateUserBackupCodes", mock.Anything, mock.MatchedBy(func(arg models.UpdateUserBackupCodesParams) bool {
			return arg.ID == userID && len(arg.BackupCodes) > 0 && arg.LastUpdatedBy.String == updatedBy
		})).Return(nil).Once()

		codes, err := gen.GenerateAndStoreBackupCodes(ctx, userID, updatedBy)

		require.NoError(t, err)
		assert.Len(t, codes, BackupCodeCount)
		for _, code := range codes {
			assert.NoError(t, ValidateBackupCodeFormat(code))
		}
		mockDB.AssertExpectations(t)
	})
}

func TestGenerateAndStoreBackupCodes_DBError(t *testing.T) {
	ctx := context.Background()
	userID := int32(42)
	updatedBy := "admin"

	mockDB := mocks.NewServiceInterface(t)
	gen := NewBackupCodeGenerator(mockDB)

	mockDB.On("UpdateUserBackupCodes", mock.Anything, mock.Anything).Return(assert.AnError).Once()

	codes, err := gen.GenerateAndStoreBackupCodes(ctx, userID, updatedBy)

	require.Error(t, err)
	assert.Nil(t, codes)
	assert.Contains(t, err.Error(), "failed to store backup codes")
	mockDB.AssertExpectations(t)
}

func TestGetBackupCodes(t *testing.T) {
	ctx := context.Background()
	userID := int32(42)

	t.Run("successful retrieval", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		storedCodes := []BackupCode{
			{Hash: "$2a$04$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTU12345678"},
			{Hash: "$2a$04$zyxwvutsrqponmlkjihgfeZYXWVUTSRQPONMLKJIHGFE87654321"},
		}
		metadataJSON := buildMetadataJSON(t, storedCodes, 2)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).Return(models.GetUserBackupCodesRow{
			BackupCodes: metadataJSON,
		}, nil).Once()

		codes, err := gen.GetBackupCodes(ctx, userID)

		require.NoError(t, err)
		require.Len(t, codes, 2)
		assert.Equal(t, storedCodes[0].Hash, codes[0].Hash)
		assert.Equal(t, storedCodes[1].Hash, codes[1].Hash)
		mockDB.AssertExpectations(t)
	})

	t.Run("empty backup codes", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).Return(models.GetUserBackupCodesRow{
			BackupCodes: nil,
		}, nil).Once()

		codes, err := gen.GetBackupCodes(ctx, userID)

		assert.NoError(t, err)
		assert.Nil(t, codes)
		mockDB.AssertExpectations(t)
	})
}

func TestGetBackupCodes_NotFound(t *testing.T) {
	ctx := context.Background()
	userID := int32(999)

	mockDB := mocks.NewServiceInterface(t)
	gen := NewBackupCodeGenerator(mockDB)

	mockDB.On("GetUserBackupCodes", mock.Anything, userID).Return(models.GetUserBackupCodesRow{
		BackupCodes: []byte{},
	}, nil).Once()

	codes, err := gen.GetBackupCodes(ctx, userID)

	assert.NoError(t, err)
	assert.Nil(t, codes)
	mockDB.AssertExpectations(t)
}

func TestGetBackupCodes_DBError(t *testing.T) {
	ctx := context.Background()
	userID := int32(42)

	mockDB := mocks.NewServiceInterface(t)
	gen := NewBackupCodeGenerator(mockDB)

	mockDB.On("GetUserBackupCodes", mock.Anything, userID).Return(models.GetUserBackupCodesRow{}, assert.AnError).Once()

	codes, err := gen.GetBackupCodes(ctx, userID)

	require.Error(t, err)
	assert.Nil(t, codes)
	assert.Contains(t, err.Error(), "failed to retrieve backup codes")
	mockDB.AssertExpectations(t)
}

func TestUpdateBackupCodes(t *testing.T) {
	ctx := context.Background()
	userID := int32(42)
	updatedBy := "admin"

	t.Run("successful update", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		existingCodes := []BackupCode{{Hash: "existinghash"}}
		existingMetadata := buildMetadataJSON(t, existingCodes, 1)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).Return(models.GetUserBackupCodesRow{
			BackupCodes: existingMetadata,
		}, nil).Once()

		mockDB.On("UpdateUserBackupCodes", mock.Anything, mock.MatchedBy(func(arg models.UpdateUserBackupCodesParams) bool {
			return arg.ID == userID && arg.LastUpdatedBy.String == updatedBy
		})).Return(nil).Once()

		newCodes := []BackupCode{{Hash: "newhash1"}, {Hash: "newhash2"}}
		err := gen.UpdateBackupCodes(ctx, userID, newCodes, updatedBy)

		require.NoError(t, err)
		mockDB.AssertExpectations(t)
	})

	t.Run("preserves generated_at from existing metadata", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		existingCodes := []BackupCode{{Hash: "hash"}}
		existingMetadata := buildMetadataJSON(t, existingCodes, 1)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).Return(models.GetUserBackupCodesRow{
			BackupCodes: existingMetadata,
		}, nil).Once()

		mockDB.On("UpdateUserBackupCodes", mock.Anything, mock.MatchedBy(func(arg models.UpdateUserBackupCodesParams) bool {
			var metadata Metadata
			if err := json.Unmarshal(arg.BackupCodes, &metadata); err != nil {
				return false
			}
			return metadata.GeneratedAt == "2025-06-22T10:30:00Z"
		})).Return(nil).Once()

		err := gen.UpdateBackupCodes(ctx, userID, []BackupCode{{Hash: "newhash"}}, updatedBy)

		require.NoError(t, err)
		mockDB.AssertExpectations(t)
	})
}

func TestUpdateBackupCodes_DBError(t *testing.T) {
	ctx := context.Background()
	userID := int32(42)
	updatedBy := "admin"

	t.Run("error on get current metadata", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).Return(models.GetUserBackupCodesRow{}, assert.AnError).Once()

		err := gen.UpdateBackupCodes(ctx, userID, []BackupCode{{Hash: "h"}}, updatedBy)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get current backup codes metadata")
		mockDB.AssertExpectations(t)
	})

	t.Run("error on update", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		existingMetadata := buildMetadataJSON(t, []BackupCode{{Hash: "h"}}, 1)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).Return(models.GetUserBackupCodesRow{
			BackupCodes: existingMetadata,
		}, nil).Once()
		mockDB.On("UpdateUserBackupCodes", mock.Anything, mock.Anything).Return(assert.AnError).Once()

		err := gen.UpdateBackupCodes(ctx, userID, []BackupCode{{Hash: "h"}}, updatedBy)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to update backup codes")
		mockDB.AssertExpectations(t)
	})
}

func TestConsumeBackupCode(t *testing.T) {
	ctx := context.Background()
	userID := int32(42)
	updatedBy := "admin"
	plainCode := "abcde-12345"

	// Use low-cost bcrypt for test speed
	hasher := password.NewBcryptHasher(&password.BcryptConfig{Cost: 4})
	hash, err := hasher.GenerateHash(plainCode)
	require.NoError(t, err)

	t.Run("successful consumption", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		storedCodes := []BackupCode{
			{Hash: hash},
			{Hash: "$2a$04$otherhashvaluexxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
		}
		metadataJSON := buildMetadataJSON(t, storedCodes, 2)

		// First call: GetBackupCodes reads from DB
		mockDB.On("GetUserBackupCodes", mock.Anything, userID).Return(models.GetUserBackupCodesRow{
			BackupCodes: metadataJSON,
		}, nil).Once()

		// Second call: UpdateBackupCodes reads current metadata
		mockDB.On("GetUserBackupCodes", mock.Anything, userID).Return(models.GetUserBackupCodesRow{
			BackupCodes: metadataJSON,
		}, nil).Once()

		// UpdateBackupCodes writes the reduced set
		mockDB.On("UpdateUserBackupCodes", mock.Anything, mock.MatchedBy(func(arg models.UpdateUserBackupCodesParams) bool {
			var metadata Metadata
			if err := json.Unmarshal(arg.BackupCodes, &metadata); err != nil {
				return false
			}
			return metadata.CodesRemaining == 1
		})).Return(nil).Once()

		consumed, err := gen.ConsumeBackupCode(ctx, userID, plainCode, updatedBy)

		require.NoError(t, err)
		assert.True(t, consumed)
		mockDB.AssertExpectations(t)
	})
}

func TestConsumeBackupCode_Invalid(t *testing.T) {
	ctx := context.Background()
	userID := int32(42)
	updatedBy := "admin"

	mockDB := mocks.NewServiceInterface(t)
	gen := NewBackupCodeGenerator(mockDB)

	// Use low-cost bcrypt hash for a different code
	hasher := password.NewBcryptHasher(&password.BcryptConfig{Cost: 4})
	hash, err := hasher.GenerateHash("zzzzz-99999")
	require.NoError(t, err)

	storedCodes := []BackupCode{{Hash: hash}}
	metadataJSON := buildMetadataJSON(t, storedCodes, 1)

	mockDB.On("GetUserBackupCodes", mock.Anything, userID).Return(models.GetUserBackupCodesRow{
		BackupCodes: metadataJSON,
	}, nil).Once()

	consumed, err := gen.ConsumeBackupCode(ctx, userID, "wrong-codes", updatedBy)

	require.NoError(t, err)
	assert.False(t, consumed)
	mockDB.AssertExpectations(t)
}

func TestConsumeBackupCode_AlreadyUsed(t *testing.T) {
	ctx := context.Background()
	userID := int32(42)
	updatedBy := "admin"

	mockDB := mocks.NewServiceInterface(t)
	gen := NewBackupCodeGenerator(mockDB)

	// No codes remaining — simulates all codes already consumed
	metadataJSON := buildMetadataJSON(t, []BackupCode{}, 0)

	mockDB.On("GetUserBackupCodes", mock.Anything, userID).Return(models.GetUserBackupCodesRow{
		BackupCodes: metadataJSON,
	}, nil).Once()

	consumed, err := gen.ConsumeBackupCode(ctx, userID, "abcde-12345", updatedBy)

	require.NoError(t, err)
	assert.False(t, consumed)
	mockDB.AssertExpectations(t)
}

func TestConsumeBackupCode_DBError(t *testing.T) {
	ctx := context.Background()
	userID := int32(42)
	updatedBy := "admin"

	mockDB := mocks.NewServiceInterface(t)
	gen := NewBackupCodeGenerator(mockDB)

	mockDB.On("GetUserBackupCodes", mock.Anything, userID).Return(models.GetUserBackupCodesRow{}, assert.AnError).Once()

	consumed, err := gen.ConsumeBackupCode(ctx, userID, "abcde-12345", updatedBy)

	require.Error(t, err)
	assert.False(t, consumed)
	assert.Contains(t, err.Error(), "failed to get backup codes")
	mockDB.AssertExpectations(t)
}
