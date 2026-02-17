// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package backupcodes

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/undernetirc/cservice-api/db/mocks"
	"github.com/undernetirc/cservice-api/internal/auth/password"
	"github.com/undernetirc/cservice-api/models"
)

// TestValidateBackupCodeFormat_Boundary tests adversarial and boundary inputs that
// the builder's tests did not cover.
func TestValidateBackupCodeFormat_Boundary(t *testing.T) {
	adversarialCases := []struct {
		name    string
		code    string
		wantErr bool
	}{
		// Unicode look-alikes
		{"unicode hyphen (em-dash)", "abcde\u2014" + "12345", true},
		{"unicode hyphen (en-dash)", "abcde\u2013" + "12345", true},
		{"unicode full-width hyphen", "abcde\uff0d12345", true},
		{"unicode digits look-alikes", "abcde-\uff11\uff12\uff13\uff14\uff15", true},
		{"null bytes in code", "abc\x00e-12345", true},
		{"null byte as hyphen", "abcde\x0012345", true},
		{"very long string (1000 chars)", strings.Repeat("a", 1000), true},
		{"only a hyphen", "-", true},
		{"two hyphens, correct length otherwise", "abcd--2345", true},
		{"correct length but wrong format (all hyphens)", "-----12345", true},
		{"newline in code", "abcde\n12345", true},
		{"tab in code", "abcde\t12345", true},
		{"carriage return", "abcde\r12345", true},
		{"all hyphens", "----------", true},
		{"hyphen at start", "-abcde1234", true},
		{"hyphen at end", "abcde1234-", true},
		{"correct format with trailing newline", "abcde-12345\n", true},
		{"correct format with leading space", " abcde-12345", true},
		{"correct format with trailing space", "abcde-12345 ", true},
		// Non-ASCII characters that might slip through
		{"chinese characters", "测试a-12345", true},
		{"emoji in code", "abc😀-12345", true},
		// Valid boundary cases
		{"all zeros (valid)", "00000-00000", false},
		{"all nines (valid)", "99999-99999", false},
		{"mixed case max alphanumeric", "ZZZZZ-zzzzz", false},
	}

	for _, tc := range adversarialCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateBackupCodeFormat(tc.code)
			if tc.wantErr {
				assert.Error(t, err, "expected error for input: %q", tc.code)
			} else {
				assert.NoError(t, err, "expected no error for input: %q", tc.code)
			}
		})
	}
}

// TestNormalizeBackupCode_Boundary tests edge cases in the normalization function.
func TestNormalizeBackupCode_Boundary(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		// Empty and minimal inputs
		{"empty string", "", ""},
		{"single space", " ", ""},
		{"all spaces", "          ", ""},
		{"spaces only 10 chars", "          ", ""},
		// After space removal, exactly 10 chars → hyphen inserted
		{"10-char string after removing 5 spaces", "a b c d e 1 2 3 4 5", "abcde-12345"},
		// Unicode: unicode space (non-breaking) is NOT removed (only ASCII space)
		{"non-breaking space (not removed)", "abcde\u00a012345", "abcde\u00a012345"},
		// Hyphen already present
		{"already has hyphen at correct position", "abcde-12345", "abcde-12345"},
		// Multiple hyphens: no hyphen added because strings.Contains returns true
		{"multiple hyphens stay as-is", "ab-c-de12345", "ab-c-de12345"},
		// Only 9 chars after space removal → no hyphen added
		{"9 chars (no hyphen added)", "abcde1234", "abcde1234"},
		// 11 chars after space removal → no hyphen added
		{"11 chars (no hyphen added)", "abcde123456", "abcde123456"},
		// Null bytes (treated as characters, not spaces)
		{"null bytes stay in output", "abcde\x0012345", "abcde\x0012345"},
		// SQL injection-like input
		{"SQL injection stays as-is (no spaces)", "';DROP-TABLE", "';DROP-TABLE"},
		{"SQL injection with spaces gets compacted", "'; DROP TABLE ", "';DROPTABLE"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := NormalizeBackupCode(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestConsumeBackupCode_Boundary tests adversarial inputs to ConsumeBackupCode.
func TestConsumeBackupCode_Boundary(t *testing.T) {
	ctx := context.Background()
	userID := int32(42)
	updatedBy := "admin"

	// Use low-cost bcrypt for test speed
	hasher := password.NewBcryptHasher(&password.BcryptConfig{Cost: 4})
	validCode := "abcde-12345"
	hash, err := hasher.GenerateHash(validCode)
	require.NoError(t, err)

	storedCodes := []BackupCode{{Hash: hash}}

	t.Run("empty string input does not consume any code", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		metadataJSON := buildMetadataJSON(t, storedCodes, 1)
		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{BackupCodes: metadataJSON}, nil).Once()

		consumed, err := gen.ConsumeBackupCode(ctx, userID, "", updatedBy)

		require.NoError(t, err)
		assert.False(t, consumed, "empty string should not match any backup code")
		mockDB.AssertExpectations(t)
	})

	t.Run("whitespace-only input does not consume any code", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		metadataJSON := buildMetadataJSON(t, storedCodes, 1)
		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{BackupCodes: metadataJSON}, nil).Once()

		consumed, err := gen.ConsumeBackupCode(ctx, userID, "     ", updatedBy)

		require.NoError(t, err)
		assert.False(t, consumed, "whitespace-only input should not match any backup code")
		mockDB.AssertExpectations(t)
	})

	t.Run("very long input (1000 chars) does not match valid code", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		metadataJSON := buildMetadataJSON(t, storedCodes, 1)
		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{BackupCodes: metadataJSON}, nil).Once()

		longInput := strings.Repeat("a", 1000)
		consumed, err := gen.ConsumeBackupCode(ctx, userID, longInput, updatedBy)

		require.NoError(t, err)
		assert.False(t, consumed, "1000-char input should not match any 11-char backup code")
		mockDB.AssertExpectations(t)
	})

	t.Run("unicode input does not match valid code", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		metadataJSON := buildMetadataJSON(t, storedCodes, 1)
		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{BackupCodes: metadataJSON}, nil).Once()

		consumed, err := gen.ConsumeBackupCode(ctx, userID, "测试-12345", updatedBy)

		require.NoError(t, err)
		assert.False(t, consumed, "unicode input should not match any backup code")
		mockDB.AssertExpectations(t)
	})

	t.Run("SQL injection-like input does not match valid code", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		metadataJSON := buildMetadataJSON(t, storedCodes, 1)
		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{BackupCodes: metadataJSON}, nil).Once()

		assert.NotPanics(t, func() {
			consumed, err := gen.ConsumeBackupCode(ctx, userID, "'; DROP TABLE users; --", updatedBy)
			require.NoError(t, err)
			assert.False(t, consumed, "SQL injection input should not match any backup code")
		})
		mockDB.AssertExpectations(t)
	})

	t.Run("null bytes in input do not match valid code", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		metadataJSON := buildMetadataJSON(t, storedCodes, 1)
		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{BackupCodes: metadataJSON}, nil).Once()

		consumed, err := gen.ConsumeBackupCode(ctx, userID, "abcde\x00-12345", updatedBy)

		require.NoError(t, err)
		assert.False(t, consumed, "input with null bytes should not match any backup code")
		mockDB.AssertExpectations(t)
	})

	t.Run("input that normalizes to correct code is accepted", func(t *testing.T) {
		// "a b c d e 1 2 3 4 5" → after normalization: "abcde12345" (10 chars) → "abcde-12345"
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		metadataJSON := buildMetadataJSON(t, storedCodes, 1)
		// ConsumeBackupCode calls GetBackupCodes (GetUserBackupCodes) and UpdateBackupCodes (GetUserBackupCodes + UpdateUserBackupCodes)
		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{BackupCodes: metadataJSON}, nil).Twice()
		mockDB.On("UpdateUserBackupCodes", mock.Anything, mock.Anything).Return(nil).Once()

		// Input with spaces that NormalizeBackupCode converts to "abcde-12345"
		normalizedInput := "a b c d e 1 2 3 4 5"
		consumed, err := gen.ConsumeBackupCode(ctx, userID, normalizedInput, updatedBy)

		require.NoError(t, err)
		assert.True(t, consumed, "normalized input should match the stored backup code")
		mockDB.AssertExpectations(t)
	})
}

// TestGetBackupCodes_CorruptMetadata tests behavior when the metadata stored in the
// database contains malformed JSON.
func TestGetBackupCodes_CorruptMetadata(t *testing.T) {
	ctx := context.Background()
	userID := int32(42)

	t.Run("malformed outer metadata JSON returns error", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{
				BackupCodes: []byte(`{this is not valid json`),
			}, nil).Once()

		codes, err := gen.GetBackupCodes(ctx, userID)

		require.Error(t, err, "malformed outer metadata should return an error")
		assert.Nil(t, codes)
		assert.Contains(t, err.Error(), "failed to unmarshal backup codes metadata")
		mockDB.AssertExpectations(t)
	})

	t.Run("valid outer metadata but malformed inner backup_codes JSON returns error", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		// Valid outer metadata, but backup_codes field contains invalid JSON
		invalidInnerMetadata := Metadata{
			BackupCodes:    `this is not valid json`,
			GeneratedAt:    "2025-06-22T10:30:00Z",
			CodesRemaining: 5,
		}
		invalidJSON, err := json.Marshal(invalidInnerMetadata)
		require.NoError(t, err)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{
				BackupCodes: invalidJSON,
			}, nil).Once()

		codes, err := gen.GetBackupCodes(ctx, userID)

		require.Error(t, err, "malformed inner backup_codes JSON should return an error")
		assert.Nil(t, codes)
		assert.Contains(t, err.Error(), "failed to unmarshal backup codes")
		mockDB.AssertExpectations(t)
	})

	t.Run("empty backup_codes field in metadata returns empty slice", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		// Valid outer metadata, backup_codes is an empty JSON array
		emptyCodesMetadata := Metadata{
			BackupCodes:    "[]",
			GeneratedAt:    "2025-06-22T10:30:00Z",
			CodesRemaining: 0,
		}
		metadataJSON, err := json.Marshal(emptyCodesMetadata)
		require.NoError(t, err)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{
				BackupCodes: metadataJSON,
			}, nil).Once()

		codes, err := gen.GetBackupCodes(ctx, userID)

		assert.NoError(t, err)
		assert.NotNil(t, codes, "empty array should return a non-nil empty slice")
		assert.Len(t, codes, 0)
		mockDB.AssertExpectations(t)
	})

	t.Run("backup_codes field is empty string returns error (invalid JSON)", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		emptyStringMetadata := Metadata{
			BackupCodes:    "",
			GeneratedAt:    "2025-06-22T10:30:00Z",
			CodesRemaining: 0,
		}
		metadataJSON, err := json.Marshal(emptyStringMetadata)
		require.NoError(t, err)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{
				BackupCodes: metadataJSON,
			}, nil).Once()

		codes, err := gen.GetBackupCodes(ctx, userID)

		// Empty string is not valid JSON → unmarshal error
		assert.Error(t, err, "empty string in backup_codes should cause a JSON unmarshal error")
		assert.Nil(t, codes)
		mockDB.AssertExpectations(t)
	})
}

// TestGetBackupCodesCount_Boundary tests the GetBackupCodesCount function which
// was not covered by the builder's tests.
func TestGetBackupCodesCount_Boundary(t *testing.T) {
	ctx := context.Background()
	userID := int32(42)

	t.Run("returns count from metadata", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		codes := []BackupCode{{Hash: "h1"}, {Hash: "h2"}, {Hash: "h3"}}
		metadataJSON := buildMetadataJSON(t, codes, 3)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{BackupCodes: metadataJSON}, nil).Once()

		count, err := gen.GetBackupCodesCount(ctx, userID)

		require.NoError(t, err)
		assert.Equal(t, 3, count)
		mockDB.AssertExpectations(t)
	})

	t.Run("returns 0 when no backup codes stored", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{BackupCodes: nil}, nil).Once()

		count, err := gen.GetBackupCodesCount(ctx, userID)

		require.NoError(t, err)
		assert.Equal(t, 0, count)
		mockDB.AssertExpectations(t)
	})

	t.Run("returns error on DB failure", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{}, assert.AnError).Once()

		count, err := gen.GetBackupCodesCount(ctx, userID)

		require.Error(t, err)
		assert.Equal(t, 0, count)
		assert.Contains(t, err.Error(), "failed to get backup codes metadata")
		mockDB.AssertExpectations(t)
	})

	t.Run("returns error on malformed metadata JSON", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{BackupCodes: []byte(`{invalid json`)}, nil).Once()

		count, err := gen.GetBackupCodesCount(ctx, userID)

		require.Error(t, err)
		assert.Equal(t, 0, count)
		assert.Contains(t, err.Error(), "failed to unmarshal backup codes metadata")
		mockDB.AssertExpectations(t)
	})

	t.Run("count of 0 remaining codes is returned correctly", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		// CodesRemaining is explicitly 0 (all codes used)
		metadataJSON := buildMetadataJSON(t, []BackupCode{}, 0)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{BackupCodes: metadataJSON}, nil).Once()

		count, err := gen.GetBackupCodesCount(ctx, userID)

		require.NoError(t, err)
		assert.Equal(t, 0, count)
		mockDB.AssertExpectations(t)
	})
}

// TestGetBackupCodesGeneratedAt_Boundary tests the GetBackupCodesGeneratedAt function
// which was not covered by the builder's tests.
func TestGetBackupCodesGeneratedAt_Boundary(t *testing.T) {
	ctx := context.Background()
	userID := int32(42)

	t.Run("returns generated_at timestamp from metadata", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		metadataJSON := buildMetadataJSON(t, []BackupCode{{Hash: "h"}}, 1)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{BackupCodes: metadataJSON}, nil).Once()

		generatedAt, err := gen.GetBackupCodesGeneratedAt(ctx, userID)

		require.NoError(t, err)
		assert.Equal(t, "2025-06-22T10:30:00Z", generatedAt)
		mockDB.AssertExpectations(t)
	})

	t.Run("returns empty string when no backup codes stored", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{BackupCodes: nil}, nil).Once()

		generatedAt, err := gen.GetBackupCodesGeneratedAt(ctx, userID)

		require.NoError(t, err)
		assert.Empty(t, generatedAt)
		mockDB.AssertExpectations(t)
	})

	t.Run("returns error on DB failure", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{}, assert.AnError).Once()

		generatedAt, err := gen.GetBackupCodesGeneratedAt(ctx, userID)

		require.Error(t, err)
		assert.Empty(t, generatedAt)
		assert.Contains(t, err.Error(), "failed to get backup codes metadata")
		mockDB.AssertExpectations(t)
	})

	t.Run("returns error on malformed metadata JSON", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{BackupCodes: []byte(`{invalid`)}, nil).Once()

		generatedAt, err := gen.GetBackupCodesGeneratedAt(ctx, userID)

		require.Error(t, err)
		assert.Empty(t, generatedAt)
		mockDB.AssertExpectations(t)
	})
}

// TestGetBackupCodesReadStatus_Boundary tests the GetBackupCodesReadStatus function
// which was not covered by the builder's tests.
func TestGetBackupCodesReadStatus_Boundary(t *testing.T) {
	ctx := context.Background()
	userID := int32(42)

	t.Run("returns true when backup codes have been read", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{
				BackupCodesRead: pgtype.Bool{Bool: true, Valid: true},
			}, nil).Once()

		read, err := gen.GetBackupCodesReadStatus(ctx, userID)

		require.NoError(t, err)
		assert.True(t, read)
		mockDB.AssertExpectations(t)
	})

	t.Run("returns false when backup codes have not been read", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{
				BackupCodesRead: pgtype.Bool{Bool: false, Valid: true},
			}, nil).Once()

		read, err := gen.GetBackupCodesReadStatus(ctx, userID)

		require.NoError(t, err)
		assert.False(t, read)
		mockDB.AssertExpectations(t)
	})

	t.Run("returns error on DB failure", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{}, assert.AnError).Once()

		read, err := gen.GetBackupCodesReadStatus(ctx, userID)

		require.Error(t, err)
		assert.False(t, read)
		assert.Contains(t, err.Error(), "failed to get backup codes read status")
		mockDB.AssertExpectations(t)
	})
}

// TestConsumeBackupCode_ConcurrentSafety tests the goroutine safety of ConsumeBackupCode.
// Note: the logical TOCTOU (time-of-check-time-of-use) race — where two concurrent
// requests both read the same backup codes, find a match, and both "consume" it —
// is a semantic race that requires DB-level transactions to prevent.
// This test verifies there are no Go-level data races (safe for `go test -race`).
func TestConsumeBackupCode_ConcurrentSafety(t *testing.T) {
	ctx := context.Background()
	userID := int32(42)
	updatedBy := "admin"

	hasher := password.NewBcryptHasher(&password.BcryptConfig{Cost: 4})
	code1, err := hasher.GenerateHash("abcde-11111")
	require.NoError(t, err)
	code2, err := hasher.GenerateHash("abcde-22222")
	require.NoError(t, err)

	const numGoroutines = 5

	t.Run("concurrent consumption of different codes is goroutine-safe", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		storedCodes := []BackupCode{{Hash: code1}, {Hash: code2}}
		metadataJSON := buildMetadataJSON(t, storedCodes, 2)

		// Each goroutine reads then updates — mock returns full set each time
		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{BackupCodes: metadataJSON}, nil).Maybe()
		mockDB.On("UpdateUserBackupCodes", mock.Anything, mock.Anything).
			Return(nil).Maybe()

		var wg sync.WaitGroup
		for range numGoroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				assert.NotPanics(t, func() {
					_, _ = gen.ConsumeBackupCode(ctx, userID, "abcde-11111", updatedBy)
				})
			}()
		}
		wg.Wait()
	})
}

// TestConsumeBackupCode_TOCTOURaceDocumentation documents the TOCTOU semantic race
// in ConsumeBackupCode. Two concurrent callers both reading the same codes list and
// both returning consumed=true for the same code reveals a design-level race condition.
//
// This is NOT a Go data race (no concurrent memory access) — it is a logical race
// that must be fixed at the database level with transactions or advisory locks.
func TestConsumeBackupCode_TOCTOURaceDocumentation(t *testing.T) {
	ctx := context.Background()
	userID := int32(42)
	updatedBy := "admin"

	hasher := password.NewBcryptHasher(&password.BcryptConfig{Cost: 4})
	codeHash, err := hasher.GenerateHash("abcde-12345")
	require.NoError(t, err)

	t.Run("two sequential calls to consume same code: first succeeds, second fails", func(t *testing.T) {
		mockDB := mocks.NewServiceInterface(t)
		gen := NewBackupCodeGenerator(mockDB)

		storedCodes := []BackupCode{{Hash: codeHash}}
		metadataJSON := buildMetadataJSON(t, storedCodes, 1)
		emptyMetadataJSON := buildMetadataJSON(t, []BackupCode{}, 0)

		// First consumption: reads full list, writes empty list
		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{BackupCodes: metadataJSON}, nil).Once()
		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{BackupCodes: metadataJSON}, nil).Once()
		mockDB.On("UpdateUserBackupCodes", mock.Anything, mock.MatchedBy(func(p models.UpdateUserBackupCodesParams) bool {
			var m Metadata
			_ = json.Unmarshal(p.BackupCodes, &m)
			return m.CodesRemaining == 0
		})).Return(nil).Once()

		// Second consumption: reads empty list
		mockDB.On("GetUserBackupCodes", mock.Anything, userID).
			Return(models.GetUserBackupCodesRow{BackupCodes: emptyMetadataJSON}, nil).Once()

		firstConsumed, firstErr := gen.ConsumeBackupCode(ctx, userID, "abcde-12345", updatedBy)
		require.NoError(t, firstErr)
		assert.True(t, firstConsumed, "first consumption should succeed")

		secondConsumed, secondErr := gen.ConsumeBackupCode(ctx, userID, "abcde-12345", updatedBy)
		require.NoError(t, secondErr)
		assert.False(t, secondConsumed, "second consumption should fail — code already used")

		mockDB.AssertExpectations(t)
	})
}
