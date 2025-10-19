//go:build integration

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/undernetirc/cservice-api/db/types/password"
	"github.com/undernetirc/cservice-api/models"
)

// TestBackupCodesMigration tests the backup codes migration functionality
func TestBackupCodesMigration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	ctx := context.Background()

	// Test that the new columns exist by creating a user and testing backup codes functionality
	t.Run("User Creation With Backup Codes Support", func(t *testing.T) {
		// Create a test user with unique credentials
		createParams := models.CreateUserParams{
			Username:         "bkup_" + time.Now().Format("150405.000000"),
			Email:            pgtype.Text{String: "backup_" + time.Now().Format("150405.000000") + "@test.com", Valid: true},
			Password:         password.Password("hashed_password"),
			Flags:            0,
			LastUpdated:      int32(time.Now().Unix()),
			LastUpdatedBy:    pgtype.Text{String: "test", Valid: true},
			LanguageID:       pgtype.Int4{Int32: 1, Valid: true},
			QuestionID:       pgtype.Int2{Int16: 1, Valid: true},
			Verificationdata: pgtype.Text{String: "test_data", Valid: true},
			PostForms:        0,
			SignupTs:         pgtype.Int4{Int32: int32(time.Now().Unix()), Valid: true},
			SignupIp:         pgtype.Text{String: "127.0.0.1", Valid: true},
			Maxlogins:        pgtype.Int4{Int32: 1, Valid: true},
		}

		user, err := db.CreateUser(ctx, createParams)
		require.NoError(t, err)
		assert.NotZero(t, user.ID)

		// Verify that backup codes fields are present and have default values
		assert.Nil(t, user.BackupCodes)            // Should be NULL initially
		assert.False(t, user.BackupCodesRead.Bool) // Should be false by default
		assert.True(t, user.BackupCodesRead.Valid) // Should be valid with default false value from migration
	})

	t.Run("Backup Codes Functionality", func(t *testing.T) {
		// Create another test user for backup codes testing with unique credentials
		time.Sleep(time.Microsecond) // Ensure unique timestamp
		createParams := models.CreateUserParams{
			Username:         "codes_" + time.Now().Format("150405.000000"),
			Email:            pgtype.Text{String: "codes_" + time.Now().Format("150405.000000") + "@test.com", Valid: true},
			Password:         password.Password("hashed_password"),
			Flags:            0,
			LastUpdated:      int32(time.Now().Unix()),
			LastUpdatedBy:    pgtype.Text{String: "test", Valid: true},
			LanguageID:       pgtype.Int4{Int32: 1, Valid: true},
			QuestionID:       pgtype.Int2{Int16: 1, Valid: true},
			Verificationdata: pgtype.Text{String: "test_data", Valid: true},
			PostForms:        0,
			SignupTs:         pgtype.Int4{Int32: int32(time.Now().Unix()), Valid: true},
			SignupIp:         pgtype.Text{String: "127.0.0.1", Valid: true},
			Maxlogins:        pgtype.Int4{Int32: 1, Valid: true},
		}

		user, err := db.CreateUser(ctx, createParams)
		require.NoError(t, err)

		// Test updating backup codes with metadata structure
		backupCodes := []string{"code1", "code2", "code3", "code4", "code5"}
		backupCodesJSON, err := json.Marshal(backupCodes)
		require.NoError(t, err)
		// For testing, we'll use the JSON as simple placeholder (in real usage, codes are bcrypt hashed)
		backupCodesData := string(backupCodesJSON)

		// Create metadata structure
		metadata := map[string]interface{}{
			"backup_codes":    backupCodesData,
			"generated_at":    time.Now().Format(time.RFC3339),
			"codes_remaining": len(backupCodes),
		}
		metadataJSON, err := json.Marshal(metadata)
		require.NoError(t, err)

		updateParams := models.UpdateUserBackupCodesParams{
			ID:            user.ID,
			BackupCodes:   metadataJSON,
			LastUpdated:   int32(time.Now().Unix()),
			LastUpdatedBy: pgtype.Text{String: "test_admin", Valid: true},
		}

		err = db.UpdateUserBackupCodes(ctx, updateParams)
		require.NoError(t, err)

		// Test getting backup codes
		backupData, err := db.GetUserBackupCodes(ctx, user.ID)
		require.NoError(t, err)
		assert.NotNil(t, backupData.BackupCodes)
		assert.False(t, backupData.BackupCodesRead.Bool) // Should be false after update

		// Verify the metadata structure
		var retrievedMetadata map[string]interface{}
		err = json.Unmarshal(backupData.BackupCodes, &retrievedMetadata)
		require.NoError(t, err)
		assert.Equal(t, float64(len(backupCodes)), retrievedMetadata["codes_remaining"])
		assert.Contains(t, retrievedMetadata, "backup_codes")
		assert.Contains(t, retrievedMetadata, "generated_at")

		// Verify the content (in real usage, codes are bcrypt hashed and cannot be retrieved)
		var retrievedCodes []string
		err = json.Unmarshal([]byte(retrievedMetadata["backup_codes"].(string)), &retrievedCodes)
		require.NoError(t, err)
		assert.Equal(t, backupCodes, retrievedCodes)

		// Test marking backup codes as read
		markReadParams := models.MarkBackupCodesAsReadParams{
			ID:            user.ID,
			LastUpdated:   int32(time.Now().Unix()),
			LastUpdatedBy: pgtype.Text{String: "test_user", Valid: true},
		}

		err = db.MarkBackupCodesAsRead(ctx, markReadParams)
		require.NoError(t, err)

		// Verify codes are marked as read
		updatedBackupData, err := db.GetUserBackupCodes(ctx, user.ID)
		require.NoError(t, err)
		assert.True(t, updatedBackupData.BackupCodesRead.Bool)
		assert.True(t, updatedBackupData.BackupCodesRead.Valid)
	})

	t.Run("Migration Backward Compatibility", func(t *testing.T) {
		// Test that existing users work correctly with new columns
		// Query the first existing user (if any) to ensure migration didn't break existing data
		allUsers, err := db.GetUsersByUsernames(ctx, []string{"admin"}) // Try to get admin user
		if err != nil || len(allUsers) == 0 {
			t.Skip("No existing users to test backward compatibility")
			return
		}

		existingUser := allUsers[0]

		// Ensure existing users have proper default values
		assert.False(t, existingUser.BackupCodesRead.Bool)

		// Test that we can still update existing users with backup codes
		backupCodes := []string{"legacy1", "legacy2", "legacy3"}
		backupCodesJSON, err := json.Marshal(backupCodes)
		require.NoError(t, err)
		backupCodesData := string(backupCodesJSON)

		// Create metadata structure
		metadata := map[string]interface{}{
			"backup_codes":    backupCodesData,
			"generated_at":    time.Now().Format(time.RFC3339),
			"codes_remaining": len(backupCodes),
		}
		metadataJSON, err := json.Marshal(metadata)
		require.NoError(t, err)

		updateParams := models.UpdateUserBackupCodesParams{
			ID:            existingUser.ID,
			BackupCodes:   metadataJSON,
			LastUpdated:   int32(time.Now().Unix()),
			LastUpdatedBy: pgtype.Text{String: "migration_test", Valid: true},
		}

		err = db.UpdateUserBackupCodes(ctx, updateParams)
		require.NoError(t, err)

		// Verify the update worked
		backupData, err := db.GetUserBackupCodes(ctx, existingUser.ID)
		require.NoError(t, err)
		assert.NotNil(t, backupData.BackupCodes)

		// Verify metadata structure
		var existingMetadata map[string]interface{}
		err = json.Unmarshal(backupData.BackupCodes, &existingMetadata)
		require.NoError(t, err)
		assert.Equal(t, float64(3), existingMetadata["codes_remaining"])
	})

	t.Run("Database Schema Validation", func(t *testing.T) {
		// Verify the columns exist with correct types using a direct query
		var columnExists bool
		var columnType string

		// Check backup_codes column
		err := dbPool.QueryRow(ctx, `
			SELECT true, data_type 
			FROM information_schema.columns 
			WHERE table_name = 'users' 
			AND column_name = 'backup_codes'
		`).Scan(&columnExists, &columnType)
		require.NoError(t, err)
		assert.True(t, columnExists)
		assert.Equal(t, "json", columnType)

		// Check backup_codes_read column
		err = dbPool.QueryRow(ctx, `
			SELECT true, data_type, column_default
			FROM information_schema.columns 
			WHERE table_name = 'users' 
			AND column_name = 'backup_codes_read'
		`).Scan(&columnExists, &columnType, new(string))
		require.NoError(t, err)
		assert.True(t, columnExists)
		assert.Equal(t, "boolean", columnType)

		// Check index exists
		var indexExists bool
		err = dbPool.QueryRow(ctx, `
			SELECT true
			FROM pg_indexes 
			WHERE tablename = 'users' 
			AND indexname = 'users_backup_codes_read_idx'
		`).Scan(&indexExists)
		require.NoError(t, err)
		assert.True(t, indexExists)
	})
}
