// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package backupcodes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	logger "log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/undernetirc/cservice-api/internal/auth/password"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

const (
	// BackupCodeCount is the number of backup codes to generate
	BackupCodeCount = 10
	// BackupCodePartLength is the length of each part of the backup code (before and after hyphen)
	BackupCodePartLength = 5
)

// BackupCodeGenerator handles the generation of backup codes
type BackupCodeGenerator struct {
	db models.ServiceInterface
}

// NewBackupCodeGenerator creates a new backup code generator
func NewBackupCodeGenerator(db models.ServiceInterface) *BackupCodeGenerator {
	return &BackupCodeGenerator{
		db: db,
	}
}

// BackupCode represents a single backup code with its bcrypt hash
type BackupCode struct {
	Hash string `json:"hash"`
}

// Metadata represents the JSON structure stored in the database
type Metadata struct {
	BackupCodes    string `json:"backup_codes"`
	GeneratedAt    string `json:"generated_at"`
	CodesRemaining int    `json:"codes_remaining"`
}

// GenerateBackupCodes generates 10 unique backup codes in the format 'abcde-12345'
func (g *BackupCodeGenerator) GenerateBackupCodes() ([]string, error) {
	codes := make([]string, BackupCodeCount)
	codeSet := make(map[string]bool) // To ensure uniqueness

	for i := 0; i < BackupCodeCount; i++ {
		for {
			code, err := generateSingleBackupCode()
			if err != nil {
				return nil, fmt.Errorf("failed to generate backup code: %w", err)
			}

			// Ensure uniqueness
			if !codeSet[code] {
				codes[i] = code
				codeSet[code] = true
				break
			}
		}
	}

	return codes, nil
}

// generateSingleBackupCode generates a single backup code in the format 'abcde-12345'
func generateSingleBackupCode() (string, error) {
	part1 := helper.GenerateSecureToken(BackupCodePartLength)
	part2 := helper.GenerateSecureToken(BackupCodePartLength)

	return fmt.Sprintf("%s-%s", part1, part2), nil
}

// ValidateBackupCodeFormat validates that a backup code matches the expected format
func ValidateBackupCodeFormat(code string) error {
	// Expected format: 5 alphanumeric + hyphen + 5 alphanumeric
	pattern := `^[a-zA-Z0-9]{5}-[a-zA-Z0-9]{5}$`
	matched, err := regexp.MatchString(pattern, code)
	if err != nil {
		return fmt.Errorf("failed to validate backup code format: %w", err)
	}

	if !matched {
		return errors.New(
			"backup code must be in format 'abcde-12345' (5 alphanumeric characters, hyphen, 5 alphanumeric characters)",
		)
	}

	return nil
}

// NormalizeBackupCode normalizes user input by removing spaces and converting to expected format
func NormalizeBackupCode(input string) string {
	// Remove all spaces
	normalized := strings.ReplaceAll(input, " ", "")

	// If there's no hyphen but the length is 10, add one in the middle
	if !strings.Contains(normalized, "-") && len(normalized) == 10 {
		normalized = normalized[:5] + "-" + normalized[5:]
	}

	return normalized
}

// GenerateAndStoreBackupCodes generates backup codes and stores them in the database
func (g *BackupCodeGenerator) GenerateAndStoreBackupCodes(
	ctx context.Context,
	userID int32,
	updatedBy string,
) ([]string, error) {
	logger.Info("Generating backup codes for user", "user_id", userID)

	// Generate the backup codes
	codes, err := g.GenerateBackupCodes()
	if err != nil {
		logger.Error("Failed to generate backup codes", "user_id", userID, "error", err)
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Initialize bcrypt hasher with default cost (10)
	hasher := password.NewBcryptHasher(nil)

	// Create backup code structs with bcrypt hashes
	backupCodes := make([]BackupCode, len(codes))
	for i, code := range codes {
		hash, err := hasher.GenerateHash(code)
		if err != nil {
			logger.Error("Failed to hash backup code", "user_id", userID, "error", err)
			return nil, fmt.Errorf("failed to hash backup code: %w", err)
		}
		backupCodes[i] = BackupCode{
			Hash: hash,
		}
	}

	// Convert to JSON for storage
	jsonData, err := json.Marshal(backupCodes)
	if err != nil {
		logger.Error("Failed to marshal backup codes to JSON", "user_id", userID, "error", err)
		return nil, fmt.Errorf("failed to marshal backup codes: %w", err)
	}

	// Create metadata structure
	metadata := Metadata{
		BackupCodes:    string(jsonData),
		GeneratedAt:    time.Now().Format(time.RFC3339),
		CodesRemaining: len(codes),
	}

	// Convert metadata to JSON for storage
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		logger.Error("Failed to marshal backup codes metadata", "user_id", userID, "error", err)
		return nil, fmt.Errorf("failed to marshal backup codes metadata: %w", err)
	}

	// Store in database
	updateParams := models.UpdateUserBackupCodesParams{
		ID:            userID,
		BackupCodes:   metadataJSON,
		LastUpdated:   int32(time.Now().Unix()), // #nosec G115 - Unix timestamps fit in int32 until 2038
		LastUpdatedBy: pgtype.Text{String: updatedBy, Valid: true},
	}

	err = g.db.UpdateUserBackupCodes(ctx, updateParams)
	if err != nil {
		logger.Error("Failed to store backup codes in database", "user_id", userID, "error", err)
		return nil, fmt.Errorf("failed to store backup codes: %w", err)
	}

	logger.Info("Successfully generated and stored backup codes", "user_id", userID, "count", len(codes))
	return codes, nil
}

// GetBackupCodes retrieves backup codes for a user
func (g *BackupCodeGenerator) GetBackupCodes(ctx context.Context, userID int32) ([]BackupCode, error) {
	logger.Debug("Retrieving backup codes for user", "user_id", userID)

	// Get backup codes from database
	backupData, err := g.db.GetUserBackupCodes(ctx, userID)
	if err != nil {
		logger.Error("Failed to retrieve backup codes from database", "user_id", userID, "error", err)
		return nil, fmt.Errorf("failed to retrieve backup codes: %w", err)
	}

	// Check if user has backup codes
	if len(backupData.BackupCodes) == 0 {
		logger.Debug("User has no backup codes", "user_id", userID)
		return nil, nil
	}

	// Parse metadata structure
	var metadata Metadata
	err = json.Unmarshal(backupData.BackupCodes, &metadata)
	if err != nil {
		logger.Error("Failed to unmarshal backup codes metadata", "user_id", userID, "error", err)
		return nil, fmt.Errorf("failed to unmarshal backup codes metadata: %w", err)
	}

	// Unmarshal backup codes from JSON
	var backupCodes []BackupCode
	err = json.Unmarshal([]byte(metadata.BackupCodes), &backupCodes)
	if err != nil {
		logger.Error("Failed to unmarshal backup codes", "user_id", userID, "error", err)
		return nil, fmt.Errorf("failed to unmarshal backup codes: %w", err)
	}

	logger.Debug("Successfully retrieved backup codes", "user_id", userID, "count", len(backupCodes))
	return backupCodes, nil
}

// GetBackupCodesReadStatus returns whether the user has seen their backup codes
func (g *BackupCodeGenerator) GetBackupCodesReadStatus(ctx context.Context, userID int32) (bool, error) {
	backupData, err := g.db.GetUserBackupCodes(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get backup codes read status: %w", err)
	}

	return backupData.BackupCodesRead.Bool, nil
}

// UpdateBackupCodes stores updated backup codes (used when codes are consumed)
func (g *BackupCodeGenerator) UpdateBackupCodes(
	ctx context.Context,
	userID int32,
	codes []BackupCode,
	updatedBy string,
) error {
	logger.Debug("Updating backup codes for user", "user_id", userID, "count", len(codes))

	// Convert to JSON
	jsonData, err := json.Marshal(codes)
	if err != nil {
		logger.Error("Failed to marshal updated backup codes", "user_id", userID, "error", err)
		return fmt.Errorf("failed to marshal backup codes: %w", err)
	}

	// Get current metadata to preserve generated_at timestamp
	backupData, err := g.db.GetUserBackupCodes(ctx, userID)
	if err != nil {
		logger.Error("Failed to get current backup codes metadata", "user_id", userID, "error", err)
		return fmt.Errorf("failed to get current backup codes metadata: %w", err)
	}

	var generatedAt string
	if len(backupData.BackupCodes) > 0 {
		var currentMetadata Metadata
		if json.Unmarshal(backupData.BackupCodes, &currentMetadata) == nil {
			generatedAt = currentMetadata.GeneratedAt
		}
	}
	if generatedAt == "" {
		generatedAt = time.Now().Format(time.RFC3339)
	}

	// Count remaining codes (all codes in the array are unused)
	codesRemaining := len(codes)

	// Create metadata structure
	metadata := Metadata{
		BackupCodes:    string(jsonData),
		GeneratedAt:    generatedAt,
		CodesRemaining: codesRemaining,
	}

	// Convert metadata to JSON for storage
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		logger.Error("Failed to marshal updated backup codes metadata", "user_id", userID, "error", err)
		return fmt.Errorf("failed to marshal backup codes metadata: %w", err)
	}

	// Update in database
	updateParams := models.UpdateUserBackupCodesParams{
		ID:            userID,
		BackupCodes:   metadataJSON,
		LastUpdated:   int32(time.Now().Unix()), // #nosec G115 - Unix timestamps fit in int32 until 2038
		LastUpdatedBy: pgtype.Text{String: updatedBy, Valid: true},
	}

	err = g.db.UpdateUserBackupCodes(ctx, updateParams)
	if err != nil {
		logger.Error("Failed to update backup codes in database", "user_id", userID, "error", err)
		return fmt.Errorf("failed to update backup codes: %w", err)
	}

	logger.Debug("Successfully updated backup codes", "user_id", userID)
	return nil
}

// GetBackupCodesCount returns the number of remaining backup codes without decryption
func (g *BackupCodeGenerator) GetBackupCodesCount(ctx context.Context, userID int32) (int, error) {
	backupData, err := g.db.GetUserBackupCodes(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to get backup codes metadata: %w", err)
	}

	if len(backupData.BackupCodes) == 0 {
		return 0, nil
	}

	var metadata Metadata
	err = json.Unmarshal(backupData.BackupCodes, &metadata)
	if err != nil {
		return 0, fmt.Errorf("failed to unmarshal backup codes metadata: %w", err)
	}

	return metadata.CodesRemaining, nil
}

// GetBackupCodesGeneratedAt returns when backup codes were generated without decryption
func (g *BackupCodeGenerator) GetBackupCodesGeneratedAt(ctx context.Context, userID int32) (string, error) {
	backupData, err := g.db.GetUserBackupCodes(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("failed to get backup codes metadata: %w", err)
	}

	if len(backupData.BackupCodes) == 0 {
		return "", nil
	}

	var metadata Metadata
	err = json.Unmarshal(backupData.BackupCodes, &metadata)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal backup codes metadata: %w", err)
	}

	return metadata.GeneratedAt, nil
}

// ConsumeBackupCode removes a backup code from the array and updates the count
func (g *BackupCodeGenerator) ConsumeBackupCode(ctx context.Context, userID int32, codeToConsume string, updatedBy string) (bool, error) {
	logger.Debug("Consuming backup code for user", "user_id", userID)

	// Get and decrypt current backup codes
	backupCodes, err := g.GetBackupCodes(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get backup codes: %w", err)
	}

	if len(backupCodes) == 0 {
		logger.Debug("User has no backup codes to consume", "user_id", userID)
		return false, nil
	}

	// Normalize the input code
	normalizedInput := NormalizeBackupCode(codeToConsume)

	// Initialize bcrypt validator for comparing hashes
	validator := password.BcryptValidator{}

	// Find and remove the matching code from the array using bcrypt comparison
	codeFound := false
	newBackupCodes := make([]BackupCode, 0, len(backupCodes))
	for _, code := range backupCodes {
		// Use bcrypt to compare the input with the stored hash
		if !codeFound && validator.ValidateHash(code.Hash, normalizedInput) == nil {
			// Skip this code (remove it from the array)
			codeFound = true
			continue
		}
		// Keep all other codes
		newBackupCodes = append(newBackupCodes, code)
	}

	if !codeFound {
		logger.Debug("Backup code not found or already used", "user_id", userID)
		return false, nil
	}

	// Update the backup codes in the database with the reduced array
	err = g.UpdateBackupCodes(ctx, userID, newBackupCodes, updatedBy)
	if err != nil {
		logger.Error("Failed to update backup codes after consumption", "user_id", userID, "error", err)
		return false, fmt.Errorf("failed to update backup codes: %w", err)
	}

	logger.Info("Successfully consumed backup code", "user_id", userID, "remaining_codes", len(newBackupCodes))
	return true, nil
}
