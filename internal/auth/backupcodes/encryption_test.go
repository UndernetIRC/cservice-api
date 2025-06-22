// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package backupcodes

import (
	"encoding/base64"
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/undernetirc/cservice-api/internal/config"
)

func TestNewBackupCodeEncryption(t *testing.T) {
	// Generate a test key
	testKey := generateTestKey(t)

	t.Run("success with valid key", func(t *testing.T) {
		// Set up environment
		oldKey := os.Getenv("CSERVICE_SERVICE_BACKUP_CODES_ENCRYPTION_KEY")
		defer func() {
			os.Setenv("CSERVICE_SERVICE_BACKUP_CODES_ENCRYPTION_KEY", oldKey)
			viper.Reset()
		}()

		os.Setenv("CSERVICE_SERVICE_BACKUP_CODES_ENCRYPTION_KEY", testKey)

		// Initialize config to pick up new env var
		viper.Reset()
		config.InitConfig("")

		encryption, err := NewBackupCodeEncryption()
		require.NoError(t, err)
		assert.NotNil(t, encryption)
		assert.Len(t, encryption.key, 32) // 256 bits
	})

	t.Run("error with missing key", func(t *testing.T) {
		// Unset environment variable
		oldKey := os.Getenv("CSERVICE_SERVICE_BACKUP_CODES_ENCRYPTION_KEY")
		defer func() {
			os.Setenv("CSERVICE_SERVICE_BACKUP_CODES_ENCRYPTION_KEY", oldKey)
			viper.Reset()
		}()

		os.Unsetenv("CSERVICE_SERVICE_BACKUP_CODES_ENCRYPTION_KEY")

		// Initialize config
		viper.Reset()
		config.InitConfig("")

		_, err := NewBackupCodeEncryption()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "backup codes encryption key not configured")
	})

	t.Run("error with invalid base64 key", func(t *testing.T) {
		// Set invalid base64
		oldKey := os.Getenv("CSERVICE_SERVICE_BACKUP_CODES_ENCRYPTION_KEY")
		defer func() {
			os.Setenv("CSERVICE_SERVICE_BACKUP_CODES_ENCRYPTION_KEY", oldKey)
			viper.Reset()
		}()

		os.Setenv("CSERVICE_SERVICE_BACKUP_CODES_ENCRYPTION_KEY", "invalid-base64-!")

		viper.Reset()
		config.InitConfig("")

		_, err := NewBackupCodeEncryption()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode encryption key")
	})

	t.Run("error with wrong key length", func(t *testing.T) {
		// Generate 16-byte key instead of 32
		shortKey := make([]byte, 16)
		for i := range shortKey {
			shortKey[i] = byte(i)
		}
		encodedShortKey := base64.StdEncoding.EncodeToString(shortKey)

		oldKey := os.Getenv("CSERVICE_SERVICE_BACKUP_CODES_ENCRYPTION_KEY")
		defer func() {
			os.Setenv("CSERVICE_SERVICE_BACKUP_CODES_ENCRYPTION_KEY", oldKey)
			viper.Reset()
		}()

		os.Setenv("CSERVICE_SERVICE_BACKUP_CODES_ENCRYPTION_KEY", encodedShortKey)

		viper.Reset()
		config.InitConfig("")

		_, err := NewBackupCodeEncryption()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "encryption key must be 32 bytes")
	})
}

func TestEncryptDecrypt(t *testing.T) {
	encryption := setupTestEncryption(t)

	t.Run("encrypt and decrypt roundtrip", func(t *testing.T) {
		plaintext := []byte(`{"codes":[{"code":"abcde-12345","used":false}]}`)

		// Encrypt
		encrypted, err := encryption.Encrypt(plaintext)
		require.NoError(t, err)
		assert.NotEmpty(t, encrypted)

		// Decrypt
		decrypted, err := encryption.Decrypt(encrypted)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("encrypt produces different output each time", func(t *testing.T) {
		plaintext := []byte("test data")

		encrypted1, err := encryption.Encrypt(plaintext)
		require.NoError(t, err)

		encrypted2, err := encryption.Encrypt(plaintext)
		require.NoError(t, err)

		// Should be different due to random nonce
		assert.NotEqual(t, encrypted1, encrypted2)

		// But both should decrypt to same plaintext
		decrypted1, err := encryption.Decrypt(encrypted1)
		require.NoError(t, err)

		decrypted2, err := encryption.Decrypt(encrypted2)
		require.NoError(t, err)

		assert.Equal(t, plaintext, decrypted1)
		assert.Equal(t, plaintext, decrypted2)
	})

	t.Run("encrypt empty data fails", func(t *testing.T) {
		_, err := encryption.Encrypt([]byte{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "plaintext cannot be empty")
	})

	t.Run("encrypt nil data fails", func(t *testing.T) {
		_, err := encryption.Encrypt(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "plaintext cannot be empty")
	})

	t.Run("decrypt empty string fails", func(t *testing.T) {
		_, err := encryption.Decrypt("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ciphertext cannot be empty")
	})

	t.Run("decrypt invalid base64 fails", func(t *testing.T) {
		_, err := encryption.Decrypt("invalid-base64-!")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode base64 ciphertext")
	})

	t.Run("decrypt too short ciphertext fails", func(t *testing.T) {
		// Create a base64-encoded string that's too short
		shortData := []byte("short")
		encoded := base64.StdEncoding.EncodeToString(shortData)

		_, err := encryption.Decrypt(encoded)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ciphertext too short")
	})

	t.Run("decrypt corrupted data fails", func(t *testing.T) {
		plaintext := []byte("test data")

		// Encrypt normally
		encrypted, err := encryption.Encrypt(plaintext)
		require.NoError(t, err)

		// Decode, corrupt, and re-encode
		decoded, err := base64.StdEncoding.DecodeString(encrypted)
		require.NoError(t, err)

		// Flip a bit in the middle (after nonce)
		if len(decoded) > 20 {
			decoded[20] ^= 1
		}

		corrupted := base64.StdEncoding.EncodeToString(decoded)

		// Should fail to decrypt
		_, err = encryption.Decrypt(corrupted)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt data")
	})
}

func TestEncryptionWithBackupCodes(t *testing.T) {
	encryption := setupTestEncryption(t)

	t.Run("encrypt backup codes JSON", func(t *testing.T) {
		// Convert to JSON
		jsonData := `[{"code":"abcde-12345","used":false},{"code":"fghij-67890","used":true},{"code":"klmno-13579","used":false}]`
		plaintext := []byte(jsonData)

		// Encrypt
		encrypted, err := encryption.Encrypt(plaintext)
		require.NoError(t, err)

		// Decrypt and verify
		decrypted, err := encryption.Decrypt(encrypted)
		require.NoError(t, err)

		assert.Equal(t, plaintext, decrypted)
		assert.Contains(t, string(decrypted), "abcde-12345")
		assert.Contains(t, string(decrypted), "fghij-67890")
		assert.Contains(t, string(decrypted), "klmno-13579")
	})
}

func TestGenerateEncryptionKey(t *testing.T) {
	t.Run("generates valid key", func(t *testing.T) {
		key, err := GenerateEncryptionKey()
		require.NoError(t, err)
		assert.NotEmpty(t, key)

		// Decode and check length
		decoded, err := base64.StdEncoding.DecodeString(key)
		require.NoError(t, err)
		assert.Len(t, decoded, 32) // 256 bits
	})

	t.Run("generates different keys", func(t *testing.T) {
		key1, err := GenerateEncryptionKey()
		require.NoError(t, err)

		key2, err := GenerateEncryptionKey()
		require.NoError(t, err)

		assert.NotEqual(t, key1, key2)
	})

	t.Run("generated key works for encryption", func(t *testing.T) {
		// Generate a new key
		keyString, err := GenerateEncryptionKey()
		require.NoError(t, err)

		// Use it to create encryption instance
		oldKey := os.Getenv("CSERVICE_SERVICE_BACKUP_CODES_ENCRYPTION_KEY")
		defer func() {
			os.Setenv("CSERVICE_SERVICE_BACKUP_CODES_ENCRYPTION_KEY", oldKey)
			viper.Reset()
		}()

		os.Setenv("CSERVICE_SERVICE_BACKUP_CODES_ENCRYPTION_KEY", keyString)

		viper.Reset()
		config.InitConfig("")

		encryption, err := NewBackupCodeEncryption()
		require.NoError(t, err)

		// Test encryption/decryption
		plaintext := []byte("test data")
		encrypted, err := encryption.Encrypt(plaintext)
		require.NoError(t, err)

		decrypted, err := encryption.Decrypt(encrypted)
		require.NoError(t, err)

		assert.Equal(t, plaintext, decrypted)
	})
}

// Helper functions for tests

func generateTestKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func setupTestEncryption(t *testing.T) *BackupCodeEncryption {
	t.Helper()

	testKey := generateTestKey(t)

	// Set up environment
	oldKey := os.Getenv("CSERVICE_SERVICE_BACKUP_CODES_ENCRYPTION_KEY")
	t.Cleanup(func() {
		os.Setenv("CSERVICE_SERVICE_BACKUP_CODES_ENCRYPTION_KEY", oldKey)
		viper.Reset()
	})

	os.Setenv("CSERVICE_SERVICE_BACKUP_CODES_ENCRYPTION_KEY", testKey)
	viper.Reset()
	config.InitConfig("")

	encryption, err := NewBackupCodeEncryption()
	require.NoError(t, err)

	return encryption
}
