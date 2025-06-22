// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package backupcodes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	logger "log/slog"

	"github.com/undernetirc/cservice-api/internal/config"
)

// EncryptionError represents an error during encryption/decryption
type EncryptionError struct {
	Operation string
	Err       error
}

func (e *EncryptionError) Error() string {
	return fmt.Sprintf("encryption %s error: %v", e.Operation, e.Err)
}

func (e *EncryptionError) Unwrap() error {
	return e.Err
}

// BackupCodeEncryption handles encryption and decryption of backup codes
type BackupCodeEncryption struct {
	key []byte
}

// NewBackupCodeEncryption creates a new backup code encryption instance
func NewBackupCodeEncryption() (*BackupCodeEncryption, error) {
	keyString := config.ServiceBackupCodesEncryptionKey.GetString()
	if keyString == "" {
		return nil, &EncryptionError{
			Operation: "initialization",
			Err:       errors.New("backup codes encryption key not configured"),
		}
	}

	// Decode the base64-encoded key
	key, err := base64.StdEncoding.DecodeString(keyString)
	if err != nil {
		return nil, &EncryptionError{
			Operation: "key_decode",
			Err:       fmt.Errorf("failed to decode encryption key: %w", err),
		}
	}

	// Validate key length for AES-256
	if len(key) != 32 {
		return nil, &EncryptionError{
			Operation: "key_validation",
			Err:       fmt.Errorf("encryption key must be 32 bytes for AES-256, got %d bytes", len(key)),
		}
	}

	return &BackupCodeEncryption{key: key}, nil
}

// Encrypt encrypts the given plaintext using AES-256-GCM
func (e *BackupCodeEncryption) Encrypt(plaintext []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", &EncryptionError{
			Operation: "encrypt",
			Err:       errors.New("plaintext cannot be empty"),
		}
	}

	// Create AES cipher
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", &EncryptionError{
			Operation: "encrypt",
			Err:       fmt.Errorf("failed to create AES cipher: %w", err),
		}
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", &EncryptionError{
			Operation: "encrypt",
			Err:       fmt.Errorf("failed to create GCM: %w", err),
		}
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", &EncryptionError{
			Operation: "encrypt",
			Err:       fmt.Errorf("failed to generate nonce: %w", err),
		}
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Encode to base64 for storage
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	logger.Debug(
		"Successfully encrypted backup codes",
		"plaintext_length",
		len(plaintext),
		"ciphertext_length",
		len(ciphertext),
	)
	return encoded, nil
}

// Decrypt decrypts the given base64-encoded ciphertext using AES-256-GCM
func (e *BackupCodeEncryption) Decrypt(encodedCiphertext string) ([]byte, error) {
	if encodedCiphertext == "" {
		return nil, &EncryptionError{
			Operation: "decrypt",
			Err:       errors.New("ciphertext cannot be empty"),
		}
	}

	// Decode from base64
	ciphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return nil, &EncryptionError{
			Operation: "decrypt",
			Err:       fmt.Errorf("failed to decode base64 ciphertext: %w", err),
		}
	}

	// Create AES cipher
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, &EncryptionError{
			Operation: "decrypt",
			Err:       fmt.Errorf("failed to create AES cipher: %w", err),
		}
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &EncryptionError{
			Operation: "decrypt",
			Err:       fmt.Errorf("failed to create GCM: %w", err),
		}
	}

	// Validate ciphertext length
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, &EncryptionError{
			Operation: "decrypt",
			Err: fmt.Errorf(
				"ciphertext too short: expected at least %d bytes, got %d",
				nonceSize,
				len(ciphertext),
			),
		}
	}

	// Extract nonce and encrypted data
	nonce, encryptedData := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, &EncryptionError{
			Operation: "decrypt",
			Err:       fmt.Errorf("failed to decrypt data: %w", err),
		}
	}

	logger.Debug(
		"Successfully decrypted backup codes",
		"ciphertext_length",
		len(ciphertext),
		"plaintext_length",
		len(plaintext),
	)
	return plaintext, nil
}

// GenerateEncryptionKey generates a new 256-bit encryption key for backup codes
func GenerateEncryptionKey() (string, error) {
	key := make([]byte, 32) // 256 bits
	_, err := rand.Read(key)
	if err != nil {
		return "", fmt.Errorf("failed to generate encryption key: %w", err)
	}

	// Encode to base64 for configuration storage
	encoded := base64.StdEncoding.EncodeToString(key)
	logger.Info("Generated new backup codes encryption key", "key_length", len(key))

	return encoded, nil
}
