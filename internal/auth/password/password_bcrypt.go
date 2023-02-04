// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package password provides password hashing and validation.
package password

import (
	"golang.org/x/crypto/bcrypt"
)

// BcryptConfig is the configuration for bcrypt hashing.
type BcryptConfig struct {
	// Cost is the bcrypt cost parameter. The cost parameter controls the
	// amount of computation required to hash the password. The higher the
	// cost, the more secure the password hash will be. The default cost is
	// 10.
	Cost int
}

// BcryptHasher is the bcrypt implementation of the Hasher interface.
type BcryptHasher struct {
	*BcryptConfig
}

// DefaultBcryptConfig is the default configuration for bcrypt hashing.
var DefaultBcryptConfig = &BcryptConfig{Cost: 10}

// NewBcryptHasher returns a new bcrypt hasher with the default configuration.
func NewBcryptHasher(config *BcryptConfig) *BcryptHasher {
	if config == nil {
		config = DefaultBcryptConfig
	}
	return &BcryptHasher{config}
}

// GenerateHash generates a bcrypt hash of the given password.
func (h *BcryptHasher) GenerateHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), h.Cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// BcryptValidator is the bcrypt implementation of the Validator interface.
type BcryptValidator struct{}

// ValidateHash validates the given password hash against the given password.
func (v BcryptValidator) ValidateHash(passwordHash string, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return ErrMismatchedHashAndPassword
	}
	return err
}
