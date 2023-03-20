// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package password provides password hashing and validation.
package password

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// Md5Config contains the settings specific for md5 hashing.
type Md5Config struct {
	SaltLength int
}

// Md5Hasher is the md5 implementation of the Hasher interface.
type Md5Hasher struct {
	*Md5Config
}

const saltLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// DefaultMd5Config is the default configuration for md5 hashing.
var DefaultMd5Config = &Md5Config{SaltLength: 8}

// NewMd5Hasher returns a new md5 hasher with the default configuration.
func NewMd5Hasher() *Md5Hasher {
	return &Md5Hasher{Md5Config: DefaultMd5Config}
}

// Hash returns the md5 byte hash of the given password and salt.
func (h *Md5Hasher) Hash(password string, salt []byte) ([]byte, error) {
	m := md5.New()
	m.Write(salt)
	m.Write([]byte(password))
	return m.Sum(nil), nil
}

// GenerateHash generates a md5 hash of the given password.
func (h *Md5Hasher) GenerateHash(password string) (string, error) {
	salt, serr := h.generateSalt()
	if serr != nil {
		return "", serr
	}
	key, err := h.Hash(password, []byte(salt))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%s", salt, hex.EncodeToString(key)), nil
}

// generateSalt generates a random salt of the given length compatible with UnderNETs legacy implementation.
func (h *Md5Hasher) generateSalt() (string, error) {
	salt := make([]byte, h.SaltLength)

	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	for i := range salt {
		salt[i] = saltLetters[salt[i]%byte(len(saltLetters))]
	}

	return string(salt), nil
}

// Md5Validator is the md5 implementation of the Validator interface.
type Md5Validator struct {
	*Md5Config
}

// ValidateHash validates the given password hash against the given password.
// It returns an error if the password is invalid.
func (v Md5Validator) ValidateHash(passwordHash string, password string) error {
	salt := passwordHash[0:v.SaltLength]
	hash := passwordHash[v.SaltLength:]

	keyHasher := NewMd5Hasher()
	key, err := keyHasher.Hash(password, []byte(salt))
	if err != nil {
		return err
	}

	bytesHash, err := hex.DecodeString(hash)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(key, bytesHash) == 1 {
		return nil
	}
	return ErrMismatchedHashAndPassword
}
