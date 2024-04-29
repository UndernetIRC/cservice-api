// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package password provides password hashing and validation.
package password

import (
	"errors"
	"strings"
)

// Hasher is the interface that wraps the GenerateHash method.
type Hasher interface {
	GenerateHash(password string) (string, error)
}

// Validator is the interface that wraps the ValidateHash method.
type Validator interface {
	ValidateHash(passwordHash string, password string) error
}

var (
	// Md5 is the MD5 implementation of the Hasher interface.
	Md5 = NewMd5Hasher()
	// Md5Val is the MD5 implementation of the Validator interface.
	Md5Val = Md5Validator{DefaultMd5Config}
	// Bcrypt is the bcrypt implementation of the Hasher interface.
	Bcrypt = NewBcryptHasher(nil)
	// BcryptVal is the bcrypt implementation of the Validator interface.
	BcryptVal = BcryptValidator{}
	// DefaultHasher is the default hasher used by the package.
	DefaultHasher = NewMd5Hasher()
)

// GenerateHash generates a hash of the given password using the provided hasher algorithm.
func GenerateHash(h Hasher, password string) (string, error) {
	if h == nil {
		return "", errors.New("missing hasher")
	}
	return h.GenerateHash(password)
}

// DetermineValidatorAlgorithm determines the validator algorithm based on the given hash.
func DetermineValidatorAlgorithm(hash string) Validator {
	switch {
	case strings.HasPrefix(hash, "$2a"):
		return BcryptVal
	case len(hash) == 40:
		return Md5Val
	default:
		return nil
	}
}

// ValidatorFunction is a function type that validates a password hash against a password.
type ValidatorFunction func(password string) error

// GetValidatorFunc determines the validator function based on the given hash.
func GetValidatorFunc(hash string) ValidatorFunction {
	fn := DetermineValidatorAlgorithm(hash)

	f := func(password string) error {
		if fn == nil {
			return ErrUnknownHashAlgorithm
		}

		return fn.ValidateHash(hash, password)
	}
	return f
}

// ValidateHash validates the given password hash against the given password using the provided validator algorithm.
func ValidateHash(v Validator, hash string, password string) error {
	if v == nil {
		return errors.New("missing validator")
	}
	return v.ValidateHash(hash, password)
}
