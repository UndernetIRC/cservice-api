// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package password

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"gopkg.in/go-playground/assert.v1"
)

func TestBcryptPassword(t *testing.T) {
	t.Run("generate hash and validate it against password", func(t *testing.T) {
		h := NewBcryptHasher(&BcryptConfig{12})
		hash, err := h.GenerateHash(pass)
		assert.Equal(t, err, nil)

		v := BcryptValidator{}
		err = v.ValidateHash(hash, pass)
		assert.Equal(t, err, nil)
	})

	t.Run("bcrypt invalid password", func(t *testing.T) {
		v := BcryptValidator{}
		err := v.ValidateHash(bcryptHash, invalidPass)
		assert.Equal(t, err, ErrMismatchedHashAndPassword)
	})

	t.Run("test invalid hash", func(t *testing.T) {
		v := BcryptValidator{}
		err := v.ValidateHash(invalidBcryptHash, pass)
		assert.Equal(t, err, bcrypt.ErrHashTooShort)
	})

	t.Run("test password too long", func(t *testing.T) {
		h := NewBcryptHasher(&BcryptConfig{12})
		_, err := h.GenerateHash(strings.Repeat("a", 80))
		assert.Equal(t, err, bcrypt.ErrPasswordTooLong)
	})
}
