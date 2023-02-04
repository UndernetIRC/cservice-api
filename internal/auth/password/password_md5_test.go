// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package password

import (
	"testing"

	"gopkg.in/go-playground/assert.v1"
)

func TestPasswordMd5Hasher(t *testing.T) {
	t.Run("generate salt", func(t *testing.T) {
		h := NewMd5Hasher()
		salt := h.generateSalt()
		assert.Equal(t, len(salt), 8)
	})

	t.Run("generate hash", func(t *testing.T) {
		h := NewMd5Hasher()
		hash, err := h.GenerateHash(pass)
		assert.Equal(t, err, nil)
		assert.Equal(t, len(hash), 40)

	})

	t.Run("validate password", func(t *testing.T) {
		v := Md5Validator{DefaultMd5Config}
		err := v.ValidateHash(md5Hash, pass)
		assert.Equal(t, err, nil)
	})

	t.Run("validate invalid password", func(t *testing.T) {
		v := Md5Validator{DefaultMd5Config}
		err := v.ValidateHash(md5Hash, invalidPass)
		assert.Equal(t, err, ErrMismatchedHashAndPassword)
	})

	t.Run("test invalid hash", func(t *testing.T) {
		v := Md5Validator{DefaultMd5Config}
		err := v.ValidateHash("123123123123", pass)
		assert.Equal(t, err, ErrMismatchedHashAndPassword)
	})

}
