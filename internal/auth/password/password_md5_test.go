// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPasswordMd5Hasher(t *testing.T) {
	t.Run("generate salt", func(t *testing.T) {
		h := NewMd5Hasher()
		salt, err := h.generateSalt()
		assert.Equal(t, nil, err)
		assert.Equal(t, 8, len(salt))
	})

	t.Run("generate hash", func(t *testing.T) {
		h := NewMd5Hasher()
		hash, err := h.GenerateHash(pass)
		assert.Equal(t, nil, err)
		assert.Equal(t, 40, len(hash))

	})

	t.Run("validate password", func(t *testing.T) {
		v := Md5Validator{DefaultMd5Config}
		err := v.ValidateHash(md5Hash, pass)
		assert.Equal(t, nil, err)
	})

	t.Run("validate invalid password", func(t *testing.T) {
		v := Md5Validator{DefaultMd5Config}
		err := v.ValidateHash(md5Hash, invalidPass)
		assert.Equal(t, ErrMismatchedHashAndPassword, err)
	})

	t.Run("test invalid hash", func(t *testing.T) {
		v := Md5Validator{DefaultMd5Config}
		err := v.ValidateHash("123123123123", pass)
		assert.Equal(t, ErrMismatchedHashAndPassword, err)
	})

}
