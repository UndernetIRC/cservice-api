// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package password

import (
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"gopkg.in/go-playground/assert.v1"
)

const md5Hash = "1234567837a1f6fd442168ba0b6ce86006116f53"                        // password is 123qwe
const bcryptHash = "$2a$12$uALFNI10cr/b73fUWsMyOOx1DRT4n41UZiiMClZIQil/mBKs4szrW" // password is 123qwe
const invalidBcryptHash = "$2a$12$uALFNI10cr/b73fUWsMyOOx1DR"
const pass = "123qwe"
const invalidPass = "123qwe123"

func TestPassword(t *testing.T) {
	t.Run("md5 valid password", func(t *testing.T) {
		v := GetValidatorFunc(md5Hash)
		err := v(pass)
		assert.Equal(t, err, nil)
	})

	t.Run("md5 invalid password", func(t *testing.T) {
		v := GetValidatorFunc(md5Hash)
		err := v(invalidPass)
		assert.Equal(t, err, ErrMismatchedHashAndPassword)
	})

	t.Run("bcrypt valid password", func(t *testing.T) {
		v := GetValidatorFunc(bcryptHash)
		err := v(pass)
		assert.Equal(t, err, nil)
	})

	t.Run("bcrypt invalid password", func(t *testing.T) {
		v := GetValidatorFunc(bcryptHash)
		err := v(invalidPass)
		assert.Equal(t, err, ErrMismatchedHashAndPassword)
	})

	t.Run("bcrypt invalid hash", func(t *testing.T) {
		v := GetValidatorFunc(invalidBcryptHash)
		err := v(pass)
		assert.Equal(t, err, bcrypt.ErrHashTooShort)
	})

	t.Run("generate bcrypt with too long password", func(t *testing.T) {
		_, err := GenerateHash(Bcrypt, strings.Repeat("a", 80))
		assert.Equal(t, err, bcrypt.ErrPasswordTooLong)
	})

	t.Run("should return bcrypt validator func", func(t *testing.T) {
		v := GetValidatorFunc(bcryptHash)
		assert.Equal(t, reflect.TypeOf(v).String(), "password.ValidatorFunction")
		assert.Equal(t, v(pass), nil)
	})

	t.Run("should return md5 validator func", func(t *testing.T) {
		v := GetValidatorFunc(md5Hash)
		assert.Equal(t, v(pass), nil)
	})

	t.Run("should return md5 validator func and fail with invalid password", func(t *testing.T) {
		v := GetValidatorFunc(md5Hash)
		assert.Equal(t, v(invalidPass), ErrMismatchedHashAndPassword)
	})

	t.Run("test ValidateHash()", func(t *testing.T) {
		err := ValidateHash(Md5Val, md5Hash, pass)
		assert.Equal(t, err, nil)
	})

}
