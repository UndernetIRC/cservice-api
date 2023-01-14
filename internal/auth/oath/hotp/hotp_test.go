// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package hotp

import (
	"encoding/base32"
	"testing"

	"gopkg.in/go-playground/assert.v1"
)

// Interop tests taken from http://tools.ietf.org/html/rfc4226#appendix-D

var hotp = New(base32.StdEncoding.EncodeToString([]byte("12345678901234567890")), 6)

func TestGenerateHotp(t *testing.T) {
	assert.Equal(t, "755224", hotp.Generate(0))
	assert.Equal(t, "287082", hotp.Generate(1))
	assert.Equal(t, "359152", hotp.Generate(2))
	assert.Equal(t, "969429", hotp.Generate(3))
	assert.Equal(t, "338314", hotp.Generate(4))
	assert.Equal(t, "254676", hotp.Generate(5))
	assert.Equal(t, "287922", hotp.Generate(6))
	assert.Equal(t, "162583", hotp.Generate(7))
	assert.Equal(t, "399871", hotp.Generate(8))
	assert.Equal(t, "520489", hotp.Generate(9))
}
