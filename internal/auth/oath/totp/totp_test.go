// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package totp

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Interop tests taken from https://tools.ietf.org/html/rfc6238#appendix-B,
// we only support sha1 right now

var totp = New(base32.StdEncoding.EncodeToString([]byte("12345678901234567890")), 8, 30)

func TestGenerateTotp(t *testing.T) {
	assert.Equal(t, "94287082", totp.GenerateCustom(time.Unix(59, 0).UTC()))
	assert.Equal(t, "07081804", totp.GenerateCustom(time.Unix(1111111109, 0).UTC()))
	assert.Equal(t, "14050471", totp.GenerateCustom(time.Unix(1111111111, 0).UTC()))
	assert.Equal(t, "89005924", totp.GenerateCustom(time.Unix(1234567890, 0).UTC()))
	assert.Equal(t, "69279037", totp.GenerateCustom(time.Unix(2000000000, 0).UTC()))
	assert.Equal(t, "65353130", totp.GenerateCustom(time.Unix(20000000000, 0).UTC()))
}

func TestValidateTotp(t *testing.T) {
	assert.True(t, totp.ValidateCustom("94287082", time.Unix(59, 0).UTC()))
	assert.False(t, totp.ValidateCustom("94287082", time.Unix(61, 0).UTC()))
}

func TestGenerateSeed(t *testing.T) {
	otp := New("", 6, 30)
	assert.Equal(t, 32, len(otp.GetSeed()))
}
