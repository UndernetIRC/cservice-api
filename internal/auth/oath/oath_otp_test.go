// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package oath

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOathGenerateNewSeed(t *testing.T) {
	otp := New("", 6)
	assert.NotEqual(t, "", otp.GetSeed())
}

func TestOathSeedNotReplaced(t *testing.T) {
	otp := New("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 6)
	assert.Equal(t, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", otp.GetSeed())
	assert.Equal(t, 6, otp.otpLength)
}
