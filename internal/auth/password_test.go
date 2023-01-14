// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var md5Hash = "1234567837a1f6fd442168ba0b6ce86006116f53"

func TestMd5ValidPassword(t *testing.T) {
	assert.True(t, ValidatePassword(md5Hash, "123qwe"))
}

func TestMd5InvalidPassword(t *testing.T) {
	assert.False(t, ValidatePassword(md5Hash, "bogus"))
}
