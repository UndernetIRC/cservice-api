// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPassword_SetAndValidate(t *testing.T) {
	p := Password("")
	pass := "Password"
	err := p.Set(pass)
	assert.Equal(t, nil, err)
	assert.NotEmptyf(t, p, "Password should not empty")
	assert.Equal(t, 40, len(p)) // length of md5 hash (current default)

	err = p.Validate(pass)
	assert.Equal(t, nil, err)
}
