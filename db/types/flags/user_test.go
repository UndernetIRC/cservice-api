// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserFlags(t *testing.T) {
	var f User = USER_TOTP_ADMIN_IPR

	assert.False(t, f.HasFlag(USER_TOTP_ENABLED))
	assert.True(t, f.HasFlag(USER_TOTP_ADMIN_IPR))

	f.AddFlag(USER_TOTP_ENABLED)
	assert.True(t, f.HasFlag(1024))

	f.RemoveFlag(USER_TOTP_ENABLED)
	assert.False(t, f.HasFlag(USER_TOTP_ENABLED))

	f.ToggleFlag(USER_TOTP_ENABLED)
	assert.True(t, f.HasFlag(USER_TOTP_ENABLED))

	f.ToggleFlag(USER_TOTP_ENABLED)
	assert.False(t, f.HasFlag(USER_TOTP_ENABLED))
}
