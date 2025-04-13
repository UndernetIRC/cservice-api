// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserFlags(t *testing.T) {
	var f = UserTotpAdminIpr

	assert.False(t, f.HasFlag(UserTotpEnabled))
	assert.True(t, f.HasFlag(UserTotpAdminIpr))

	f.AddFlag(UserTotpEnabled)
	assert.True(t, f.HasFlag(1024))

	f.RemoveFlag(UserTotpEnabled)
	assert.False(t, f.HasFlag(UserTotpEnabled))

	f.ToggleFlag(UserTotpEnabled)
	assert.True(t, f.HasFlag(UserTotpEnabled))

	f.ToggleFlag(UserTotpEnabled)
	assert.False(t, f.HasFlag(UserTotpEnabled))
}
