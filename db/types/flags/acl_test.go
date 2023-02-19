// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestACLFlags(t *testing.T) {
	var f ACL = AclXhelp | AclMiaView

	assert.True(t, f.HasFlag(AclXhelp))

	f.AddFlag(AclXchgmgrReview)
	assert.True(t, f.HasFlag(AclXchgmgrReview))

	f.RemoveFlag(AclXchgmgrReview)
	assert.False(t, f.HasFlag(AclXchgmgrReview))

	f.ToggleFlag(AclXchgmgrReview)
	assert.True(t, f.HasFlag(AclXchgmgrReview))

	f.ToggleFlag(AclXchgmgrReview)
	assert.False(t, f.HasFlag(AclXchgmgrReview))
}
