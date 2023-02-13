// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestACLFlags(t *testing.T) {
	var f ACL = ACL_XHELP | ACL_MIA_VIEW

	assert.True(t, f.HasFlag(ACL_XHELP))

	f.AddFlag(ACL_XCHGMGR_REVIEW)
	assert.True(t, f.HasFlag(ACL_XCHGMGR_REVIEW))

	f.RemoveFlag(ACL_XCHGMGR_REVIEW)
	assert.False(t, f.HasFlag(ACL_XCHGMGR_REVIEW))

	f.ToggleFlag(ACL_XCHGMGR_REVIEW)
	assert.True(t, f.HasFlag(ACL_XCHGMGR_REVIEW))

	f.ToggleFlag(ACL_XCHGMGR_REVIEW)
	assert.False(t, f.HasFlag(ACL_XCHGMGR_REVIEW))
}
