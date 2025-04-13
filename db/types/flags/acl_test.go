// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestACLFlags(t *testing.T) {
	var f ACL = ACLXhelp | ACLMiaView

	assert.True(t, f.HasFlag(ACLXhelp))

	f.AddFlag(ACLXchgmgrReview)
	assert.True(t, f.HasFlag(ACLXchgmgrReview))

	f.RemoveFlag(ACLXchgmgrReview)
	assert.False(t, f.HasFlag(ACLXchgmgrReview))

	f.ToggleFlag(ACLXchgmgrReview)
	assert.True(t, f.HasFlag(ACLXchgmgrReview))

	f.ToggleFlag(ACLXchgmgrReview)
	assert.False(t, f.HasFlag(ACLXchgmgrReview))
}
