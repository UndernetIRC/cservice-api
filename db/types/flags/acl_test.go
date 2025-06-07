// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package flags

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestACLFlags(t *testing.T) {
	var f = ACLXhelp | ACLMiaView

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

func TestACL_HasFlag(t *testing.T) {
	tests := []struct {
		name     string
		acl      ACL
		flag     ACL
		expected bool
	}{
		{
			name:     "empty acl has no flags",
			acl:      0,
			flag:     ACLXchgmgrReview,
			expected: false,
		},
		{
			name:     "acl with XchgmgrReview has XchgmgrReview flag",
			acl:      ACLXchgmgrReview,
			flag:     ACLXchgmgrReview,
			expected: true,
		},
		{
			name:     "acl with XchgmgrReview does not have XchgmgrAdmin flag",
			acl:      ACLXchgmgrReview,
			flag:     ACLXchgmgrAdmin,
			expected: false,
		},
		{
			name:     "acl with multiple flags has specific flag",
			acl:      ACLXchgmgrReview | ACLXhelp | ACLXwebctl,
			flag:     ACLXhelp,
			expected: true,
		},
		{
			name:     "acl with all flags has XtotpDisableOthers flag",
			acl:      ACLXchgmgrReview | ACLXchgmgrAdmin | ACLXmailchReview | ACLXmailchAdmin | ACLXhelp | ACLXhelpCanAdd | ACLXhelpCanEdit | ACLXwebaxs2 | ACLXwebaxs3 | ACLXwebctl | ACLXwebacl | ACLXwebusrToaster | ACLXatCanView | ACLXatCanEdit | ACLXdomainLock | ACLXsuspendUsr | ACLXunsuspendUsr | ACLXwebsess | ACLXcomplaintsAdmRead | ACLXcomplaintsAdmReply | ACLXloggingView | ACLXiprViewOwn | ACLXiprViewOthers | ACLXiprModOwn | ACLXiprModOthers | ACLXwebusrToasterRdonly | ACLMiaView | ACLXtotpDisableOthers,
			flag:     ACLXtotpDisableOthers,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.acl.HasFlag(tt.flag)
			if result != tt.expected {
				t.Errorf("HasFlag() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestACL_AddFlag(t *testing.T) {
	tests := []struct {
		name     string
		initial  ACL
		flag     ACL
		expected ACL
	}{
		{
			name:     "add flag to empty acl",
			initial:  0,
			flag:     ACLXchgmgrReview,
			expected: ACLXchgmgrReview,
		},
		{
			name:     "add flag to acl with existing flags",
			initial:  ACLXchgmgrReview,
			flag:     ACLXhelp,
			expected: ACLXchgmgrReview | ACLXhelp,
		},
		{
			name:     "add same flag twice (idempotent)",
			initial:  ACLXchgmgrReview,
			flag:     ACLXchgmgrReview,
			expected: ACLXchgmgrReview,
		},
		{
			name:     "add multiple flags one by one",
			initial:  ACLXchgmgrReview | ACLXhelp,
			flag:     ACLXwebctl,
			expected: ACLXchgmgrReview | ACLXhelp | ACLXwebctl,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl := tt.initial
			acl.AddFlag(tt.flag)
			if acl != tt.expected {
				t.Errorf("AddFlag() resulted in %v, expected %v", acl, tt.expected)
			}
		})
	}
}

func TestACL_RemoveFlag(t *testing.T) {
	tests := []struct {
		name     string
		initial  ACL
		flag     ACL
		expected ACL
	}{
		{
			name:     "remove flag from empty acl",
			initial:  0,
			flag:     ACLXchgmgrReview,
			expected: 0,
		},
		{
			name:     "remove existing flag",
			initial:  ACLXchgmgrReview | ACLXhelp,
			flag:     ACLXchgmgrReview,
			expected: ACLXhelp,
		},
		{
			name:     "remove non-existent flag",
			initial:  ACLXchgmgrReview,
			flag:     ACLXhelp,
			expected: ACLXchgmgrReview,
		},
		{
			name:     "remove flag from acl with all flags",
			initial:  ACLXchgmgrReview | ACLXchgmgrAdmin | ACLXmailchReview | ACLXmailchAdmin | ACLXhelp | ACLXhelpCanAdd | ACLXhelpCanEdit | ACLXwebaxs2 | ACLXwebaxs3 | ACLXwebctl | ACLXwebacl | ACLXwebusrToaster | ACLXatCanView | ACLXatCanEdit | ACLXdomainLock | ACLXsuspendUsr | ACLXunsuspendUsr | ACLXwebsess | ACLXcomplaintsAdmRead | ACLXcomplaintsAdmReply | ACLXloggingView | ACLXiprViewOwn | ACLXiprViewOthers | ACLXiprModOwn | ACLXiprModOthers | ACLXwebusrToasterRdonly | ACLMiaView | ACLXtotpDisableOthers,
			flag:     ACLXhelp,
			expected: ACLXchgmgrReview | ACLXchgmgrAdmin | ACLXmailchReview | ACLXmailchAdmin | ACLXhelpCanAdd | ACLXhelpCanEdit | ACLXwebaxs2 | ACLXwebaxs3 | ACLXwebctl | ACLXwebacl | ACLXwebusrToaster | ACLXatCanView | ACLXatCanEdit | ACLXdomainLock | ACLXsuspendUsr | ACLXunsuspendUsr | ACLXwebsess | ACLXcomplaintsAdmRead | ACLXcomplaintsAdmReply | ACLXloggingView | ACLXiprViewOwn | ACLXiprViewOthers | ACLXiprModOwn | ACLXiprModOthers | ACLXwebusrToasterRdonly | ACLMiaView | ACLXtotpDisableOthers,
		},
		{
			name:     "remove last remaining flag",
			initial:  ACLXchgmgrReview,
			flag:     ACLXchgmgrReview,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl := tt.initial
			acl.RemoveFlag(tt.flag)
			if acl != tt.expected {
				t.Errorf("RemoveFlag() resulted in %v, expected %v", acl, tt.expected)
			}
		})
	}
}

func TestACL_ToggleFlag(t *testing.T) {
	tests := []struct {
		name     string
		initial  ACL
		flag     ACL
		expected ACL
	}{
		{
			name:     "toggle flag on empty acl",
			initial:  0,
			flag:     ACLXchgmgrReview,
			expected: ACLXchgmgrReview,
		},
		{
			name:     "toggle existing flag off",
			initial:  ACLXchgmgrReview,
			flag:     ACLXchgmgrReview,
			expected: 0,
		},
		{
			name:     "toggle non-existent flag on",
			initial:  ACLXchgmgrReview,
			flag:     ACLXhelp,
			expected: ACLXchgmgrReview | ACLXhelp,
		},
		{
			name:     "toggle flag in acl with multiple flags",
			initial:  ACLXchgmgrReview | ACLXhelp | ACLXwebctl,
			flag:     ACLXhelp,
			expected: ACLXchgmgrReview | ACLXwebctl,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl := tt.initial
			acl.ToggleFlag(tt.flag)
			if acl != tt.expected {
				t.Errorf("ToggleFlag() resulted in %v, expected %v", acl, tt.expected)
			}
		})
	}
}

func TestACL_ListFlags(t *testing.T) {
	tests := []struct {
		name     string
		acl      ACL
		expected []ACL
	}{
		{
			name:     "empty acl returns empty list",
			acl:      0,
			expected: []ACL{},
		},
		{
			name:     "single flag",
			acl:      ACLXchgmgrReview,
			expected: []ACL{ACLXchgmgrReview},
		},
		{
			name:     "multiple flags",
			acl:      ACLXchgmgrReview | ACLXhelp | ACLXwebctl,
			expected: []ACL{ACLXchgmgrReview, ACLXhelp, ACLXwebctl},
		},
		{
			name:     "all flags",
			acl:      ACLXchgmgrReview | ACLXchgmgrAdmin | ACLXmailchReview | ACLXmailchAdmin | ACLXhelp | ACLXhelpCanAdd | ACLXhelpCanEdit | ACLXwebaxs2 | ACLXwebaxs3 | ACLXwebctl | ACLXwebacl | ACLXwebusrToaster | ACLXatCanView | ACLXatCanEdit | ACLXdomainLock | ACLXsuspendUsr | ACLXunsuspendUsr | ACLXwebsess | ACLXcomplaintsAdmRead | ACLXcomplaintsAdmReply | ACLXloggingView | ACLXiprViewOwn | ACLXiprViewOthers | ACLXiprModOwn | ACLXiprModOthers | ACLXwebusrToasterRdonly | ACLMiaView | ACLXtotpDisableOthers,
			expected: []ACL{ACLXchgmgrReview, ACLXchgmgrAdmin, ACLXmailchReview, ACLXmailchAdmin, ACLXhelp, ACLXhelpCanAdd, ACLXhelpCanEdit, ACLXwebaxs2, ACLXwebaxs3, ACLXwebctl, ACLXwebacl, ACLXwebusrToaster, ACLXatCanView, ACLXatCanEdit, ACLXdomainLock, ACLXsuspendUsr, ACLXunsuspendUsr, ACLXwebsess, ACLXcomplaintsAdmRead, ACLXcomplaintsAdmReply, ACLXloggingView, ACLXiprViewOwn, ACLXiprViewOthers, ACLXiprModOwn, ACLXiprModOthers, ACLXwebusrToasterRdonly, ACLMiaView, ACLXtotpDisableOthers},
		},
		{
			name:     "non-consecutive flags",
			acl:      ACLXchgmgrReview | ACLXwebctl | ACLMiaView,
			expected: []ACL{ACLXchgmgrReview, ACLXwebctl, ACLMiaView},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.acl.ListFlags()
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ListFlags() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestACL_ListFlags_Integration(t *testing.T) {
	t.Run("add and list flags", func(t *testing.T) {
		var acl ACL

		// Add flags one by one and verify ListFlags
		acl.AddFlag(ACLXchgmgrReview)
		flags := acl.ListFlags()
		expected := []ACL{ACLXchgmgrReview}
		if !reflect.DeepEqual(flags, expected) {
			t.Errorf("After adding ACLXchgmgrReview, ListFlags() = %v, expected %v", flags, expected)
		}

		acl.AddFlag(ACLXhelp)
		flags = acl.ListFlags()
		expected = []ACL{ACLXchgmgrReview, ACLXhelp}
		if !reflect.DeepEqual(flags, expected) {
			t.Errorf("After adding ACLXhelp, ListFlags() = %v, expected %v", flags, expected)
		}

		// Remove a flag and verify
		acl.RemoveFlag(ACLXchgmgrReview)
		flags = acl.ListFlags()
		expected = []ACL{ACLXhelp}
		if !reflect.DeepEqual(flags, expected) {
			t.Errorf("After removing ACLXchgmgrReview, ListFlags() = %v, expected %v", flags, expected)
		}
	})

	t.Run("toggle and list flags", func(t *testing.T) {
		var acl ACL

		// Toggle flag on
		acl.ToggleFlag(ACLXwebctl)
		flags := acl.ListFlags()
		expected := []ACL{ACLXwebctl}
		if !reflect.DeepEqual(flags, expected) {
			t.Errorf("After toggling ACLXwebctl on, ListFlags() = %v, expected %v", flags, expected)
		}

		// Toggle flag off
		acl.ToggleFlag(ACLXwebctl)
		flags = acl.ListFlags()
		expected = []ACL{}
		if !reflect.DeepEqual(flags, expected) {
			t.Errorf("After toggling ACLXwebctl off, ListFlags() = %v, expected %v", flags, expected)
		}
	})
}

func TestACL_Name(t *testing.T) {
	tests := []struct {
		name     string
		flag     ACL
		expected string
	}{
		{
			name:     "ACLXchgmgrReview",
			flag:     ACLXchgmgrReview,
			expected: "ACLXchgmgrReview",
		},
		{
			name:     "ACLXchgmgrAdmin",
			flag:     ACLXchgmgrAdmin,
			expected: "ACLXchgmgrAdmin",
		},
		{
			name:     "ACLXhelp",
			flag:     ACLXhelp,
			expected: "ACLXhelp",
		},
		{
			name:     "ACLXtotpDisableOthers",
			flag:     ACLXtotpDisableOthers,
			expected: "ACLXtotpDisableOthers",
		},
		{
			name:     "unknown flag",
			flag:     ACL(0x12345678),
			expected: "ACL(0x12345678)",
		},
		{
			name:     "zero flag",
			flag:     ACL(0),
			expected: "ACL(0x0)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.flag.Name()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestACL_ListFlagNames(t *testing.T) {
	tests := []struct {
		name     string
		flags    ACL
		expected []string
	}{
		{
			name:     "no flags",
			flags:    0,
			expected: []string{},
		},
		{
			name:     "single flag",
			flags:    ACLXchgmgrReview,
			expected: []string{"ACLXchgmgrReview"},
		},
		{
			name:     "multiple flags",
			flags:    ACLXchgmgrReview | ACLXhelp | ACLXtotpDisableOthers,
			expected: []string{"ACLXchgmgrReview", "ACLXhelp", "ACLXtotpDisableOthers"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.flags.ListFlagNames()
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func BenchmarkACL_Name(b *testing.B) {
	flag := ACLXchgmgrReview
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = flag.Name()
	}
}

// Benchmark tests to ensure performance
func BenchmarkACL_HasFlag(b *testing.B) {
	acl := ACLXchgmgrReview | ACLXhelp | ACLXwebctl
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		acl.HasFlag(ACLXhelp)
	}
}

func BenchmarkACL_ListFlags(b *testing.B) {
	acl := ACLXchgmgrReview | ACLXchgmgrAdmin | ACLXmailchReview | ACLXmailchAdmin | ACLXhelp | ACLXhelpCanAdd | ACLXhelpCanEdit | ACLXwebaxs2 | ACLXwebaxs3 | ACLXwebctl | ACLXwebacl | ACLXwebusrToaster | ACLXatCanView | ACLXatCanEdit | ACLXdomainLock | ACLXsuspendUsr | ACLXunsuspendUsr | ACLXwebsess | ACLXcomplaintsAdmRead | ACLXcomplaintsAdmReply | ACLXloggingView | ACLXiprViewOwn | ACLXiprViewOthers | ACLXiprModOwn | ACLXiprModOthers | ACLXwebusrToasterRdonly | ACLMiaView | ACLXtotpDisableOthers
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		acl.ListFlags()
	}
}
