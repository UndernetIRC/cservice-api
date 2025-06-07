// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package flags contains all the bitmask based flags used in the database.
package flags

import "fmt"

// ACL is a bitmask based flag for ACLs.
type ACL int32

// HasFlag returns true if the flag is set.
func (f *ACL) HasFlag(flag ACL) bool {
	return *f&flag != 0
}

// AddFlag adds the flag.
func (f *ACL) AddFlag(flag ACL) {
	*f |= flag
}

// RemoveFlag removes the flag.
func (f *ACL) RemoveFlag(flag ACL) {
	*f &= ^flag
}

// ToggleFlag toggles the flag.
func (f *ACL) ToggleFlag(flag ACL) {
	*f ^= flag
}

// ListFlags returns a slice of all flags that are currently set.
func (f *ACL) ListFlags() []ACL {
	flags := make([]ACL, 0)

	// Iterate through each bit position (since flags are 1 << iota)
	// ACL is int32, so check up to 32 bits
	for i := 0; i < 32; i++ {
		flag := ACL(1 << i)
		if f.HasFlag(flag) {
			flags = append(flags, flag)
		}
	}

	return flags
}

// Name returns the human-readable name of the flag.
func (f ACL) Name() string {
	switch f {
	case ACLXchgmgrReview:
		return "ACLXchgmgrReview"
	case ACLXchgmgrAdmin:
		return "ACLXchgmgrAdmin"
	case ACLXmailchReview:
		return "ACLXmailchReview"
	case ACLXmailchAdmin:
		return "ACLXmailchAdmin"
	case ACLXhelp:
		return "ACLXhelp"
	case ACLXhelpCanAdd:
		return "ACLXhelpCanAdd"
	case ACLXhelpCanEdit:
		return "ACLXhelpCanEdit"
	case ACLXwebaxs2:
		return "ACLXwebaxs2"
	case ACLXwebaxs3:
		return "ACLXwebaxs3"
	case ACLXwebctl:
		return "ACLXwebctl"
	case ACLXwebacl:
		return "ACLXwebacl"
	case ACLXwebusrToaster:
		return "ACLXwebusrToaster"
	case ACLXatCanView:
		return "ACLXatCanView"
	case ACLXatCanEdit:
		return "ACLXatCanEdit"
	case ACLXdomainLock:
		return "ACLXdomainLock"
	case ACLXsuspendUsr:
		return "ACLXsuspendUsr"
	case ACLXunsuspendUsr:
		return "ACLXunsuspendUsr"
	case ACLXwebsess:
		return "ACLXwebsess"
	case ACLXcomplaintsAdmRead:
		return "ACLXcomplaintsAdmRead"
	case ACLXcomplaintsAdmReply:
		return "ACLXcomplaintsAdmReply"
	case ACLXloggingView:
		return "ACLXloggingView"
	case ACLXiprViewOwn:
		return "ACLXiprViewOwn"
	case ACLXiprViewOthers:
		return "ACLXiprViewOthers"
	case ACLXiprModOwn:
		return "ACLXiprModOwn"
	case ACLXiprModOthers:
		return "ACLXiprModOthers"
	case ACLXwebusrToasterRdonly:
		return "ACLXwebusrToasterRdonly"
	case ACLMiaView:
		return "ACLMiaView"
	case ACLXtotpDisableOthers:
		return "ACLXtotpDisableOthers"
	default:
		return fmt.Sprintf("ACL(0x%x)", int32(f))
	}
}

// ListFlagNames returns a slice of human-readable flag names for all flags that are currently set.
func (f *ACL) ListFlagNames() []string {
	flagValues := f.ListFlags()
	names := make([]string, len(flagValues))

	for i, flag := range flagValues {
		names[i] = flag.Name()
	}

	return names
}

// ACL flags.
const (
	ACLXchgmgrReview ACL = 1 << iota
	ACLXchgmgrAdmin
	ACLXmailchReview
	ACLXmailchAdmin
	ACLXhelp
	ACLXhelpCanAdd
	ACLXhelpCanEdit
	ACLXwebaxs2
	ACLXwebaxs3
	ACLXwebctl
	ACLXwebacl
	ACLXwebusrToaster
	ACLXatCanView
	ACLXatCanEdit
	ACLXdomainLock
	ACLXsuspendUsr
	ACLXunsuspendUsr
	ACLXwebsess
	ACLXcomplaintsAdmRead
	ACLXcomplaintsAdmReply
	ACLXloggingView
	ACLXiprViewOwn
	ACLXiprViewOthers
	ACLXiprModOwn
	ACLXiprModOthers
	ACLXwebusrToasterRdonly
	ACLMiaView
	ACLXtotpDisableOthers
)
