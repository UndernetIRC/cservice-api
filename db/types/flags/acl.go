// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package flags contains all the bitmask based flags used in the database.
package flags

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
