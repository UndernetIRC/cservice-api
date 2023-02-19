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
	AclXchgmgrReview ACL = 1 << iota
	AclXchgmgrAdmin
	AclXmailchReview
	AclXmailchAdmin
	AclXhelp
	AclXhelpCanAdd
	AclXhelpCanEdit
	AclXwebaxs2
	AclXwebaxs3
	AclXwebctl
	AclXwebacl
	AclXwebusrToaster
	AclXatCanView
	AclXatCanEdit
	AclXdomainLock
	AclXsuspendUsr
	AclXunsuspendUsr
	AclXwebsess
	AclXcomplaintsAdmRead
	AclXcomplaintsAdmReply
	AclXloggingView
	AclXiprViewOwn
	AclXiprViewOthers
	AclXiprModOwn
	AclXiprModOthers
	AclXwebusrToasterRdonly
	AclMiaView
	AclXtotpDisableOthers
)
