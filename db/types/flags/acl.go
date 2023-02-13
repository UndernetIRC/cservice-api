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
	ACL_XCHGMGR_REVIEW ACL = 1 << iota
	ACL_XCHGMGR_ADMIN
	ACL_XMAILCH_REVIEW
	ACL_XMAILCH_ADMIN
	ACL_XHELP
	ACL_XHELP_CAN_ADD
	ACL_XHELP_CAN_EDIT
	ACL_XWEBAXS_2
	ACL_XWEBAXS_3
	ACL_XWEBCTL
	ACL_XWEBACL
	ACL_XWEBUSR_TOASTER
	ACL_XAT_CAN_VIEW
	ACL_XAT_CAN_EDIT
	ACL_XDOMAIN_LOCK
	ACL_XSUSPEND_USR
	ACL_XUNSUSPEND_USR
	ACL_XWEBSESS
	ACL_XCOMPLAINTS_ADM_READ
	ACL_XCOMPLAINTS_ADM_REPLY
	ACL_XLOGGING_VIEW
	ACL_XIPR_VIEW_OWN
	ACL_XIPR_VIEW_OTHERS
	ACL_XIPR_MOD_OWN
	ACL_XIPR_MOD_OTHERS
	ACL_XWEBUSR_TOASTER_RDONLY
	ACL_MIA_VIEW
	ACL_XTOTP_DISABLE_OTHERS77
)
