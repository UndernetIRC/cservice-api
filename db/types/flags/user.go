// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package flags contains all the bitmask based flags used in the database.
package flags

// User is a bitmask based flag for users.
type User int16

// HasFlag returns true if the flag is set.
func (f *User) HasFlag(flag User) bool {
	return *f&flag != 0
}

// AddFlag adds the flag.
func (f *User) AddFlag(flag User) {
	*f |= flag
}

// RemoveFlag removes the flag.
func (f *User) RemoveFlag(flag User) {
	*f &= ^flag
}

// ToggleFlag toggles the flag.
func (f *User) ToggleFlag(flag User) {
	*f ^= flag
}

// User flags.
const (
	// UserGlobalSuspend indicates that the user is globally suspended
	UserGlobalSuspend User = 1 << iota
	// UserLoggedIn is deprecated
	UserLoggedIn
	// UserInvisible indicates that the user is invisible
	UserInvisible
	// UserFraud indicates that the username is fraud
	UserFraud
	// UserNoNotes indicates that the user do not want to be sent notes
	UserNoNotes
	// UserNoPurge do not remove the user for being idle
	UserNoPurge
	// UserNoAdmin indicates that any * authentication is disabled (verify/commands)
	UserNoAdmin
	// UserAlumni indicates that any * privileged is gone, *except* tg he verify; it is like an honorary position
	UserAlumni
	// UserOper indicates that the user is flagged as being an official operator, as for allowing them
	// special accesses such as posting complaints even when system is closed to public.
	UserOper
	// UserNoAdduser prevent anyone adding the username to channels (user-set flag, default disabled)
	UserNoAdduser
	// UserTotpEnabled indicates that TOTP is enabled for the user
	UserTotpEnabled
	// UserTotpAdminIpr indicates that the admin user has IP restrictions
	UserTotpAdminIpr
)
