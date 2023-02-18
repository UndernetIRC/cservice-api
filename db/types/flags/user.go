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
	// USER_GLOBAL_SUSPEND indicates that the user is globally suspended
	USER_GLOBAL_SUSPEND User = 1 << iota
	// USER_LOGGED_IN is deprecated
	USER_LOGGED_IN
	// USER_INVISIBLE indicates that the user is invisible
	USER_INVISIBLE
	// USER_FRAUD indicates that the username is fraud
	USER_FRAUD
	// USER_NO_NOTES indicates that the user do not want to be sent notes
	USER_NO_NOTES
	// USER_NO_PURGE do not remove the user for being idle
	USER_NO_PURGE
	// USER_NO_ADMIN indicates that any * authentication is disabled (verify/commands)
	USER_NO_ADMIN
	// USER_ALUMNI indicates that any * privileged is gone, *except* tg he verify; it is like an honorary position
	USER_ALUMNI
	// USER_OPER indicates that the user is flagged as being an official operator, as for allowing them
	// special accesses such as posting complaints even when system is closed to public.
	USER_OPER
	// USER_NO_ADDUSER prevent anyone adding the username to channels (user-set flag, default disabled)
	USER_NO_ADDUSER
	// USER_TOTP_ENABLED indicates that TOTP is enabled for the user
	USER_TOTP_ENABLED
	// USER_TOTP_ADMIN_IPR indicates that the admin user has IP restrictions
	USER_TOTP_ADMIN_IPR
)
