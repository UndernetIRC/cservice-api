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
	// USER_TOTP_ENABLED indicates that TOTP is enabled for the user
	USER_TOTP_ENABLED User = 1024
	// USER_TOTP_ADMIN_IPR indicates that the admin user has IP restrictions
	USER_TOTP_ADMIN_IPR User = 2048
)
