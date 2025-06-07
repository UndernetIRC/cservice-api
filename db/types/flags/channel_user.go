// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

// Package flags contains all the bitmask based flags used in the database.
package flags

import "fmt"

// ChannelUser is a bitmask based flag for channel userflags.
type ChannelUser int16

// HasFlag returns true if the flag is set.
func (f *ChannelUser) HasFlag(flag ChannelUser) bool {
	return *f&flag != 0
}

// AddFlag adds the flag.
func (f *ChannelUser) AddFlag(flag ChannelUser) {
	*f |= flag
}

// RemoveFlag removes the flag.
func (f *ChannelUser) RemoveFlag(flag ChannelUser) {
	*f &= ^flag
}

// ToggleFlag toggles the flag.
func (f *ChannelUser) ToggleFlag(flag ChannelUser) {
	*f ^= flag
}

// ListFlags returns a slice of all flags that are currently set.
func (f *ChannelUser) ListFlags() []ChannelUser {
	flags := make([]ChannelUser, 0)

	// Iterate through each bit position (since flags are 1 << iota)
	// ChannelUser is int16, so check up to 16 bits
	for i := 0; i < 16; i++ {
		flag := ChannelUser(1 << i)
		if f.HasFlag(flag) {
			flags = append(flags, flag)
		}
	}

	return flags
}

// Name returns the human-readable name of the flag.
func (f ChannelUser) Name() string {
	switch f {
	case ChannelUserNone:
		return "ChannelUserNone"
	case ChannelUserOp:
		return "ChannelUserOp"
	case ChannelUserVoice:
		return "ChannelUserVoice"
	default:
		return fmt.Sprintf("ChannelUser(0x%x)", int16(f))
	}
}

// ListFlagNames returns a slice of human-readable flag names for all flags that are currently set.
func (f *ChannelUser) ListFlagNames() []string {
	flagValues := f.ListFlags()
	names := make([]string, len(flagValues))

	for i, flag := range flagValues {
		names[i] = flag.Name()
	}

	return names
}

// Channel userflags (default user permissions) - based on gnuworld constants.
const (
	// ChannelUserNone indicates no special user flags - default value
	ChannelUserNone ChannelUser = 0x0
	// ChannelUserOp indicates that default mode should be OP
	ChannelUserOp ChannelUser = 0x1
	// ChannelUserVoice indicates that default mode should be VOICE
	ChannelUserVoice ChannelUser = 0x2
)
