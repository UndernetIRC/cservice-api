// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

// Package flags contains all the bitmask based flags used in the database.
package flags

import "fmt"

// Channel is a bitmask based flag for channels.
type Channel int32

// HasFlag returns true if the flag is set.
func (f *Channel) HasFlag(flag Channel) bool {
	return *f&flag != 0
}

// AddFlag adds the flag.
func (f *Channel) AddFlag(flag Channel) {
	*f |= flag
}

// RemoveFlag removes the flag.
func (f *Channel) RemoveFlag(flag Channel) {
	*f &= ^flag
}

// ToggleFlag toggles the flag.
func (f *Channel) ToggleFlag(flag Channel) {
	*f ^= flag
}

// ListFlags returns a slice of all flags that are currently set.
func (f *Channel) ListFlags() []Channel {
	flags := make([]Channel, 0)

	// Iterate through each bit position (since flags are 1 << iota)
	// Channel is int32, so check up to 32 bits
	for i := 0; i < 32; i++ {
		flag := Channel(1 << i)
		if f.HasFlag(flag) {
			flags = append(flags, flag)
		}
	}

	return flags
}

// Name returns the human-readable name of the flag.
func (f Channel) Name() string {
	switch f {
	case ChannelNoPurge:
		return "ChannelNoPurge"
	case ChannelSpecial:
		return "ChannelSpecial"
	case ChannelNoRegister:
		return "ChannelNoRegister"
	case ChannelNeverReg:
		return "ChannelNeverReg"
	case ChannelSuspended:
		return "ChannelSuspended"
	case ChannelTempSuspended:
		return "ChannelTempSuspended"
	case ChannelCaution:
		return "ChannelCaution"
	case ChannelVacation:
		return "ChannelVacation"
	case ChannelLocked:
		return "ChannelLocked"
	case ChannelFloatLimit:
		return "ChannelFloatLimit"
	case ChannelMIA:
		return "ChannelMIA"
	case ChannelJoinLimit:
		return "ChannelJoinLimit"
	case ChannelAlwaysOp:
		return "ChannelAlwaysOp"
	case ChannelStrictOp:
		return "ChannelStrictOp"
	case ChannelNoOp:
		return "ChannelNoOp"
	case ChannelAutoTopic:
		return "ChannelAutoTopic"
	case ChannelOpOnly:
		return "ChannelOpOnly"
	case ChannelAutoJoin:
		return "ChannelAutoJoin"
	case ChannelNoForce:
		return "ChannelNoForce"
	case ChannelNoVoice:
		return "ChannelNoVoice"
	case ChannelNoTake:
		return "ChannelNoTake"
	case ChannelFloodPro:
		return "ChannelFloodPro"
	case ChannelFloodProGLine:
		return "ChannelFloodProGLine"
	case ChannelOpLog:
		return "ChannelOpLog"
	default:
		return fmt.Sprintf("Channel(0x%x)", int32(f))
	}
}

// ListFlagNames returns a slice of human-readable flag names for all flags that are currently set.
func (f *Channel) ListFlagNames() []string {
	flagValues := f.ListFlags()
	names := make([]string, len(flagValues))

	for i, flag := range flagValues {
		names[i] = flag.Name()
	}

	return names
}

// Channel flags - based on gnuworld sqlChannel constants.
const (
	// ChannelNoPurge indicates that the channel should not be purged for inactivity
	ChannelNoPurge Channel = 0x00000001
	// ChannelSpecial indicates that the channel is special (higher privileges)
	ChannelSpecial Channel = 0x00000002
	// ChannelNoRegister indicates that the channel cannot be registered
	ChannelNoRegister Channel = 0x00000004
	// ChannelNeverReg indicates that the channel can never be registered (permanent)
	ChannelNeverReg Channel = 0x00000008
	// ChannelSuspended indicates that the channel is suspended
	ChannelSuspended Channel = 0x00000010
	// ChannelTempSuspended indicates that the channel is temporarily suspended
	ChannelTempSuspended Channel = 0x00000020
	// ChannelCaution indicates that the channel requires caution (admin attention)
	ChannelCaution Channel = 0x00000040
	// ChannelVacation indicates that the channel is in vacation mode
	ChannelVacation Channel = 0x00000080
	// ChannelLocked indicates that the channel is locked (no changes allowed)
	ChannelLocked Channel = 0x00000100
	// ChannelFloatLimit indicates that the channel has floating limits
	ChannelFloatLimit Channel = 0x00000200
	// ChannelMIA indicates that the channel is marked as MIA (Missing In Action)
	ChannelMIA Channel = 0x00000400
	// ChannelJoinLimit indicates that the channel has join limits
	ChannelJoinLimit Channel = 0x00000800

	// ChannelAlwaysOp indicates that users should always get op
	ChannelAlwaysOp Channel = 0x00010000
	// ChannelStrictOp indicates that only certain users can get ops
	ChannelStrictOp Channel = 0x00020000
	// ChannelNoOp indicates that no auto-op is allowed
	ChannelNoOp Channel = 0x00040000
	// ChannelAutoTopic indicates that automatic topic management is enabled
	ChannelAutoTopic Channel = 0x00080000
	// ChannelOpOnly indicates that only ops can perform certain actions (Deprecated)
	ChannelOpOnly Channel = 0x00100000
	// ChannelAutoJoin indicates that the bot should auto-join the channel
	ChannelAutoJoin Channel = 0x00200000
	// ChannelNoForce indicates that forced access is not allowed (Reserved for Planetarion)
	ChannelNoForce Channel = 0x00400000
	// ChannelNoVoice indicates that no auto-voice is allowed
	ChannelNoVoice Channel = 0x00800000
	// ChannelNoTake indicates that the channel cannot be taken over
	ChannelNoTake Channel = 0x01000000
	// ChannelFloodPro indicates that flood protection is enabled
	ChannelFloodPro Channel = 0x02000000
	// ChannelFloodProGLine indicates that flood protection with G-Line is enabled
	ChannelFloodProGLine Channel = 0x04000000
	// ChannelOpLog indicates that operator actions should be logged
	ChannelOpLog Channel = 0x08000000
)
