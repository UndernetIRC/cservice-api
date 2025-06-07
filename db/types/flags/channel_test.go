// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChannel_HasFlag(t *testing.T) {
	tests := []struct {
		name     string
		flags    Channel
		flag     Channel
		expected bool
	}{
		{
			name:     "flag is set",
			flags:    ChannelSpecial | ChannelSuspended,
			flag:     ChannelSpecial,
			expected: true,
		},
		{
			name:     "flag is not set",
			flags:    ChannelSpecial | ChannelSuspended,
			flag:     ChannelLocked,
			expected: false,
		},
		{
			name:     "no flags set",
			flags:    0,
			flag:     ChannelSpecial,
			expected: false,
		},
		{
			name:     "multiple flags set, check one",
			flags:    ChannelSpecial | ChannelSuspended | ChannelLocked,
			flag:     ChannelSuspended,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.flags
			result := f.HasFlag(tt.flag)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestChannel_AddFlag(t *testing.T) {
	tests := []struct {
		name     string
		initial  Channel
		flag     Channel
		expected Channel
	}{
		{
			name:     "add flag to empty",
			initial:  0,
			flag:     ChannelSpecial,
			expected: ChannelSpecial,
		},
		{
			name:     "add flag to existing",
			initial:  ChannelSpecial,
			flag:     ChannelSuspended,
			expected: ChannelSpecial | ChannelSuspended,
		},
		{
			name:     "add already set flag",
			initial:  ChannelSpecial | ChannelSuspended,
			flag:     ChannelSpecial,
			expected: ChannelSpecial | ChannelSuspended,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.initial
			f.AddFlag(tt.flag)
			assert.Equal(t, tt.expected, f)
		})
	}
}

func TestChannel_RemoveFlag(t *testing.T) {
	tests := []struct {
		name     string
		initial  Channel
		flag     Channel
		expected Channel
	}{
		{
			name:     "remove existing flag",
			initial:  ChannelSpecial | ChannelSuspended,
			flag:     ChannelSpecial,
			expected: ChannelSuspended,
		},
		{
			name:     "remove non-existing flag",
			initial:  ChannelSpecial,
			flag:     ChannelSuspended,
			expected: ChannelSpecial,
		},
		{
			name:     "remove from empty",
			initial:  0,
			flag:     ChannelSpecial,
			expected: 0,
		},
		{
			name:     "remove all flags",
			initial:  ChannelSpecial,
			flag:     ChannelSpecial,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.initial
			f.RemoveFlag(tt.flag)
			assert.Equal(t, tt.expected, f)
		})
	}
}

func TestChannel_ToggleFlag(t *testing.T) {
	tests := []struct {
		name     string
		initial  Channel
		flag     Channel
		expected Channel
	}{
		{
			name:     "toggle on empty",
			initial:  0,
			flag:     ChannelSpecial,
			expected: ChannelSpecial,
		},
		{
			name:     "toggle existing flag off",
			initial:  ChannelSpecial,
			flag:     ChannelSpecial,
			expected: 0,
		},
		{
			name:     "toggle new flag on",
			initial:  ChannelSpecial,
			flag:     ChannelSuspended,
			expected: ChannelSpecial | ChannelSuspended,
		},
		{
			name:     "toggle existing flag off while others remain",
			initial:  ChannelSpecial | ChannelSuspended,
			flag:     ChannelSpecial,
			expected: ChannelSuspended,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.initial
			f.ToggleFlag(tt.flag)
			assert.Equal(t, tt.expected, f)
		})
	}
}

func TestChannel_ListFlags(t *testing.T) {
	tests := []struct {
		name     string
		flags    Channel
		expected []Channel
	}{
		{
			name:     "no flags",
			flags:    0,
			expected: []Channel{},
		},
		{
			name:     "single flag",
			flags:    ChannelSpecial,
			expected: []Channel{ChannelSpecial},
		},
		{
			name:     "multiple flags",
			flags:    ChannelSpecial | ChannelSuspended | ChannelLocked,
			expected: []Channel{ChannelSpecial, ChannelSuspended, ChannelLocked},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.flags
			result := f.ListFlags()
			assert.Equal(t, len(tt.expected), len(result))
			for _, expectedFlag := range tt.expected {
				assert.Contains(t, result, expectedFlag)
			}
		})
	}
}

func TestChannel_ListFlags_WithGnuworldConstants(t *testing.T) {
	// Test that ListFlags returns the correct gnuworld constant values
	t.Run("returns gnuworld constants correctly", func(t *testing.T) {
		var flags Channel

		// Set some specific gnuworld flags
		flags.AddFlag(ChannelSpecial)   // 0x00000002
		flags.AddFlag(ChannelSuspended) // 0x00000010
		flags.AddFlag(ChannelAlwaysOp)  // 0x00010000
		flags.AddFlag(ChannelFloodPro)  // 0x02000000

		listedFlags := flags.ListFlags()

		// Should return exactly 4 flags
		assert.Len(t, listedFlags, 4)

		// Check that the returned values match our gnuworld constants
		expectedFlags := []Channel{
			ChannelSpecial,   // 0x00000002
			ChannelSuspended, // 0x00000010
			ChannelAlwaysOp,  // 0x00010000
			ChannelFloodPro,  // 0x02000000
		}

		// Sort both slices to compare (order doesn't matter)
		assert.ElementsMatch(t, expectedFlags, listedFlags)

		// Verify each flag value explicitly
		flagMap := make(map[Channel]bool)
		for _, flag := range listedFlags {
			flagMap[flag] = true
		}

		assert.True(t, flagMap[ChannelSpecial])
		assert.True(t, flagMap[ChannelSuspended])
		assert.True(t, flagMap[ChannelAlwaysOp])
		assert.True(t, flagMap[ChannelFloodPro])
	})

	t.Run("returns correct values for bit gaps", func(t *testing.T) {
		var flags Channel

		// Test flags around the gap (bits 12-15 are unused in gnuworld)
		flags.AddFlag(ChannelJoinLimit) // 0x00000800 (bit 11)
		flags.AddFlag(ChannelAlwaysOp)  // 0x00010000 (bit 16)

		listedFlags := flags.ListFlags()

		// Should return exactly 2 flags
		assert.Len(t, listedFlags, 2)
		assert.ElementsMatch(t, []Channel{ChannelJoinLimit, ChannelAlwaysOp}, listedFlags)
	})
}

func TestChannel_FlagValues(t *testing.T) {
	// Test that each flag has the correct bit value - based on gnuworld sqlChannel constants
	expectedValues := map[Channel]Channel{
		ChannelNoPurge:       0x00000001,
		ChannelSpecial:       0x00000002,
		ChannelNoRegister:    0x00000004,
		ChannelNeverReg:      0x00000008,
		ChannelSuspended:     0x00000010,
		ChannelTempSuspended: 0x00000020,
		ChannelCaution:       0x00000040,
		ChannelVacation:      0x00000080,
		ChannelLocked:        0x00000100,
		ChannelFloatLimit:    0x00000200,
		ChannelMIA:           0x00000400,
		ChannelJoinLimit:     0x00000800,
		ChannelAlwaysOp:      0x00010000,
		ChannelStrictOp:      0x00020000,
		ChannelNoOp:          0x00040000,
		ChannelAutoTopic:     0x00080000,
		ChannelOpOnly:        0x00100000,
		ChannelAutoJoin:      0x00200000,
		ChannelNoForce:       0x00400000,
		ChannelNoVoice:       0x00800000,
		ChannelNoTake:        0x01000000,
		ChannelFloodPro:      0x02000000,
		ChannelFloodProGLine: 0x04000000,
		ChannelOpLog:         0x08000000,
	}

	for flag, expectedValue := range expectedValues {
		assert.Equal(t, expectedValue, flag, "Flag %v should have value %x", flag, expectedValue)
	}
}

// Benchmark tests
func BenchmarkChannel_HasFlag(b *testing.B) {
	f := ChannelSpecial | ChannelSuspended | ChannelLocked
	flag := ChannelSuspended

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.HasFlag(flag)
	}
}

func BenchmarkChannel_AddFlag(b *testing.B) {
	f := ChannelSpecial

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.AddFlag(ChannelSuspended)
	}
}

func BenchmarkChannel_RemoveFlag(b *testing.B) {
	f := ChannelSpecial | ChannelSuspended

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.RemoveFlag(ChannelSuspended)
	}
}

func BenchmarkChannel_ToggleFlag(b *testing.B) {
	f := ChannelSpecial

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.ToggleFlag(ChannelSuspended)
	}
}

func BenchmarkChannel_ListFlags(b *testing.B) {
	f := ChannelSpecial | ChannelSuspended | ChannelLocked | ChannelNoForce

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.ListFlags()
	}
}

func TestChannel_Name(t *testing.T) {
	tests := []struct {
		name     string
		flag     Channel
		expected string
	}{
		{
			name:     "ChannelSpecial",
			flag:     ChannelSpecial,
			expected: "ChannelSpecial",
		},
		{
			name:     "ChannelSuspended",
			flag:     ChannelSuspended,
			expected: "ChannelSuspended",
		},
		{
			name:     "ChannelAlwaysOp",
			flag:     ChannelAlwaysOp,
			expected: "ChannelAlwaysOp",
		},
		{
			name:     "ChannelFloodPro",
			flag:     ChannelFloodPro,
			expected: "ChannelFloodPro",
		},
		{
			name:     "unknown flag",
			flag:     Channel(0x12345678),
			expected: "Channel(0x12345678)",
		},
		{
			name:     "zero flag",
			flag:     Channel(0),
			expected: "Channel(0x0)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.flag.Name()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestChannel_ListFlagNames(t *testing.T) {
	tests := []struct {
		name     string
		flags    Channel
		expected []string
	}{
		{
			name:     "no flags",
			flags:    0,
			expected: []string{},
		},
		{
			name:     "single flag",
			flags:    ChannelSpecial,
			expected: []string{"ChannelSpecial"},
		},
		{
			name:     "multiple flags",
			flags:    ChannelSpecial | ChannelSuspended | ChannelAlwaysOp,
			expected: []string{"ChannelSpecial", "ChannelSuspended", "ChannelAlwaysOp"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.flags.ListFlagNames()
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func BenchmarkChannel_Name(b *testing.B) {
	flag := ChannelSpecial
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = flag.Name()
	}
}
