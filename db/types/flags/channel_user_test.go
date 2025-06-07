// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChannelUser_HasFlag(t *testing.T) {
	tests := []struct {
		name     string
		flags    ChannelUser
		flag     ChannelUser
		expected bool
	}{
		{
			name:     "flag is set",
			flags:    ChannelUserOp,
			flag:     ChannelUserOp,
			expected: true,
		},
		{
			name:     "flag is not set",
			flags:    ChannelUserOp,
			flag:     ChannelUserVoice,
			expected: false,
		},
		{
			name:     "no flags set",
			flags:    ChannelUserNone,
			flag:     ChannelUserOp,
			expected: false,
		},
		{
			name:     "multiple flags set, check one",
			flags:    ChannelUserOp | ChannelUserVoice,
			flag:     ChannelUserVoice,
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

func TestChannelUser_AddFlag(t *testing.T) {
	tests := []struct {
		name     string
		initial  ChannelUser
		flag     ChannelUser
		expected ChannelUser
	}{
		{
			name:     "add flag to empty",
			initial:  ChannelUserNone,
			flag:     ChannelUserOp,
			expected: ChannelUserOp,
		},
		{
			name:     "add flag to existing",
			initial:  ChannelUserOp,
			flag:     ChannelUserVoice,
			expected: ChannelUserOp | ChannelUserVoice,
		},
		{
			name:     "add already set flag",
			initial:  ChannelUserOp,
			flag:     ChannelUserOp,
			expected: ChannelUserOp,
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

func TestChannelUser_RemoveFlag(t *testing.T) {
	tests := []struct {
		name     string
		initial  ChannelUser
		flag     ChannelUser
		expected ChannelUser
	}{
		{
			name:     "remove existing flag",
			initial:  ChannelUserOp | ChannelUserVoice,
			flag:     ChannelUserOp,
			expected: ChannelUserVoice,
		},
		{
			name:     "remove non-existing flag",
			initial:  ChannelUserOp,
			flag:     ChannelUserVoice,
			expected: ChannelUserOp,
		},
		{
			name:     "remove from empty",
			initial:  ChannelUserNone,
			flag:     ChannelUserOp,
			expected: ChannelUserNone,
		},
		{
			name:     "remove all flags",
			initial:  ChannelUserOp,
			flag:     ChannelUserOp,
			expected: ChannelUserNone,
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

func TestChannelUser_ToggleFlag(t *testing.T) {
	tests := []struct {
		name     string
		initial  ChannelUser
		flag     ChannelUser
		expected ChannelUser
	}{
		{
			name:     "toggle on empty",
			initial:  ChannelUserNone,
			flag:     ChannelUserOp,
			expected: ChannelUserOp,
		},
		{
			name:     "toggle existing flag off",
			initial:  ChannelUserOp,
			flag:     ChannelUserOp,
			expected: ChannelUserNone,
		},
		{
			name:     "toggle new flag on",
			initial:  ChannelUserOp,
			flag:     ChannelUserVoice,
			expected: ChannelUserOp | ChannelUserVoice,
		},
		{
			name:     "toggle existing flag off while others remain",
			initial:  ChannelUserOp | ChannelUserVoice,
			flag:     ChannelUserOp,
			expected: ChannelUserVoice,
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

func TestChannelUser_ListFlags(t *testing.T) {
	tests := []struct {
		name     string
		flags    ChannelUser
		expected []ChannelUser
	}{
		{
			name:     "no flags",
			flags:    ChannelUserNone,
			expected: []ChannelUser{},
		},
		{
			name:     "single flag",
			flags:    ChannelUserOp,
			expected: []ChannelUser{ChannelUserOp},
		},
		{
			name:     "multiple flags",
			flags:    ChannelUserOp | ChannelUserVoice,
			expected: []ChannelUser{ChannelUserOp, ChannelUserVoice},
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

func TestChannelUser_FlagValues(t *testing.T) {
	// Test that each flag has the correct bit value
	expectedValues := map[ChannelUser]ChannelUser{
		ChannelUserNone:  0x0,
		ChannelUserOp:    0x1,
		ChannelUserVoice: 0x2,
	}

	for flag, expectedValue := range expectedValues {
		assert.Equal(t, expectedValue, flag, "Flag %v should have value %x", flag, expectedValue)
	}
}

// Benchmark tests
func BenchmarkChannelUser_HasFlag(b *testing.B) {
	f := ChannelUserOp | ChannelUserVoice
	flag := ChannelUserVoice

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.HasFlag(flag)
	}
}

func BenchmarkChannelUser_AddFlag(b *testing.B) {
	f := ChannelUserOp

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.AddFlag(ChannelUserVoice)
	}
}

func BenchmarkChannelUser_RemoveFlag(b *testing.B) {
	f := ChannelUserOp | ChannelUserVoice

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.RemoveFlag(ChannelUserVoice)
	}
}

func BenchmarkChannelUser_ToggleFlag(b *testing.B) {
	f := ChannelUserOp

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.ToggleFlag(ChannelUserVoice)
	}
}

func BenchmarkChannelUser_ListFlags(b *testing.B) {
	f := ChannelUserOp | ChannelUserVoice

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.ListFlags()
	}
}

func TestChannelUser_Name(t *testing.T) {
	tests := []struct {
		name     string
		flag     ChannelUser
		expected string
	}{
		{
			name:     "ChannelUserNone",
			flag:     ChannelUserNone,
			expected: "ChannelUserNone",
		},
		{
			name:     "ChannelUserOp",
			flag:     ChannelUserOp,
			expected: "ChannelUserOp",
		},
		{
			name:     "ChannelUserVoice",
			flag:     ChannelUserVoice,
			expected: "ChannelUserVoice",
		},
		{
			name:     "unknown flag",
			flag:     ChannelUser(0x1234),
			expected: "ChannelUser(0x1234)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.flag.Name()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestChannelUser_ListFlagNames(t *testing.T) {
	tests := []struct {
		name     string
		flags    ChannelUser
		expected []string
	}{
		{
			name:     "no flags",
			flags:    ChannelUserNone,
			expected: []string{},
		},
		{
			name:     "single flag",
			flags:    ChannelUserOp,
			expected: []string{"ChannelUserOp"},
		},
		{
			name:     "multiple flags",
			flags:    ChannelUserOp | ChannelUserVoice,
			expected: []string{"ChannelUserOp", "ChannelUserVoice"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.flags.ListFlagNames()
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func BenchmarkChannelUser_Name(b *testing.B) {
	flag := ChannelUserOp
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = flag.Name()
	}
}
