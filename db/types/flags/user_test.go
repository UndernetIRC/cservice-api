// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package flags

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserFlags(t *testing.T) {
	var f = UserTotpAdminIpr

	assert.False(t, f.HasFlag(UserTotpEnabled))
	assert.True(t, f.HasFlag(UserTotpAdminIpr))

	f.AddFlag(UserTotpEnabled)
	assert.True(t, f.HasFlag(1024))

	f.RemoveFlag(UserTotpEnabled)
	assert.False(t, f.HasFlag(UserTotpEnabled))

	f.ToggleFlag(UserTotpEnabled)
	assert.True(t, f.HasFlag(UserTotpEnabled))

	f.ToggleFlag(UserTotpEnabled)
	assert.False(t, f.HasFlag(UserTotpEnabled))
}

func TestUser_HasFlag(t *testing.T) {
	tests := []struct {
		name     string
		user     User
		flag     User
		expected bool
	}{
		{
			name:     "empty user has no flags",
			user:     0,
			flag:     UserGlobalSuspend,
			expected: false,
		},
		{
			name:     "user with GlobalSuspend has GlobalSuspend flag",
			user:     UserGlobalSuspend,
			flag:     UserGlobalSuspend,
			expected: true,
		},
		{
			name:     "user with GlobalSuspend does not have LoggedIn flag",
			user:     UserGlobalSuspend,
			flag:     UserLoggedIn,
			expected: false,
		},
		{
			name:     "user with multiple flags has specific flag",
			user:     UserGlobalSuspend | UserInvisible | UserFraud,
			flag:     UserInvisible,
			expected: true,
		},
		{
			name:     "user with all flags has TotpAdminIpr flag",
			user:     UserGlobalSuspend | UserLoggedIn | UserInvisible | UserFraud | UserNoNotes | UserNoPurge | UserNoAdmin | UserAlumni | UserOper | UserNoAdduser | UserTotpEnabled | UserTotpAdminIpr,
			flag:     UserTotpAdminIpr,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.user.HasFlag(tt.flag)
			if result != tt.expected {
				t.Errorf("HasFlag() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestUser_AddFlag(t *testing.T) {
	tests := []struct {
		name     string
		initial  User
		flag     User
		expected User
	}{
		{
			name:     "add flag to empty user",
			initial:  0,
			flag:     UserGlobalSuspend,
			expected: UserGlobalSuspend,
		},
		{
			name:     "add flag to user with existing flags",
			initial:  UserGlobalSuspend,
			flag:     UserInvisible,
			expected: UserGlobalSuspend | UserInvisible,
		},
		{
			name:     "add same flag twice (idempotent)",
			initial:  UserGlobalSuspend,
			flag:     UserGlobalSuspend,
			expected: UserGlobalSuspend,
		},
		{
			name:     "add multiple flags one by one",
			initial:  UserGlobalSuspend | UserInvisible,
			flag:     UserFraud,
			expected: UserGlobalSuspend | UserInvisible | UserFraud,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := tt.initial
			user.AddFlag(tt.flag)
			if user != tt.expected {
				t.Errorf("AddFlag() resulted in %v, expected %v", user, tt.expected)
			}
		})
	}
}

func TestUser_RemoveFlag(t *testing.T) {
	tests := []struct {
		name     string
		initial  User
		flag     User
		expected User
	}{
		{
			name:     "remove flag from empty user",
			initial:  0,
			flag:     UserGlobalSuspend,
			expected: 0,
		},
		{
			name:     "remove existing flag",
			initial:  UserGlobalSuspend | UserInvisible,
			flag:     UserGlobalSuspend,
			expected: UserInvisible,
		},
		{
			name:     "remove non-existent flag",
			initial:  UserGlobalSuspend,
			flag:     UserInvisible,
			expected: UserGlobalSuspend,
		},
		{
			name:     "remove flag from user with all flags",
			initial:  UserGlobalSuspend | UserLoggedIn | UserInvisible | UserFraud | UserNoNotes | UserNoPurge | UserNoAdmin | UserAlumni | UserOper | UserNoAdduser | UserTotpEnabled | UserTotpAdminIpr,
			flag:     UserInvisible,
			expected: UserGlobalSuspend | UserLoggedIn | UserFraud | UserNoNotes | UserNoPurge | UserNoAdmin | UserAlumni | UserOper | UserNoAdduser | UserTotpEnabled | UserTotpAdminIpr,
		},
		{
			name:     "remove last remaining flag",
			initial:  UserGlobalSuspend,
			flag:     UserGlobalSuspend,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := tt.initial
			user.RemoveFlag(tt.flag)
			if user != tt.expected {
				t.Errorf("RemoveFlag() resulted in %v, expected %v", user, tt.expected)
			}
		})
	}
}

func TestUser_ToggleFlag(t *testing.T) {
	tests := []struct {
		name     string
		initial  User
		flag     User
		expected User
	}{
		{
			name:     "toggle flag on empty user",
			initial:  0,
			flag:     UserGlobalSuspend,
			expected: UserGlobalSuspend,
		},
		{
			name:     "toggle existing flag off",
			initial:  UserGlobalSuspend,
			flag:     UserGlobalSuspend,
			expected: 0,
		},
		{
			name:     "toggle non-existent flag on",
			initial:  UserGlobalSuspend,
			flag:     UserInvisible,
			expected: UserGlobalSuspend | UserInvisible,
		},
		{
			name:     "toggle flag in user with multiple flags",
			initial:  UserGlobalSuspend | UserInvisible | UserFraud,
			flag:     UserInvisible,
			expected: UserGlobalSuspend | UserFraud,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := tt.initial
			user.ToggleFlag(tt.flag)
			if user != tt.expected {
				t.Errorf("ToggleFlag() resulted in %v, expected %v", user, tt.expected)
			}
		})
	}
}

func TestUser_ListFlags(t *testing.T) {
	tests := []struct {
		name     string
		user     User
		expected []User
	}{
		{
			name:     "empty user returns empty list",
			user:     0,
			expected: []User{},
		},
		{
			name:     "single flag",
			user:     UserGlobalSuspend,
			expected: []User{UserGlobalSuspend},
		},
		{
			name:     "multiple flags",
			user:     UserGlobalSuspend | UserInvisible | UserFraud,
			expected: []User{UserGlobalSuspend, UserInvisible, UserFraud},
		},
		{
			name:     "all flags",
			user:     UserGlobalSuspend | UserLoggedIn | UserInvisible | UserFraud | UserNoNotes | UserNoPurge | UserNoAdmin | UserAlumni | UserOper | UserNoAdduser | UserTotpEnabled | UserTotpAdminIpr,
			expected: []User{UserGlobalSuspend, UserLoggedIn, UserInvisible, UserFraud, UserNoNotes, UserNoPurge, UserNoAdmin, UserAlumni, UserOper, UserNoAdduser, UserTotpEnabled, UserTotpAdminIpr},
		},
		{
			name:     "non-consecutive flags",
			user:     UserGlobalSuspend | UserFraud | UserTotpEnabled,
			expected: []User{UserGlobalSuspend, UserFraud, UserTotpEnabled},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.user.ListFlags()
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ListFlags() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestUser_ListFlags_Integration(t *testing.T) {
	t.Run("add and list flags", func(t *testing.T) {
		var user User

		// Add flags one by one and verify ListFlags
		user.AddFlag(UserGlobalSuspend)
		flags := user.ListFlags()
		expected := []User{UserGlobalSuspend}
		if !reflect.DeepEqual(flags, expected) {
			t.Errorf("After adding UserGlobalSuspend, ListFlags() = %v, expected %v", flags, expected)
		}

		user.AddFlag(UserInvisible)
		flags = user.ListFlags()
		expected = []User{UserGlobalSuspend, UserInvisible}
		if !reflect.DeepEqual(flags, expected) {
			t.Errorf("After adding UserInvisible, ListFlags() = %v, expected %v", flags, expected)
		}

		// Remove a flag and verify
		user.RemoveFlag(UserGlobalSuspend)
		flags = user.ListFlags()
		expected = []User{UserInvisible}
		if !reflect.DeepEqual(flags, expected) {
			t.Errorf("After removing UserGlobalSuspend, ListFlags() = %v, expected %v", flags, expected)
		}
	})

	t.Run("toggle and list flags", func(t *testing.T) {
		var user User

		// Toggle flag on
		user.ToggleFlag(UserTotpEnabled)
		flags := user.ListFlags()
		expected := []User{UserTotpEnabled}
		if !reflect.DeepEqual(flags, expected) {
			t.Errorf("After toggling UserTotpEnabled on, ListFlags() = %v, expected %v", flags, expected)
		}

		// Toggle flag off
		user.ToggleFlag(UserTotpEnabled)
		flags = user.ListFlags()
		expected = []User{}
		if !reflect.DeepEqual(flags, expected) {
			t.Errorf("After toggling UserTotpEnabled off, ListFlags() = %v, expected %v", flags, expected)
		}
	})
}

func TestUser_Name(t *testing.T) {
	tests := []struct {
		name     string
		flag     User
		expected string
	}{
		{
			name:     "UserGlobalSuspend",
			flag:     UserGlobalSuspend,
			expected: "UserGlobalSuspend",
		},
		{
			name:     "UserLoggedIn",
			flag:     UserLoggedIn,
			expected: "UserLoggedIn",
		},
		{
			name:     "UserInvisible",
			flag:     UserInvisible,
			expected: "UserInvisible",
		},
		{
			name:     "UserTotpEnabled",
			flag:     UserTotpEnabled,
			expected: "UserTotpEnabled",
		},
		{
			name:     "unknown flag",
			flag:     User(0x1234),
			expected: "User(0x1234)",
		},
		{
			name:     "zero flag",
			flag:     User(0),
			expected: "User(0x0)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.flag.Name()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUser_ListFlagNames(t *testing.T) {
	tests := []struct {
		name     string
		flags    User
		expected []string
	}{
		{
			name:     "no flags",
			flags:    0,
			expected: []string{},
		},
		{
			name:     "single flag",
			flags:    UserGlobalSuspend,
			expected: []string{"UserGlobalSuspend"},
		},
		{
			name:     "multiple flags",
			flags:    UserGlobalSuspend | UserInvisible | UserTotpEnabled,
			expected: []string{"UserGlobalSuspend", "UserInvisible", "UserTotpEnabled"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.flags.ListFlagNames()
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func BenchmarkUser_Name(b *testing.B) {
	flag := UserGlobalSuspend
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = flag.Name()
	}
}

// Benchmark tests to ensure performance
func BenchmarkUser_HasFlag(b *testing.B) {
	user := UserGlobalSuspend | UserInvisible | UserFraud
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		user.HasFlag(UserInvisible)
	}
}

func BenchmarkUser_ListFlags(b *testing.B) {
	user := UserGlobalSuspend | UserLoggedIn | UserInvisible | UserFraud | UserNoNotes | UserNoPurge | UserNoAdmin | UserAlumni | UserOper | UserNoAdduser | UserTotpEnabled | UserTotpAdminIpr
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		user.ListFlags()
	}
}
