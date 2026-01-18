// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package channel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/undernetirc/cservice-api/db/types/flags"
)

func TestSettingsRegistry(t *testing.T) {
	t.Run("all settings have valid configuration", func(t *testing.T) {
		for _, s := range Settings {
			assert.NotEmpty(t, s.Name, "setting must have a name")
			assert.NotEmpty(t, s.DBColumn, "setting %s must have a DB column", s.Name)
			assert.True(t, s.Level >= 1 && s.Level <= 500, "setting %s level must be 1-500", s.Name)

			if s.Type == TypeBool && s.DBColumn == "flags" {
				assert.NotZero(t, s.Flag, "boolean flag setting %s must have Flag set", s.Name)
			}
			if s.Type == TypeInt {
				assert.NotNil(t, s.Min, "int setting %s must have Min", s.Name)
				assert.NotNil(t, s.Max, "int setting %s must have Max", s.Name)
			}
			if s.Type == TypeString {
				assert.NotNil(t, s.MaxLen, "string setting %s must have MaxLen", s.Name)
			}
		}
	})

	t.Run("GetSettingByName returns correct setting", func(t *testing.T) {
		s := GetSettingByName("autojoin")
		assert.NotNil(t, s)
		assert.Equal(t, "autojoin", s.Name)
		assert.Equal(t, int32(500), s.Level)
		assert.Equal(t, flags.ChannelAutoJoin, s.Flag)
	})

	t.Run("GetSettingByName returns nil for unknown", func(t *testing.T) {
		s := GetSettingByName("nonexistent")
		assert.Nil(t, s)
	})

	t.Run("level 500 settings count", func(t *testing.T) {
		count := 0
		for _, s := range Settings {
			if s.Level == 500 {
				count++
			}
		}
		assert.Equal(t, 4, count, "should have 4 level 500 settings")
	})

	t.Run("level 450 settings count", func(t *testing.T) {
		count := 0
		for _, s := range Settings {
			if s.Level == 450 {
				count++
			}
		}
		assert.Equal(t, 10, count, "should have 10 level 450 settings")
	})
}
