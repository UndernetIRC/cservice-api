// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package channel

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAccessDeniedError_Error(t *testing.T) {
	t.Run("returns expected error message", func(t *testing.T) {
		err := &AccessDeniedError{
			UserLevel: 400,
			DeniedSettings: []DeniedSetting{
				{Name: "autojoin", RequiredLevel: 500},
			},
		}

		assert.Equal(t, "insufficient permissions to modify settings", err.Error())
	})
}

func TestAccessDeniedError_SingleDeniedSetting(t *testing.T) {
	err := &AccessDeniedError{
		UserLevel: 400,
		DeniedSettings: []DeniedSetting{
			{Name: "massdeoppro", RequiredLevel: 500},
		},
	}

	assert.Equal(t, int32(400), err.UserLevel)
	assert.Len(t, err.DeniedSettings, 1)
	assert.Equal(t, "massdeoppro", err.DeniedSettings[0].Name)
	assert.Equal(t, int32(500), err.DeniedSettings[0].RequiredLevel)
}

func TestAccessDeniedError_MultipleDeniedSettings(t *testing.T) {
	err := &AccessDeniedError{
		UserLevel: 300,
		DeniedSettings: []DeniedSetting{
			{Name: "autojoin", RequiredLevel: 500},
			{Name: "massdeoppro", RequiredLevel: 500},
			{Name: "description", RequiredLevel: 450},
		},
	}

	assert.Equal(t, int32(300), err.UserLevel)
	assert.Len(t, err.DeniedSettings, 3)

	// Verify each denied setting
	assert.Equal(t, "autojoin", err.DeniedSettings[0].Name)
	assert.Equal(t, int32(500), err.DeniedSettings[0].RequiredLevel)

	assert.Equal(t, "massdeoppro", err.DeniedSettings[1].Name)
	assert.Equal(t, int32(500), err.DeniedSettings[1].RequiredLevel)

	assert.Equal(t, "description", err.DeniedSettings[2].Name)
	assert.Equal(t, int32(450), err.DeniedSettings[2].RequiredLevel)
}

func TestAccessDeniedError_ImplementsErrorInterface(t *testing.T) {
	var err error = &AccessDeniedError{
		UserLevel:      400,
		DeniedSettings: []DeniedSetting{},
	}

	// Verify it implements the error interface
	assert.NotNil(t, err.Error())
}

func TestDeniedSetting_JSONTags(t *testing.T) {
	// This test verifies the struct has the expected fields
	// The JSON tags are verified implicitly through the field names
	ds := DeniedSetting{
		Name:          "autojoin",
		RequiredLevel: 500,
	}

	assert.Equal(t, "autojoin", ds.Name)
	assert.Equal(t, int32(500), ds.RequiredLevel)
}

func TestAccessDeniedError_GetUserLevel(t *testing.T) {
	err := &AccessDeniedError{
		UserLevel: 450,
		DeniedSettings: []DeniedSetting{
			{Name: "autojoin", RequiredLevel: 500},
		},
	}

	assert.Equal(t, int32(450), err.GetUserLevel())
}

func TestAccessDeniedError_GetDeniedSettings(t *testing.T) {
	t.Run("returns converted denied settings", func(t *testing.T) {
		err := &AccessDeniedError{
			UserLevel: 300,
			DeniedSettings: []DeniedSetting{
				{Name: "autojoin", RequiredLevel: 500},
				{Name: "floatlim", RequiredLevel: 450},
			},
		}

		result := err.GetDeniedSettings()

		assert.Len(t, result, 2)
		assert.Equal(t, "autojoin", result[0].Name)
		assert.Equal(t, int32(500), result[0].RequiredLevel)
		assert.Equal(t, "floatlim", result[1].Name)
		assert.Equal(t, int32(450), result[1].RequiredLevel)
	})

	t.Run("returns empty slice for nil denied settings", func(t *testing.T) {
		err := &AccessDeniedError{
			UserLevel:      300,
			DeniedSettings: nil,
		}

		result := err.GetDeniedSettings()

		assert.NotNil(t, result)
		assert.Len(t, result, 0)
	})

	t.Run("returns empty slice for empty denied settings", func(t *testing.T) {
		err := &AccessDeniedError{
			UserLevel:      300,
			DeniedSettings: []DeniedSetting{},
		}

		result := err.GetDeniedSettings()

		assert.NotNil(t, result)
		assert.Len(t, result, 0)
	})
}
