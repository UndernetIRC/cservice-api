// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package channel

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckAccessForFullRequest(t *testing.T) {
	t.Run("level 500 user can modify all settings", func(t *testing.T) {
		err := CheckAccessForFullRequest(500)
		assert.NoError(t, err)
	})

	t.Run("level 450 user denied level 500 settings", func(t *testing.T) {
		err := CheckAccessForFullRequest(450)
		assert.Error(t, err)

		accessErr, ok := err.(*AccessDeniedError)
		assert.True(t, ok)
		assert.Equal(t, int32(450), accessErr.UserLevel)
		assert.Len(t, accessErr.DeniedSettings, 4) // autojoin, massdeoppro, noop, strictop
	})

	t.Run("level 400 user denied all settings", func(t *testing.T) {
		err := CheckAccessForFullRequest(400)
		assert.Error(t, err)

		accessErr, ok := err.(*AccessDeniedError)
		assert.True(t, ok)
		assert.Len(t, accessErr.DeniedSettings, 14)
	})
}

func TestCheckAccessForPartialRequest(t *testing.T) {
	t.Run("level 500 user can modify any setting", func(t *testing.T) {
		val := true
		req := &PartialSettingsRequest{Autojoin: &val}
		err := CheckAccessForPartialRequest(500, req)
		assert.NoError(t, err)
	})

	t.Run("level 450 user can modify level 450 settings", func(t *testing.T) {
		val := true
		req := &PartialSettingsRequest{Autotopic: &val}
		err := CheckAccessForPartialRequest(450, req)
		assert.NoError(t, err)
	})

	t.Run("level 450 user denied level 500 settings", func(t *testing.T) {
		val := true
		req := &PartialSettingsRequest{Autojoin: &val}
		err := CheckAccessForPartialRequest(450, req)
		assert.Error(t, err)

		accessErr, ok := err.(*AccessDeniedError)
		assert.True(t, ok)
		assert.Len(t, accessErr.DeniedSettings, 1)
		assert.Equal(t, "autojoin", accessErr.DeniedSettings[0].Name)
	})

	t.Run("empty request passes for any level", func(t *testing.T) {
		req := &PartialSettingsRequest{}
		err := CheckAccessForPartialRequest(1, req)
		assert.NoError(t, err)
	})

	t.Run("multiple denied settings collected", func(t *testing.T) {
		boolVal := true
		intVal := 5
		req := &PartialSettingsRequest{
			Autojoin:    &boolVal,
			Massdeoppro: &intVal,
			Noop:        &boolVal,
		}
		err := CheckAccessForPartialRequest(450, req)
		assert.Error(t, err)

		accessErr, ok := err.(*AccessDeniedError)
		assert.True(t, ok)
		assert.Len(t, accessErr.DeniedSettings, 3)
	})
}
