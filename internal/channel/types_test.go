// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package channel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/undernetirc/cservice-api/internal/helper"
)

func TestFullSettingsRequestValidation(t *testing.T) {
	v := helper.NewValidator()

	t.Run("valid request passes", func(t *testing.T) {
		req := FullSettingsRequest{
			Autojoin:    true,
			Massdeoppro: 3,
			Noop:        false,
			Strictop:    false,
			Autotopic:   true,
			Description: "Test channel",
			Floatlim:    true,
			Floatgrace:  1,
			Floatmargin: 3,
			Floatmax:    0,
			Floatperiod: 20,
			Keywords:    "test",
			URL:         "https://example.com",
			Userflags:   0,
		}
		err := v.Validate(&req)
		assert.NoError(t, err)
	})

	t.Run("massdeoppro out of range fails", func(t *testing.T) {
		req := FullSettingsRequest{Massdeoppro: 8, Floatmargin: 3, Floatperiod: 20}
		err := v.Validate(&req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "massdeoppro")
	})

	t.Run("floatmargin below minimum fails", func(t *testing.T) {
		req := FullSettingsRequest{Floatmargin: 1, Floatperiod: 20}
		err := v.Validate(&req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "floatmargin")
	})

	t.Run("floatperiod below minimum fails", func(t *testing.T) {
		req := FullSettingsRequest{Floatmargin: 3, Floatperiod: 10}
		err := v.Validate(&req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "floatperiod")
	})

	t.Run("invalid url fails", func(t *testing.T) {
		req := FullSettingsRequest{Floatmargin: 3, Floatperiod: 20, URL: "not-a-url"}
		err := v.Validate(&req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "url")
	})
}

func TestPartialSettingsRequestValidation(t *testing.T) {
	v := helper.NewValidator()

	t.Run("empty request passes", func(t *testing.T) {
		req := PartialSettingsRequest{}
		err := v.Validate(&req)
		assert.NoError(t, err)
	})

	t.Run("single valid field passes", func(t *testing.T) {
		val := true
		req := PartialSettingsRequest{Autojoin: &val}
		err := v.Validate(&req)
		assert.NoError(t, err)
	})

	t.Run("invalid massdeoppro fails", func(t *testing.T) {
		val := 10
		req := PartialSettingsRequest{Massdeoppro: &val}
		err := v.Validate(&req)
		assert.Error(t, err)
	})
}
