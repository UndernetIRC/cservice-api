// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package errors

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSettingsAccessDeniedError implements the SettingsAccessDeniedError interface for testing.
type mockSettingsAccessDeniedError struct {
	userLevel      int32
	deniedSettings []DeniedSettingInfo
}

func (m *mockSettingsAccessDeniedError) Error() string {
	return "insufficient permissions to modify settings"
}

func (m *mockSettingsAccessDeniedError) GetUserLevel() int32 {
	return m.userLevel
}

func (m *mockSettingsAccessDeniedError) GetDeniedSettings() []DeniedSettingInfo {
	return m.deniedSettings
}

func TestHandleSettingsAccessDeniedError(t *testing.T) {
	t.Run("single denied setting", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPut, "/api/channels/123/settings", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Response().Header().Set(echo.HeaderXRequestID, "test-request-id")

		accessErr := &mockSettingsAccessDeniedError{
			userLevel: 450,
			deniedSettings: []DeniedSettingInfo{
				{Name: "autojoin", RequiredLevel: 500},
			},
		}

		logOutput := captureLogOutput(t, func() {
			err := HandleSettingsAccessDeniedError(c, accessErr)
			require.NoError(t, err)
		})

		assert.Equal(t, http.StatusForbidden, rec.Code)

		var response ErrorResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

		assert.Equal(t, "error", response.Status)
		assert.Equal(t, ErrCodeForbidden, response.Error.Code)
		assert.Equal(t, "Insufficient permissions to modify settings", response.Error.Message)

		// Check details structure
		details, ok := response.Error.Details.(map[string]interface{})
		require.True(t, ok, "details should be a map")

		userLevel, ok := details["user_level"].(float64)
		require.True(t, ok, "user_level should be present")
		assert.Equal(t, float64(450), userLevel)

		deniedSettings, ok := details["denied_settings"].([]interface{})
		require.True(t, ok, "denied_settings should be present")
		assert.Len(t, deniedSettings, 1)

		firstSetting := deniedSettings[0].(map[string]interface{})
		assert.Equal(t, "autojoin", firstSetting["setting"])
		assert.Equal(t, float64(500), firstSetting["required_level"])

		// Check log output
		assert.Contains(t, logOutput, "Channel settings access denied")
		assert.Contains(t, logOutput, "test-request-id")
	})

	t.Run("multiple denied settings", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPut, "/api/channels/123/settings", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Response().Header().Set(echo.HeaderXRequestID, "test-request-id")

		accessErr := &mockSettingsAccessDeniedError{
			userLevel: 100,
			deniedSettings: []DeniedSettingInfo{
				{Name: "autojoin", RequiredLevel: 500},
				{Name: "floatlim", RequiredLevel: 450},
				{Name: "massdeoppro", RequiredLevel: 200},
			},
		}

		err := HandleSettingsAccessDeniedError(c, accessErr)
		require.NoError(t, err)

		assert.Equal(t, http.StatusForbidden, rec.Code)

		var response ErrorResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

		details := response.Error.Details.(map[string]interface{})
		assert.Equal(t, float64(100), details["user_level"])

		deniedSettings := details["denied_settings"].([]interface{})
		assert.Len(t, deniedSettings, 3)
	})

	t.Run("empty denied settings", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPut, "/api/channels/123/settings", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Response().Header().Set(echo.HeaderXRequestID, "test-request-id")

		accessErr := &mockSettingsAccessDeniedError{
			userLevel:      450,
			deniedSettings: []DeniedSettingInfo{},
		}

		err := HandleSettingsAccessDeniedError(c, accessErr)
		require.NoError(t, err)

		assert.Equal(t, http.StatusForbidden, rec.Code)

		var response ErrorResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

		details := response.Error.Details.(map[string]interface{})
		deniedSettings := details["denied_settings"].([]interface{})
		assert.Len(t, deniedSettings, 0)
	})

	t.Run("nil denied settings", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPut, "/api/channels/123/settings", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Response().Header().Set(echo.HeaderXRequestID, "test-request-id")

		accessErr := &mockSettingsAccessDeniedError{
			userLevel:      450,
			deniedSettings: nil,
		}

		err := HandleSettingsAccessDeniedError(c, accessErr)
		require.NoError(t, err)

		assert.Equal(t, http.StatusForbidden, rec.Code)

		var response ErrorResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))

		assert.Equal(t, "error", response.Status)
		assert.Equal(t, ErrCodeForbidden, response.Error.Code)
	})
}
