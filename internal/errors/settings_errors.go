// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package errors

import (
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v4"
)

// DeniedSettingInfo represents a setting the user lacks permission to modify.
type DeniedSettingInfo struct {
	Name          string `json:"setting"`
	RequiredLevel int32  `json:"required_level"`
}

// SettingsAccessDeniedError is the interface for settings access denied errors.
type SettingsAccessDeniedError interface {
	error
	GetUserLevel() int32
	GetDeniedSettings() []DeniedSettingInfo
}

// SettingsAccessDeniedDetails contains the detailed information for settings access denied errors.
type SettingsAccessDeniedDetails struct {
	DeniedSettings []DeniedSettingInfo `json:"denied_settings"`
	UserLevel      int32               `json:"user_level"`
}

// HandleSettingsAccessDeniedError handles channel settings permission errors.
func HandleSettingsAccessDeniedError(c echo.Context, err SettingsAccessDeniedError) error {
	requestID := getRequestID(c)

	deniedSettings := err.GetDeniedSettings()
	userLevel := err.GetUserLevel()

	slog.Warn("Channel settings access denied",
		"requestID", requestID,
		"path", c.Request().URL.Path,
		"method", c.Request().Method,
		"userLevel", userLevel,
		"deniedSettingsCount", len(deniedSettings))

	details := SettingsAccessDeniedDetails{
		DeniedSettings: deniedSettings,
		UserLevel:      userLevel,
	}

	return c.JSON(http.StatusForbidden, NewErrorResponse(
		ErrCodeForbidden,
		"Insufficient permissions to modify settings",
		details,
	))
}
