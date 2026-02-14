// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package channel

import (
	apierrors "github.com/undernetirc/cservice-api/internal/errors"
)

// DeniedSetting represents a setting the user lacks permission to modify.
type DeniedSetting struct {
	Name          string `json:"setting"`
	RequiredLevel int32  `json:"required_level"`
}

// AccessDeniedError is returned when a user attempts to modify settings above their access level.
type AccessDeniedError struct {
	UserLevel      int32           `json:"user_level"`
	DeniedSettings []DeniedSetting `json:"denied_settings"`
}

// Error implements the error interface.
func (e *AccessDeniedError) Error() string {
	return "insufficient permissions to modify settings"
}

// GetUserLevel returns the user's access level.
func (e *AccessDeniedError) GetUserLevel() int32 {
	return e.UserLevel
}

// GetDeniedSettings returns the list of denied settings as DeniedSettingInfo.
func (e *AccessDeniedError) GetDeniedSettings() []apierrors.DeniedSettingInfo {
	result := make([]apierrors.DeniedSettingInfo, len(e.DeniedSettings))
	for i, ds := range e.DeniedSettings {
		result[i] = apierrors.DeniedSettingInfo{
			Name:          ds.Name,
			RequiredLevel: ds.RequiredLevel,
		}
	}
	return result
}
