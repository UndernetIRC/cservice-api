// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package channel

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
