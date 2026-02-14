// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package channel

// CheckAccessForFullRequest verifies if a user can modify ALL channel settings.
// Used for PUT requests where all fields are required.
// Returns an AccessDeniedError if the user lacks permission for any settings.
func CheckAccessForFullRequest(userAccess int32) error {
	var denied []DeniedSetting

	for _, setting := range Settings {
		if userAccess < setting.Level {
			denied = append(denied, DeniedSetting{
				Name:          setting.Name,
				RequiredLevel: setting.Level,
			})
		}
	}

	if len(denied) > 0 {
		return &AccessDeniedError{
			UserLevel:      userAccess,
			DeniedSettings: denied,
		}
	}

	return nil
}

// CheckAccessForPartialRequest verifies if a user can modify the requested settings.
// Used for PATCH requests where only provided fields are updated.
// Returns an AccessDeniedError if the user lacks permission for any requested settings.
func CheckAccessForPartialRequest(userAccess int32, req *PartialSettingsRequest) error {
	var denied []DeniedSetting

	// Map of field names to their pointer values for checking if they're set
	fieldsToCheck := []struct {
		name  string
		isSet bool
	}{
		{"autojoin", req.Autojoin != nil},
		{"massdeoppro", req.Massdeoppro != nil},
		{"noop", req.Noop != nil},
		{"strictop", req.Strictop != nil},
		{"autotopic", req.Autotopic != nil},
		{"description", req.Description != nil},
		{"floatlim", req.Floatlim != nil},
		{"floatgrace", req.Floatgrace != nil},
		{"floatmargin", req.Floatmargin != nil},
		{"floatmax", req.Floatmax != nil},
		{"floatperiod", req.Floatperiod != nil},
		{"keywords", req.Keywords != nil},
		{"url", req.URL != nil},
		{"userflags", req.Userflags != nil},
	}

	for _, field := range fieldsToCheck {
		if !field.isSet {
			continue
		}

		setting := GetSettingByName(field.name)
		if setting == nil {
			continue
		}

		if userAccess < setting.Level {
			denied = append(denied, DeniedSetting{
				Name:          setting.Name,
				RequiredLevel: setting.Level,
			})
		}
	}

	if len(denied) > 0 {
		return &AccessDeniedError{
			UserLevel:      userAccess,
			DeniedSettings: denied,
		}
	}

	return nil
}
