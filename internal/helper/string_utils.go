// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package helper

func StrPtr2Str(str *string) string {
	if str == nil {
		return ""
	}
	return *str
}

func InArray(needle string, haystack []string) bool {
	for _, value := range haystack {
		if value == needle {
			return true
		}
	}
	return false
}
