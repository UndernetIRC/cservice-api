// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package helper

func StrPtr2Str(str *string) string {
	if str == nil {
		return ""
	}
	return *str
}
