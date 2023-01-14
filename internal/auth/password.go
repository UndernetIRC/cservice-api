// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package auth

type Password interface {
	GeneratePasswordHash(password string) string
	ValidatePassword(passwordHash string, password string) bool
}

func Validate(passwordType Password, passwordHash string, password string) bool {
	return passwordType.ValidatePassword(passwordHash, password)
}
func ValidatePassword(passwordHash string, password string) bool {
	if len(passwordHash) == 40 {
		return md5validatePassword(passwordHash, password)
	}
	return false
}
