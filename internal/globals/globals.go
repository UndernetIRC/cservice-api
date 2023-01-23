// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package globals contains global variables and functions
package globals

import (
	"fmt"
	"os"
)

// LogAndExit logs a message and exits with a given code
func LogAndExit(message string, code int) {
	fmt.Println(message)
	os.Exit(code)
}
