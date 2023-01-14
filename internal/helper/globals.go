// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package helper

import (
	"fmt"
	"os"
)

func LogAndExit(message string, code int) {
	fmt.Println(message)
	os.Exit(code)
}
