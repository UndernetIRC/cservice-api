// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package helper

import (
	"fmt"
	"math"
	"strconv"
)

// SafeAtoi32 converts a string to int32 with bounds checking
func SafeAtoi32(s string) (int32, error) {
	// Convert to int64 first to check bounds
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}

	// Check bounds for int32
	if n > math.MaxInt32 || n < math.MinInt32 {
		return 0, fmt.Errorf("value %d is outside int32 range", n)
	}

	return int32(n), nil
}
