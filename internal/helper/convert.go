// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 UnderNET

package helper

import (
	"fmt"
	"math"
	"strconv"

	"github.com/jackc/pgx/v5/pgtype"
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

// SafeInt32 safely converts int to int32 with bounds checking
// Returns 0 for overflow conditions, caller should validate the result
func SafeInt32(value int) int32 {
	if value > math.MaxInt32 || value < math.MinInt32 {
		return 0 // Return 0 for overflow, caller should validate
	}
	return int32(value)
}

// SafeInt32FromInt64 safely converts int64 to int32 with bounds checking
// Returns 0 for overflow conditions, caller should validate the result
func SafeInt32FromInt64(value int64) int32 {
	if value > math.MaxInt32 || value < math.MinInt32 {
		return 0 // Return 0 for overflow, caller should validate
	}
	return int32(value)
}

// SafeInt64FromInt safely converts int to int64 with bounds checking
// This is generally safe on most platforms but included for completeness
func SafeInt64FromInt(value int) int64 {
	return int64(value)
}

// SafeIntFromInt32 safely converts int32 to int
// This is generally safe as int is at least 32 bits on all supported platforms
func SafeIntFromInt32(value int32) int {
	return int(value)
}

// SafeIntFromInt64 safely converts int64 to int with bounds checking
// Returns 0 for overflow conditions on 32-bit platforms
func SafeIntFromInt64(value int64) int {
	// On 64-bit platforms, int is int64, so this is safe
	// On 32-bit platforms, int is int32, so we need to check bounds
	if value > int64(math.MaxInt) || value < int64(math.MinInt) {
		return 0
	}
	return int(value)
}

// StringToNullableText converts a string to pgtype.Text
func StringToNullableText(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{String: s, Valid: true}
}

// NullableTextToString converts pgtype.Text to string
func NullableTextToString(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}

// Int32ToNullableInt32 converts int32 to pgtype.Int4
func Int32ToNullableInt32(i int32) pgtype.Int4 {
	return pgtype.Int4{Int32: i, Valid: true}
}

// NullableInt32ToInt32Ptr converts pgtype.Int4 to *int32
func NullableInt32ToInt32Ptr(i pgtype.Int4) *int32 {
	if !i.Valid {
		return nil
	}
	return &i.Int32
}
