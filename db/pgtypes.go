// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package db defines the database types and functions.
package db

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// NewString returns a new pgtype.Text
func NewString(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: true}
}

// NewTimestamp returns a new pgtype.Timestamp
func NewTimestamp(t time.Time) pgtype.Timestamp {
	return pgtype.Timestamp{Time: t, Valid: true}
}

func NewInt4(t int64) pgtype.Int4 {
	const (
		maxInt32 = 2147483647
		minInt32 = -2147483648
	)

	var result int32
	if t > maxInt32 {
		result = maxInt32
	} else if t < minInt32 {
		result = minInt32
	} else {
		result = int32(t) // #nosec G115 - safe conversion after bounds check
	}

	return pgtype.Int4{Int32: result, Valid: true}
}

// TextToString extracts a Go string from pgtype.Text, returning empty string if null
func TextToString(pgText pgtype.Text) string {
	if pgText.Valid {
		return pgText.String
	}
	return ""
}

// Int4ToInt32 extracts a Go int32 from pgtype.Int4, returning 0 if null
func Int4ToInt32(pgInt4 pgtype.Int4) int32 {
	if pgInt4.Valid {
		return pgInt4.Int32
	}
	return 0
}

// Int4ToInt extracts a Go int from pgtype.Int4, returning 0 if null
func Int4ToInt(pgInt4 pgtype.Int4) int {
	if pgInt4.Valid {
		return int(pgInt4.Int32)
	}
	return 0
}
